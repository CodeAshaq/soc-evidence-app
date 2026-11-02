'use strict';
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const config = require('./config');
const es = config.demoMode ? require('./demo') : require('./elastic');
const store = require('./store');
const ioc = require('./ioc');
const report = require('./report');
const { toPdf } = require('./pdf');
const worker = require('./worker');
const enrich = require('./enrichment-store');
const { extractEvidence, isPrivateIp } = require('./extract');

const app = express();
app.disable('x-powered-by');
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: { 'upgrade-insecure-requests': null }, // aplikasi sering dipakai di LAN via http
    },
  })
);
app.use(express.json({ limit: '100kb' }));
app.use('/api', rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false }));

// ---- Autentikasi token sederhana (opsional) ----
function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}
app.use('/api', (req, res, next) => {
  if (!config.appToken || req.path === '/health') return next();
  if (safeEqual(req.get('x-api-token') || '', config.appToken)) return next();
  return res.status(401).json({ error: 'Token tidak valid' });
});

const wrap = (fn) => (req, res) =>
  Promise.resolve(fn(req, res)).catch((err) => {
    console.error(`[${req.method} ${req.path}]`, err.message);
    // pesan error generik ke klien; detail hanya di log server
    res.status(500).json({ error: 'Terjadi kesalahan pada server. Lihat log server.' });
  });

// ---- Routes ----
app.get('/api/health', wrap(async (req, res) => {
  const info = { app: 'soc-evidence-collector', demo: config.demoMode, auth_required: Boolean(config.appToken) };
  try {
    info.elastic = await es.health();
    info.elastic_ok = true;
  } catch (e) {
    info.elastic_ok = false;
    info.elastic_error = 'Tidak dapat terhubung ke Elasticsearch';
  }
  info.ti = { virustotal: Boolean(config.ti.vtKey), abuseipdb: Boolean(config.ti.abuseKey) };
  info.kibana_status_update = Boolean(config.kibana.url);
  info.auto = worker.status();
  res.json(info);
}));

app.get('/api/alerts', wrap(async (req, res) => {
  const data = await es.searchAlerts(req.query);
  data.alerts = data.alerts.map((a) => {
    const e = enrich.get(a.id);
    const t = store.get(a.id);
    return {
      ...a, triage: t.verdict, triage_source: t.verdict_source,
      auto: e && e.schema === 2 ? { level: e.level, score: e.score, label: e.label, priority: e.priority } : null,
    };
  });
  res.json(data);
}));

app.get('/api/alerts/:id', wrap(async (req, res) => {
  const found = await es.getAlert(req.params.id);
  if (!found) return res.status(404).json({ error: 'Alert tidak ditemukan' });
  res.json({
    id: found.id,
    evidence: { timestamp: found.source['@timestamp'], ...extractEvidence(found.source) },
    raw: found.source,
    triage: store.get(found.id),
  });
}));

/** Jendela waktu ±N menit dari timestamp alert. */
function windowOf(timestamp, minutes) {
  const t = new Date(timestamp).getTime();
  const m = Math.min(Math.max(parseInt(minutes, 10) || 15, 1), 43200); // hingga 30 hari
  return { from: new Date(t - m * 60000).toISOString(), to: new Date(t + m * 60000).toISOString(), minutes: m };
}

app.post('/api/alerts/:id/related', wrap(async (req, res) => {
  const found = await es.getAlert(req.params.id);
  if (!found) return res.status(404).json({ error: 'Alert tidak ditemukan' });
  const ev = extractEvidence(found.source);
  const w = windowOf(found.source['@timestamp'], req.body && req.body.window_minutes);

  // Default pivot = semua IP/host/user dari alert; boleh dipersempit oleh analis.
  const body = req.body || {};
  const ips = Array.isArray(body.ips) ? body.ips : ev.iocs.filter((i) => i.type === 'ip').map((i) => i.value);
  const hosts = Array.isArray(body.hosts) ? body.hosts : [ev.host.name].filter(Boolean);
  const users = Array.isArray(body.users) ? body.users : [ev.user.name].filter(Boolean);

  const data = await es.relatedEvents({
    ips: ips.filter((x) => net.isIP(String(x))),
    hosts: hosts.map(String),
    users: users.map(String),
    from: w.from,
    to: w.to,
  });
  res.json({ window: w, pivots: { ips, hosts, users }, ...data });
}));

app.get('/api/ioc', wrap(async (req, res) => {
  res.json(await ioc.check(req.query.value));
}));

app.post('/api/ioc/bulk', wrap(async (req, res) => {
  const values = Array.isArray(req.body && req.body.values) ? req.body.values : [];
  res.json({ results: await ioc.checkMany(values) });
}));

app.put('/api/alerts/:id/triage', wrap(async (req, res) => {
  const b = req.body || {};
  const allowed = ['open', 'acknowledged', 'in-progress', 'closed'];
  if (b.status && !allowed.includes(b.status)) return res.status(400).json({ error: 'status tidak valid' });
  let saved;
  try {
    saved = store.update(req.params.id, { verdict: b.verdict, note: b.note, status: b.status, analyst: b.analyst });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  let elastic = null;
  if (b.status) elastic = await es.setAlertStatus(req.params.id, b.status, b.note);
  res.json({ triage: saved, elastic });
}));

app.get('/api/alerts/:id/report', wrap(async (req, res) => {
  const found = await es.getAlert(req.params.id);
  if (!found) return res.status(404).json({ error: 'Alert tidak ditemukan' });
  const evidence = { timestamp: found.source['@timestamp'], ...extractEvidence(found.source) };

  // PDF: memakai hasil analisa tersimpan (tanpa memanggil ulang API threat intelligence)
  if (String(req.query.format || '').toLowerCase() === 'pdf') {
    let analysis = enrich.get(found.id);
    if (!analysis || analysis.schema !== 2) analysis = await worker.enrichOne(es, found.id, { throttle: false });
    const buf = await toPdf({ id: found.id, evidence, analysis, triage: store.get(found.id), generated_at: new Date().toISOString() });
    res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': `attachment; filename="laporan-triage-${found.id.replace(/[^a-zA-Z0-9_-]/g, '')}.pdf"` });
    return res.send(buf);
  }

  const w = windowOf(found.source['@timestamp'], req.query.window);

  const related = await es.relatedEvents({
    ips: evidence.iocs.filter((i) => i.type === 'ip').map((i) => i.value),
    hosts: [evidence.host.name].filter(Boolean),
    users: [evidence.user.name].filter(Boolean),
    from: w.from,
    to: w.to,
  });
  const iocs = await ioc.checkMany(evidence.iocs.filter((i) => !(i.type === 'ip' && isPrivateIp(i.value))).map((i) => i.value));
  const data = {
    id: found.id, evidence, related, iocs,
    triage: store.get(found.id),
    analysis: (() => { const a = enrich.get(found.id); return a && a.schema === 2 ? a : null; })(),
    generated_at: new Date().toISOString(),
    window_minutes: w.minutes,
  };

  const format = String(req.query.format || 'md').toLowerCase();
  const name = `evidence-${found.id.replace(/[^a-zA-Z0-9_-]/g, '')}`;
  if (format === 'json') {
    res.set('Content-Disposition', `attachment; filename="${name}.json"`);
    return res.json({ ...data, raw: found.source });
  }
  if (format === 'html') {
    res.set({ 'Content-Type': 'text/html; charset=utf-8', 'Content-Disposition': `attachment; filename="${name}.html"` });
    return res.send(report.toHtml(data));
  }
  res.set({ 'Content-Type': 'text/markdown; charset=utf-8', 'Content-Disposition': `attachment; filename="${name}.md"` });
  return res.send(report.toMarkdown(data));
}));

// ---- Analisa otomatis ----
app.get('/api/alerts/:id/analysis', wrap(async (req, res) => {
  res.json({ analysis: enrich.get(req.params.id) });
}));

app.post('/api/alerts/:id/analysis', wrap(async (req, res) => {
  try {
    const rec = await worker.enrichOne(es, req.params.id, { throttle: false, windowMinutes: req.body && req.body.window_minutes });
    if (!rec) return res.status(404).json({ error: 'Alert tidak ditemukan' });
    return res.json({ analysis: rec });
  } catch (e) {
    if (e.code === 'BUSY') return res.status(409).json({ error: 'Analisa untuk alert ini sedang berjalan' });
    throw e;
  }
}));

app.get('/api/auto/status', (req, res) => res.json(worker.status()));

// Analisa semua alert pada rentang waktu kustom (latar belakang). Body: { from, to, severities?, force? }
app.post('/api/auto/backfill', wrap(async (req, res) => {
  const b = req.body || {};
  const from = new Date(b.from);
  const to = new Date(b.to);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) || from >= to) {
    return res.status(400).json({ error: 'Rentang waktu tidak valid' });
  }
  const allowed = ['critical', 'high', 'medium', 'low', 'all'];
  const severities = Array.isArray(b.severities) ? b.severities.map(String).filter((s) => allowed.includes(s)) : [];
  try {
    const bf = await worker.backfill(es, { from: from.toISOString(), to: to.toISOString(), severities, force: Boolean(b.force) });
    return res.status(202).json({ backfill: bf });
  } catch (e) {
    if (e.code === 'BUSY') return res.status(409).json({ error: 'Backfill sebelumnya masih berjalan' });
    throw e;
  }
}));

app.post('/api/auto/backfill/cancel', (req, res) => {
  worker.cancelBackfill();
  res.json(worker.status());
});

// ---- Static ----
app.use('/docs', express.static(path.join(__dirname, '..', 'docs')));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint tidak ada' }));

if (require.main === module) {
  app.listen(config.port, config.host, () => {
    console.log(`SOC Evidence Collector berjalan di http://${config.host}:${config.port}  (demo=${config.demoMode})`);
    worker.start(es);
    if (config.host !== '127.0.0.1' && !config.appToken) {
      console.warn('PERINGATAN: aplikasi terbuka di jaringan tanpa APP_TOKEN. Set APP_TOKEN di .env.');
    }
  });
}

module.exports = app;
