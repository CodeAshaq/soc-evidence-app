'use strict';
/**
 * Worker analisa otomatis:
 *  - polling alert baru secara berkala (cycle),
 *  - backfill alert pada rentang waktu kustom (backfill),
 *  - setiap alert: kumpulkan evidence + event terkait, validasi IOC publik, analisa MITRE ATT&CK,
 *    lalu simpan hasil dan (bila AUTO_APPLY_VERDICT aktif) verdict otomatis.
 * Tidak pernah menutup alert atau mengubah status di Elastic.
 */
const config = require('./config');
const ioc = require('./ioc');
const store = require('./enrichment-store');
const triage = require('./store');
const analyzer = require('./analyzer');
const { extractEvidence } = require('./extract');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const clampWin = (m) => Math.min(Math.max(parseInt(m, 10) || config.auto.windowMinutes, 1), 43200);

const state = { enabled: false, running: false, last_run: null, last_ok: null, last_error: null, processed: 0, failed: 0, pending: 0, backfill: null };
const attempts = new Map(); // id alert -> jumlah percobaan gagal (maks 3 sampai restart)
const inflight = new Set();
let timer = null;
let stopped = false;
let cancelBackfill = false;

const needsAnalysis = (id) => {
  const r = store.get(id);
  return !r || r.schema !== analyzer.SCHEMA;
};

/** Kumpulkan evidence + event terkait + validasi IOC untuk satu alert, analisa, simpan. */
async function enrichOne(es, id, { throttle = false, windowMinutes } = {}) {
  if (inflight.has(id)) throw Object.assign(new Error('Analisa sedang berjalan'), { code: 'BUSY' });
  inflight.add(id);
  try {
    const found = await es.getAlert(id);
    if (!found) return null;
    const evidence = { timestamp: found.source['@timestamp'], ...extractEvidence(found.source) };
    const winMin = clampWin(windowMinutes);

    let related = { total: 0, events: [] };
    try {
      const t = new Date(evidence.timestamp).getTime();
      const win = winMin * 60000;
      related = await es.relatedEvents({
        ips: evidence.iocs.filter((i) => i.type === 'ip').map((i) => i.value),
        hosts: [evidence.host.name].filter(Boolean),
        users: [evidence.user.name].filter(Boolean),
        from: new Date(t - win).toISOString(),
        to: new Date(t + win).toISOString(),
      });
    } catch (_) {
      related = { total: 0, events: [], error: 'gagal memuat event terkait' };
    }

    // Hanya IOC publik yang divalidasi (IP privat tidak pernah dikirim keluar)
    const values = [...new Set(evidence.iocs.filter((i) => !(i.type === 'ip' && i.private)).map((i) => i.value))].slice(0, 20);
    const iocResults = [];
    for (const v of values) {
      const r = await ioc.check(v);
      iocResults.push(r);
      // jeda antar pemanggilan API eksternal agar tidak melewati kuota gratis
      if (throttle && !r.cached && Array.isArray(r.sources) && r.sources.length && !config.demoMode && config.auto.tiIntervalMs > 0) {
        await sleep(config.auto.tiIntervalMs);
      }
    }

    const analysis = analyzer.analyze({ evidence, related, iocResults, windowMinutes: winMin });

    let applied = { applied: false, reason: 'off' };
    if (config.auto.applyVerdict !== 'off') {
      applied = triage.applyAuto(id, {
        verdict: analysis.verdict,
        mode: config.auto.applyVerdict,
        note: `Verdict otomatis: ${analysis.label} (skor ${analysis.score}/100, prioritas ${analysis.priority}, keyakinan ${analysis.confidence}).`,
      });
    }

    const rec = {
      alert_id: id,
      enriched_at: new Date().toISOString(),
      related_total: related.total || 0,
      verdict_applied: Boolean(applied.applied),
      verdict_apply_reason: applied.applied ? null : applied.reason || null,
      ioc_results: iocResults,
      ...analysis,
    };
    store.set(id, rec);
    return rec;
  } finally {
    inflight.delete(id);
  }
}

async function cycle(es) {
  state.running = true;
  state.last_run = new Date().toISOString();
  try {
    const now = Date.now();
    const lookbackMs = (config.demoMode ? 1440 : config.auto.lookbackMinutes) * 60000;
    // Jendela = lookback, diperluas bila worker sempat mati (maks catchupHours) agar alert tidak terlewat
    const lastOk = state.last_ok ? new Date(state.last_ok).getTime() - 5 * 60000 : Infinity;
    const sinceMs = Math.max(now - config.auto.catchupHours * 3600e3, Math.min(now - lookbackMs, lastOk));
    const from = new Date(sinceMs).toISOString();
    const to = new Date(now).toISOString();

    const found = new Map();
    for (const sev of config.auto.severities) {
      let offset = 0;
      while (found.size < 1000 && offset < 10000) {
        const r = await es.searchAlerts({ from, to, severity: sev, size: 200, offset });
        for (const a of r.alerts) found.set(a.id, a);
        offset += r.alerts.length;
        if (!r.alerts.length || offset >= r.total) break;
      }
    }
    const todo = [...found.values()]
      .filter((a) => a.status !== 'closed' && needsAnalysis(a.id) && (attempts.get(a.id) || 0) < 3)
      .sort((a, b) => (RANK[b.severity] || 0) - (RANK[a.severity] || 0) || new Date(b.timestamp) - new Date(a.timestamp));
    state.pending = todo.length;

    for (const a of todo.slice(0, config.auto.maxPerCycle)) {
      try {
        await enrichOne(es, a.id, { throttle: true });
        state.processed++;
      } catch (e) {
        if (e.code !== 'BUSY') {
          attempts.set(a.id, (attempts.get(a.id) || 0) + 1);
          state.failed++;
          console.warn(`[auto] gagal menganalisa ${a.id}: ${e.message}`);
        }
      }
      state.pending = Math.max(0, state.pending - 1);
    }

    // last_ok hanya maju bila antrean sudah habis, supaya backlog tidak hilang dari jendela
    if (todo.length <= config.auto.maxPerCycle) {
      state.last_ok = to;
      store.setMeta({ last_ok: to });
    }
    state.last_error = null;
  } catch (e) {
    state.last_error = `siklus gagal: ${e.message}`;
    console.warn(`[auto] ${state.last_error}`);
  } finally {
    state.running = false;
  }
}

/**
 * Analisa semua alert pada rentang waktu kustom (berjalan di latar belakang).
 * severities: ['all'] atau daftar severity; kosong = AUTO_SEVERITIES.
 */
async function backfill(es, { from, to, severities, force = false, includeClosed = false }) {
  if (state.backfill && state.backfill.running) throw Object.assign(new Error('Backfill sedang berjalan'), { code: 'BUSY' });
  const sevs = severities && severities.length ? severities : config.auto.severities;
  const list = sevs.includes('all') ? [''] : sevs;
  cancelBackfill = false;
  const bf = {
    running: true, phase: 'mencari alert', total: 0, done: 0, failed: 0, skipped: 0, truncated: false, cancelled: false,
    from, to, severities: sevs, started_at: new Date().toISOString(), finished_at: null, error: null,
  };
  state.backfill = bf;

  (async () => {
    try {
      const found = new Map();
      for (const sev of list) {
        let offset = 0;
        while (found.size < config.auto.backfillMax * 2 && offset < 10000) {
          const r = await es.searchAlerts({ from, to, severity: sev || undefined, size: 200, offset });
          for (const a of r.alerts) found.set(a.id, a);
          offset += r.alerts.length;
          if (!r.alerts.length || offset >= r.total) break;
        }
      }
      let todo = [...found.values()]
        .filter((a) => (includeClosed || a.status !== 'closed') && (force || needsAnalysis(a.id)))
        .sort((a, b) => (RANK[b.severity] || 0) - (RANK[a.severity] || 0) || new Date(b.timestamp) - new Date(a.timestamp));
      if (todo.length > config.auto.backfillMax) { todo = todo.slice(0, config.auto.backfillMax); bf.truncated = true; }
      bf.total = todo.length;
      bf.phase = 'menganalisa';
      for (const a of todo) {
        if (cancelBackfill) { bf.cancelled = true; break; }
        try {
          await enrichOne(es, a.id, { throttle: true });
          bf.done++;
        } catch (e) {
          if (e.code === 'BUSY') bf.skipped++;
          else { bf.failed++; console.warn(`[auto] backfill gagal ${a.id}: ${e.message}`); }
        }
      }
    } catch (e) {
      bf.error = e.message;
      console.warn(`[auto] backfill gagal: ${e.message}`);
    } finally {
      bf.running = false;
      bf.phase = bf.cancelled ? 'dibatalkan' : bf.error ? 'gagal' : 'selesai';
      bf.finished_at = new Date().toISOString();
    }
  })();
  return { ...bf };
}

function start(es) {
  state.enabled = config.auto.enabled;
  if (!state.enabled) return;
  const m = store.getMeta();
  if (m.last_ok) state.last_ok = m.last_ok;
  const loop = async () => {
    if (stopped) return;
    await cycle(es);
    timer = setTimeout(loop, config.auto.pollSeconds * 1000);
  };
  timer = setTimeout(loop, 3000);
  console.log(`[auto] analisa otomatis aktif: severity=${config.auto.severities.join(',')}, interval=${config.auto.pollSeconds}s, maks ${config.auto.maxPerCycle}/siklus, verdict=${config.auto.applyVerdict}`);
}

function stop() {
  stopped = true;
  clearTimeout(timer);
}

const status = () => ({
  ...state,
  backfill: state.backfill ? { ...state.backfill } : null,
  severities: config.auto.severities,
  poll_seconds: config.auto.pollSeconds,
  apply_verdict: config.auto.applyVerdict,
  backfill_max: config.auto.backfillMax,
  analyzed_total: store.count(),
});

module.exports = { start, stop, status, enrichOne, backfill, cancelBackfill: () => { cancelBackfill = true; } };
