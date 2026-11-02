'use strict';
// Uji analisa otomatis (MITRE ATT&CK, narasi, auto-verdict, backfill). Jalankan: npm test
const Module = require('module');
const orig = Module._load;
Module._load = function (req, ...a) { return req === 'dotenv' ? { config() {} } : orig.call(this, req, ...a); }; // dotenv opsional untuk uji
process.env.DEMO_MODE = 'true';
process.env.AUTO_ENRICH = 'true';
process.env.AUTO_POLL_SECONDS = '15';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '..');
const dataDir = path.join(root, 'data');
const clean = () => ['enrichment.json', 'triage.json'].forEach((f) => fs.rmSync(path.join(dataDir, f), { force: true }));
clean();

const demo = require(`${root}/server/demo`);
const worker = require(`${root}/server/worker`);
const enrich = require(`${root}/server/enrichment-store`);
const triage = require(`${root}/server/store`);
const analyzer = require(`${root}/server/analyzer`);
const { extractEvidence, parseThreat, flatten } = require(`${root}/server/extract`);
const report = require(`${root}/server/report`);

const text = (parts) => parts.map((p) => (typeof p === 'string' ? p : p.v)).join('');
const allText = (a) => Object.values(a.narrative).flatMap((v) => v.map((x) => (typeof x === 'string' ? x : x.v))).join(' ');

(async () => {
  // 1) parsing MITRE: struktur asli (array + subtechnique), bentuk datar, dan objek tunggal
  const real = extractEvidence((await demo.getAlert('demo-0002')).source);
  assert.deepStrictEqual(real.rule.threat[0], { tactic_id: 'TA0002', tactic: 'Execution', technique_id: 'T1059.001', technique: 'Command and Scripting Interpreter: PowerShell' });
  const dotted = { 'kibana.alert.rule.parameters': { threat: [{ framework: 'MITRE ATT&CK', tactic: { id: 'TA0006', name: 'Credential Access' }, technique: [{ id: 'T1110', name: 'Brute Force', subtechnique: [] }] }] } };
  assert.strictEqual(parseThreat(dotted, flatten(dotted))[0].technique_id, 'T1110');
  const flat = { 'kibana.alert.rule.threat.tactic.name': ['Discovery'], 'kibana.alert.rule.threat.tactic.id': ['TA0007'], 'kibana.alert.rule.threat.technique.id': ['T1046'], 'kibana.alert.rule.threat.technique.name': ['Network Service Discovery'] };
  const pf = parseThreat(flat, flatten(flat))[0];
  assert.ok(pf.tactic_id === 'TA0007' && pf.technique_id === 'T1046');

  // 2) siklus worker dari kosong: hanya high/critical, verdict otomatis tersimpan
  assert.strictEqual(enrich.count(), 0);
  worker.start(demo);
  await new Promise((r) => setTimeout(r, 3600));
  const st = worker.status();
  assert.strictEqual(st.processed, 3, JSON.stringify(st));
  assert.strictEqual(st.last_error, null);
  assert.ok(!enrich.get('demo-0003') && !enrich.get('demo-0005')); // medium & closed tidak diproses otomatis
  worker.stop();
  assert.strictEqual(triage.get('demo-0002').verdict, 'true_positive');
  assert.strictEqual(triage.get('demo-0002').verdict_source, 'auto');
  assert.strictEqual(triage.get('demo-0001').verdict, 'needs_investigation');

  // 3) kasus PowerShell dari dokumen Office
  const a2 = enrich.get('demo-0002');
  assert.strictEqual(a2.schema, 2);
  assert.strictEqual(a2.verdict, 'true_positive');
  assert.strictEqual(a2.priority, 'P1');
  assert.strictEqual(a2.scenario, 'phish_exec');
  const ids = a2.ttps.map((t) => t.technique_id);
  ['T1566.001', 'T1204.002', 'T1059.001', 'T1564.003', 'T1105', 'T1071.001'].forEach((i) => assert.ok(ids.includes(i), `TTP ${i} hilang: ${ids}`));
  const ps = a2.ttps.find((t) => t.technique_id === 'T1059.001');
  assert.strictEqual(ps.source, 'rule+evidence');
  assert.strictEqual(ps.confidence, 'confirmed');
  assert.ok(ps.procedure.includes('DownloadString'));
  assert.ok(a2.ttps.every((t) => /^TA\d{4}$/.test(t.tactic_id) && t.tactic), 'tiap TTP harus punya tactic');
  const order = a2.ttps.map((t) => t.tactic_id);
  assert.deepStrictEqual(order, [...order].sort(), 'TTP urut sesuai rantai taktik');
  const nt = allText(a2);
  assert.ok(/threat actor/i.test(nt), 'istilah profesional: threat actor');
  assert.ok(!/attacker/i.test(nt), 'tidak memakai kata attacker');
  assert.ok(nt.includes('invoice_okt.docm') && nt.includes('update-check.example') && nt.includes('diizinkan'));
  assert.ok(a2.narrative.conclusion.length && a2.narrative.actions.length >= 3);
  assert.ok(a2.ioc_results.every((r) => typeof r.score === 'number'));
  console.log('--- narasi demo-0002 ---');
  [['Root cause', 'root_cause'], ['Aktivitas', 'activity'], ['Pemeriksaan', 'findings'], ['Kesimpulan', 'conclusion']].forEach(([t, k]) => console.log(`${t}: ${text(a2.narrative[k])}\n`));

  // 4) scan & brute force & akun
  const a1 = enrich.get('demo-0001');
  assert.strictEqual(a1.scenario, 'scan');
  assert.ok(a1.ttps.some((t) => t.technique_id === 'T1046'));
  const r3 = await worker.enrichOne(demo, 'demo-0003');
  assert.strictEqual(r3.scenario, 'bruteforce');
  assert.ok(r3.ttps.some((t) => t.technique_id === 'T1110'));
  const r4 = await worker.enrichOne(demo, 'demo-0004');
  assert.strictEqual(r4.scenario, 'account');
  assert.ok(/threat actor/i.test(allText(r4)));
  assert.ok(r4.ttps.some((t) => t.technique_id === 'T1078'));

  // 5) verdict analis tidak ditimpa; verdict otomatis boleh diperbarui
  triage.update('demo-0003', { verdict: 'benign', note: 'dikonfirmasi tim IT', analyst: 'tester' });
  const again = await worker.enrichOne(demo, 'demo-0003');
  assert.strictEqual(again.verdict_applied, false);
  assert.strictEqual(again.verdict_apply_reason, 'analyst');
  assert.strictEqual(triage.get('demo-0003').verdict, 'benign');
  assert.strictEqual(triage.get('demo-0003').verdict_source, 'analyst');
  const before = triage.get('demo-0002').notes.length;
  await worker.enrichOne(demo, 'demo-0002'); // analisa ulang, verdict sama: tidak menambah catatan
  assert.strictEqual(triage.get('demo-0002').notes.length, before);

  // 6) daftar aman menurunkan skor ke false positive
  const ev = { timestamp: 'x', rule: { severity: 'medium', name: 'r', threat: [] }, network: { source_ip: '10.9.8.7' }, host: {}, user: {}, process: {}, iocs: [], meta: {} };
  const rules = JSON.parse(JSON.stringify(analyzer.loadRules()));
  rules.allowlist.ips = ['10.9.0.0/16'];
  const fp = analyzer.analyze({ evidence: ev, related: { total: 0, events: [] }, iocResults: [], rules });
  assert.strictEqual(fp.verdict, 'false_positive');
  assert.strictEqual(fp.priority, 'P4');
  assert.ok(analyzer.inList('192.168.1.5', ['192.168.1.0/24']) && !analyzer.inList('192.168.2.5', ['192.168.1.0/24']));
  // severity tinggi tanpa sinyal lain tidak boleh diturunkan otomatis menjadi false positive
  const hi = analyzer.analyze({ evidence: { ...ev, rule: { ...ev.rule, severity: 'high' } }, related: { total: 0, events: [] }, iocResults: [] });
  assert.strictEqual(hi.verdict, 'needs_investigation');

  // 7) backfill rentang kustom
  clean();
  const bf0 = await worker.backfill(demo, { from: '2000-01-01T00:00:00Z', to: '2099-01-01T00:00:00Z', severities: ['all'], force: true });
  assert.strictEqual(bf0.running, true);
  await assert.rejects(worker.backfill(demo, { from: '2000-01-01T00:00:00Z', to: '2099-01-01T00:00:00Z' }), (e) => e.code === 'BUSY');
  for (let i = 0; i < 50 && worker.status().backfill.running; i++) await new Promise((r) => setTimeout(r, 100));
  const bf = worker.status().backfill;
  assert.strictEqual(bf.running, false);
  assert.strictEqual(bf.phase, 'selesai');
  assert.strictEqual(bf.total, 4); // 5 alert demo, 1 closed dilewati
  assert.strictEqual(bf.done, 4);
  assert.strictEqual(enrich.count(), 4);

  // 8) laporan memuat analisa, TTP, dan escaping
  const d = { id: 'demo-0002', evidence: { timestamp: 't', ...real }, related: { total: 0, events: [] }, iocs: [], triage: triage.get('demo-0002'), analysis: enrich.get('demo-0002'), generated_at: 'now', window_minutes: 15 };
  d.analysis.ttps[0].procedure = '<img src=x onerror=alert(1)>';
  const html = report.toHtml(d);
  const md = report.toMarkdown(d);
  assert.ok(html.includes('Aktivitas threat actor') && md.includes('## TTP (MITRE ATT&CK)') && md.includes('T1059.001'));
  assert.ok(!html.includes('<img src=x') && !md.includes('<img'));

  clean();
  console.log('SEMUA TES ANALISA OTOMATIS LULUS');
})().catch((e) => { console.error('GAGAL:', e); clean(); process.exit(1); });
