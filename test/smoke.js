'use strict';
// Smoke test modul murni (tanpa express/elasticsearch). dotenv di-stub karena npm tidak bisa install di sandbox.
const Module = require('module');
const origLoad = Module._load;
Module._load = function (req, ...a) {
  if (req === 'dotenv') return { config() {} };
  return origLoad.call(this, req, ...a);
};
process.env.DEMO_MODE = 'true';
const assert = require('assert');
const root = process.argv[2] || require('path').resolve(__dirname, '..');
const { extractEvidence, detectIocType, isPrivateIp } = require(`${root}/server/extract`);
const demo = require(`${root}/server/demo`);
const ioc = require(`${root}/server/ioc`);
const report = require(`${root}/server/report`);
const store = require(`${root}/server/store`);

(async () => {
  // detectIocType
  assert.strictEqual(detectIocType('203.0.113.45'), 'ip');
  assert.strictEqual(detectIocType('2001:db8::1'), 'ip');
  assert.strictEqual(detectIocType('evil-login.example'), 'domain');
  assert.strictEqual(detectIocType('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'), 'sha256');
  assert.strictEqual(detectIocType('https://x.example/a?b=1'), 'url');
  assert.strictEqual(detectIocType('not an ioc!!'), null);
  assert.strictEqual(detectIocType('<script>alert(1)</script>'), null);
  // isPrivateIp
  ['10.1.1.1', '192.168.5.5', '172.16.0.1', '127.0.0.1', '169.254.1.1', '100.64.0.1'].forEach((ip) => assert.ok(isPrivateIp(ip), ip));
  ['8.8.8.8', '203.0.113.45', '172.32.0.1'].forEach((ip) => assert.ok(!isPrivateIp(ip), ip));

  // alerts + extraction
  const list = await demo.searchAlerts({});
  assert.strictEqual(list.alerts.length, 5);
  const a = await demo.getAlert('demo-0002');
  const ev = extractEvidence(a.source);
  assert.strictEqual(ev.host.name, 'WS-FIN-07');
  assert.strictEqual(ev.user.name, 'it.budi');
  assert.strictEqual(ev.network.destination_port, 443);
  assert.ok(ev.iocs.some((i) => i.type === 'ip' && i.value === '198.51.100.23' && !i.private));
  assert.ok(ev.iocs.some((i) => i.type === 'ip' && i.value === '10.10.30.77' && i.private));
  assert.ok(ev.iocs.some((i) => i.type === 'domain' && i.value === 'update-check.example'));
  assert.ok(ev.iocs.some((i) => i.type === 'sha256'));
  assert.ok(ev.process.command_line.includes('DownloadString'));

  // IOC check (simulasi demo + privat + invalid)
  const bad = await ioc.check('198.51.100.23');
  assert.strictEqual(bad.verdict, 'malicious');
  assert.strictEqual((await ioc.check('10.0.0.5')).verdict, 'private');
  assert.strictEqual((await ioc.check('bukan ioc')).verdict, 'invalid');
  assert.ok((await ioc.check('198.51.100.23')).cached);

  // related + report (+ XSS escaping)
  const rel = await demo.relatedEvents({ ips: ['203.0.113.45'], hosts: [], users: [] });
  assert.strictEqual(rel.events.length, 4);
  const a1 = await demo.getAlert('demo-0001');
  const ev1 = { timestamp: a1.source['@timestamp'], ...extractEvidence(a1.source) };
  ev1.rule.name = '<img src=x onerror=alert(1)>';
  const triage = { verdict: 'true_positive', notes: [{ at: 'now', by: '<b>x</b>', text: '<script>1</script> | pipe' }] };
  const iocs = await ioc.checkMany(['203.0.113.45']);
  const data = { id: 'demo-0001', evidence: ev1, related: rel, iocs, triage, generated_at: 'now', window_minutes: 15 };
  const html = report.toHtml(data);
  assert.ok(!html.includes('<img src=x'), 'HTML harus ter-escape');
  assert.ok(!html.includes('<script>1'), 'catatan harus ter-escape');
  const md = report.toMarkdown(data);
  assert.ok(md.includes('203.0.113.45') && md.includes('malicious')); assert.ok(!md.includes('<img'), 'MD harus ter-escape');

  // store
  const saved = store.update('demo-0001', { verdict: 'true_positive', note: 'uji', analyst: 'tester' });
  assert.strictEqual(saved.notes.length, 1);
  assert.throws(() => store.update('demo-0001', { verdict: 'hacker' }));
  console.log('SEMUA SMOKE TEST LULUS');
  console.log(md.split('\n').slice(0, 22).join('\n'));
})().catch((e) => { console.error('GAGAL:', e); process.exit(1); });
