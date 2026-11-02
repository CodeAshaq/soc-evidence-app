'use strict';
// Uji pembuat laporan PDF. Jalankan: node test/pdf.js
const Module = require('module');
const orig = Module._load;
Module._load = function (r, ...a) { return r === 'dotenv' ? { config() {} } : orig.call(this, r, ...a); };
process.env.DEMO_MODE = 'true';
const assert = require('assert');
const path = require('path');
const root = path.resolve(__dirname, '..');
const demo = require(`${root}/server/demo`);
const worker = require(`${root}/server/worker`);
const store = require(`${root}/server/store`);
const { extractEvidence } = require(`${root}/server/extract`);
const { toPdf } = require(`${root}/server/pdf`);

(async () => {
  for (const id of ['demo-0001', 'demo-0002']) {
    const an = await worker.enrichOne(demo, id);
    const f = await demo.getAlert(id);
    // karakter non-Latin dan token sangat panjang tidak boleh membuat pembuatan PDF gagal
    f.source.host = { name: 'host-ΩΩ-' + 'x'.repeat(200) };
    const buf = await toPdf({ id, evidence: { timestamp: f.source['@timestamp'], ...extractEvidence(f.source) }, analysis: an, triage: store.get(id), generated_at: new Date().toISOString() });
    assert.strictEqual(buf.slice(0, 5).toString(), '%PDF-');
    assert.ok(buf.length > 3000);
  }
  console.log('TES PDF LULUS');
  process.exit(0);
})().catch((e) => { console.error('GAGAL:', e); process.exit(1); });
