'use strict';
// Tes tahap 1: pengaman Host/Origin, token, brankas terenkripsi, audit log, dan pemasangan rute rahasia.
// express/helmet/express-rate-limit di-stub karena npm tidak selalu tersedia; yang diuji adalah logika kita.
const Module = require('module');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');
const root = process.argv[2] || path.resolve(__dirname, '..');

const sec = require(`${root}/server/security`);
const { createVault, loadMasterKey } = require(`${root}/server/vault`);
const { createAudit, redact } = require(`${root}/server/audit`);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-sec-'));
const mkRes = () => {
  const r = { code: 200, body: null, status(c) { r.code = c; return r; }, json(b) { r.body = b; return r; } };
  return r;
};
const run = (mw, req) => { const res = mkRes(); let nexted = false; mw(req, res, () => { nexted = true; }); return { res, nexted }; };
const rq = (o) => ({ method: 'GET', path: '/x', headers: { host: 'localhost:3000' }, socket: { remoteAddress: '127.0.0.1' }, ...o });

(async () => {
  // ---- Host / Origin / Sec-Fetch-Site ----
  const audit = createAudit({ file: path.join(tmp, 'a1.log') });
  const guard = sec.hostOriginGuard({ allowedHosts: ['soc.lan'], audit });
  assert.ok(run(guard, rq()).nexted, 'localhost diizinkan');
  assert.ok(run(guard, rq({ headers: { host: '127.0.0.1:3000' } })).nexted);
  assert.ok(run(guard, rq({ headers: { host: '[::1]:3000' } })).nexted);
  assert.ok(run(guard, rq({ headers: { host: 'LOCALHOST:3000' } })).nexted);
  assert.ok(run(guard, rq({ headers: { host: 'soc.lan:3000' } })).nexted, 'ALLOWED_HOSTS dihormati');
  assert.strictEqual(run(guard, rq({ headers: { host: 'evil.example:3000' } })).res.code, 403, 'DNS rebinding ditolak');
  assert.strictEqual(run(guard, rq({ headers: {} })).res.code, 403, 'tanpa Host ditolak');
  assert.strictEqual(run(guard, rq({ headers: { host: 'localhost.evil.example' } })).res.code, 403);
  for (const v of ['cross-site', 'same-site']) {
    assert.strictEqual(run(guard, rq({ headers: { host: 'localhost:3000', 'sec-fetch-site': v } })).res.code, 403, v);
  }
  for (const v of ['same-origin', 'none']) {
    assert.ok(run(guard, rq({ headers: { host: 'localhost:3000', 'sec-fetch-site': v } })).nexted, v);
  }
  const post = (origin) => rq({ method: 'POST', headers: { host: 'localhost:3000', origin } });
  assert.ok(run(guard, post('http://localhost:3000')).nexted, 'origin sama diizinkan');
  assert.strictEqual(run(guard, post('https://evil.example')).res.code, 403, 'origin asing ditolak');
  assert.strictEqual(run(guard, post('http://localhost:8080')).res.code, 403, 'port lain ditolak');
  assert.strictEqual(run(guard, post('null')).res.code, 403, 'origin null ditolak');
  assert.ok(run(guard, rq({ method: 'POST' })).nexted, 'klien non-browser (tanpa Origin) lolos ke token');
  assert.ok(audit.tail(10).some((e) => e.action === 'guard.denied'), 'penolakan tercatat di audit');

  // ---- JSON only ----
  const jo = sec.jsonOnly();
  assert.ok(run(jo, rq()).nexted, 'GET bebas');
  assert.strictEqual(run(jo, rq({ method: 'POST', headers: { 'content-type': 'text/plain' } })).res.code, 415);
  assert.strictEqual(run(jo, rq({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' } })).res.code, 415);
  assert.strictEqual(run(jo, rq({ method: 'DELETE', headers: {} })).res.code, 415);
  assert.ok(run(jo, rq({ method: 'POST', headers: { 'content-type': 'application/json' } })).nexted);
  assert.ok(run(jo, rq({ method: 'PUT', headers: { 'content-type': 'application/json; charset=utf-8' } })).nexted);

  // ---- Token ----
  let clock = 1000;
  const ta = sec.tokenAuth({ token: 'rahasia-panjang-123', audit, maxFails: 3, lockMs: 60000, now: () => clock });
  assert.ok(run(ta, rq({ path: '/health' })).nexted, 'health tanpa token');
  assert.strictEqual(run(ta, rq({ headers: { host: 'localhost' } })).res.code, 401);
  assert.strictEqual(run(ta, rq({ headers: { 'x-api-token': 'salah' } })).res.code, 401);
  assert.strictEqual(run(ta, rq({ url: '/x?token=rahasia-panjang-123', headers: {} })).res.code, 401, 'token via query tidak diterima');
  assert.strictEqual(run(ta, rq({ headers: { cookie: 'x-api-token=rahasia-panjang-123' } })).res.code, 429, 'terkunci setelah gagal berulang');
  assert.strictEqual(run(ta, rq({ headers: { 'x-api-token': 'rahasia-panjang-123' } })).res.code, 429, 'tetap terkunci selama masa kunci');
  clock += 61000;
  assert.ok(run(ta, rq({ headers: { 'x-api-token': 'rahasia-panjang-123' } })).nexted, 'token benar setelah masa kunci');
  assert.ok(run(sec.tokenAuth({ token: '' }), rq()).nexted, 'tanpa APP_TOKEN: lolos (diamankan guard)');

  // ---- redactText ----
  const red = sec.redactText('gagal: ApiKey abcDEF1234567890== dan x-apikey: 9f86d081884c7d65 token=abc123xyz Bearer eyJhbGciOi.payload.sig');
  assert.ok(!/abcDEF1234567890|9f86d081884c7d65|abc123xyz|eyJhbGciOi/.test(red), red);
  assert.strictEqual(sec.redactText('koneksi ditolak 503'), 'koneksi ditolak 503');

  // ---- Brankas ----
  const key = crypto.randomBytes(32);
  const vf = path.join(tmp, 'vault.json');
  const v = createVault({ file: vf, key });
  const SECRET = 'sk-test-ABCDEFGHIJKLMNOP-1234';
  const m = v.set('VT_API_KEY', SECRET, { label: 'Akun free' });
  assert.deepStrictEqual(Object.keys(m).sort(), ['added_at', 'label', 'last4', 'name', 'updated_at']);
  assert.strictEqual(m.last4, '1234');
  assert.strictEqual(v.get('VT_API_KEY'), SECRET);
  assert.ok(!JSON.stringify(v.meta()).includes(SECRET), 'meta tidak memuat rahasia');
  const onDisk = fs.readFileSync(vf, 'utf8');
  assert.ok(!onDisk.includes(SECRET) && !onDisk.includes('ABCDEFGHIJ'), 'file terenkripsi');
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(vf).mode & 0o777, 0o600, 'mode 0600');
  assert.strictEqual(v.getOr('NOPE', 'dari-env-12345'), 'dari-env-12345');
  assert.strictEqual(v.getOr('VT_API_KEY', 'dari-env-12345'), SECRET, 'brankas diutamakan');
  // instance baru dengan master key sama membaca ulang dari disk
  assert.strictEqual(createVault({ file: vf, key }).get('VT_API_KEY'), SECRET);
  // master key salah
  assert.throws(() => createVault({ file: vf, key: crypto.randomBytes(32) }).get('VT_API_KEY'), (e) => e.code === 'DECRYPT_FAILED');
  assert.strictEqual(createVault({ file: vf, key: crypto.randomBytes(32) }).getOr('VT_API_KEY', 'env-cadangan'), 'env-cadangan');
  // data dirusak
  const j = JSON.parse(onDisk); j.VT_API_KEY.ct = Buffer.from('xxxxxxxx').toString('base64');
  fs.writeFileSync(path.join(tmp, 'v2.json'), JSON.stringify(j));
  assert.throws(() => createVault({ file: path.join(tmp, 'v2.json'), key }).get('VT_API_KEY'), (e) => e.code === 'DECRYPT_FAILED');
  // entri ditukar antar nama (AAD)
  const sw = { ABUSEIPDB_API_KEY: JSON.parse(onDisk).VT_API_KEY };
  fs.writeFileSync(path.join(tmp, 'v3.json'), JSON.stringify(sw));
  assert.throws(() => createVault({ file: path.join(tmp, 'v3.json'), key }).get('ABUSEIPDB_API_KEY'), (e) => e.code === 'DECRYPT_FAILED');
  // validasi
  assert.throws(() => v.set('bad name!', SECRET), (e) => e.code === 'BAD_NAME');
  for (const bad of ['', 'pendek', 'ada spasi di sini 12345', 'baris\nbaru-12345678', 'x'.repeat(5000)]) {
    assert.throws(() => v.set('VT_API_KEY', bad), (e) => e.code === 'BAD_VALUE', JSON.stringify(bad).slice(0, 20));
  }
  assert.throws(() => createVault({ file: path.join(tmp, 'v4.json'), key: null }).set('VT_API_KEY', SECRET), (e) => e.code === 'NO_MASTER_KEY');
  assert.ok(v.remove('VT_API_KEY') && !v.remove('VT_API_KEY'));
  assert.strictEqual(v.get('VT_API_KEY'), null);
  // master key
  assert.strictEqual(loadMasterKey({}), null);
  assert.strictEqual(loadMasterKey({ VAULT_KEY: key.toString('base64') }).length, 32);
  assert.strictEqual(loadMasterKey({ VAULT_KEY: key.toString('hex') }).length, 32);
  assert.throws(() => loadMasterKey({ VAULT_KEY: 'terlalu-pendek' }), /32 byte/);
  const kf = path.join(tmp, 'k'); fs.writeFileSync(kf, `${key.toString('base64')}\n`);
  assert.strictEqual(loadMasterKey({ VAULT_KEY_FILE: kf }).length, 32);

  // ---- Audit ----
  const af = path.join(tmp, 'a2.log');
  const au = createAudit({ file: af, maxBytes: 600 });
  au.record({ action: 'secret.set', actor: 'budi', detail: { name: 'VT_API_KEY', value: SECRET, api_key: 'zzz', nested: { token: 'qqq', ok: 1 } } });
  const raw = fs.readFileSync(af, 'utf8');
  assert.ok(!raw.includes(SECRET) && !raw.includes('zzz') && !raw.includes('qqq'), 'audit tidak memuat nilai rahasia');
  assert.strictEqual(au.tail(5)[0].detail.name, 'VT_API_KEY');
  for (let i = 0; i < 12; i += 1) au.record({ action: 'x', detail: { i } });
  assert.ok(fs.existsSync(`${af}.1`), 'rotasi log');
  au.record({ action: 'th', ip: '1.1.1.1', throttle: true }); au.record({ action: 'th', ip: '1.1.1.1', throttle: true });
  assert.strictEqual(au.tail(500).filter((e) => e.action === 'th').length, 1, 'throttle');
  assert.strictEqual(redact({ Authorization: 'x', a: 'b' }).Authorization, '[disembunyikan]');

  // ---- Pemasangan di index.js (express di-stub) ----
  const routes = []; const uses = [];
  const mk = () => {
    const app = { use: (...a) => { uses.push(a); return app; }, disable() {} };
    ['get', 'put', 'post', 'delete'].forEach((m) => { app[m] = (p, ...h) => { routes.push({ m, p, h: h[h.length - 1] }); return app; }; });
    return app;
  };
  const expressStub = () => mk();
  expressStub.json = (o) => { const f = () => {}; f.opts = o; f.kind = 'json'; return f; };
  expressStub.static = () => () => {};
  const orig = Module._load;
  Module._load = function (req, ...a) {
    if (req === 'dotenv') return { config() {} };
    if (req === 'express') return expressStub;
    if (req === 'helmet') return (o) => { const f = () => {}; f.opts = o; f.kind = 'helmet'; return f; };
    if (req === 'express-rate-limit') return (o) => { const f = () => {}; f.opts = o; f.kind = 'rate'; return f; };
    return orig.call(this, req, ...a);
  };
  process.env.DEMO_MODE = 'true';
  process.env.APP_TOKEN = 'token-uji-123456';
  process.env.VAULT_KEY = crypto.randomBytes(32).toString('base64');
  const dataDir = path.join(root, 'data');
  const hadVault = fs.existsSync(path.join(dataDir, 'vault.json'));
  require(`${root}/server/index.js`);
  Module._load = orig;

  const order = uses.map((u) => (typeof u[0] === 'string' ? u[0] : '*'));
  assert.ok(order.indexOf('*') === 0, 'guard Host/Origin dipasang paling awal');
  const firstJson = uses.findIndex((u) => u.some((x) => x && x.kind === 'json' && x.opts.limit === '100kb'));
  assert.ok(firstJson > 0, 'parser JSON global terpasang');
  const secretsUse = uses.find((u) => u[0] === '/api/secrets');
  assert.ok(secretsUse && secretsUse.some((x) => x && x.kind === 'json' && x.opts.limit === '8kb'), 'batas 8kb pada /api/secrets');
  assert.ok(uses.indexOf(secretsUse) < firstJson, 'parser kecil sebelum parser global');
  assert.ok(secretsUse.some((x) => x && x.kind === 'rate' && x.opts.limit === 10), 'rate limit ketat pada /api/secrets');
  const find = (m, p) => routes.find((r) => r.m === m && r.p === p);
  const putS = find('put', '/api/secrets/:name').h;
  const delS = find('delete', '/api/secrets/:name').h;
  const getS = find('get', '/api/secrets').h;

  const call = async (h, req) => { const res = mkRes(); await h({ socket: { remoteAddress: '127.0.0.1' }, get: () => '', ...req }, res); return res; };
  let r = await call(putS, { params: { name: 'EVIL_KEY' }, body: { value: 'abcdefghijkl' } });
  assert.strictEqual(r.code, 400, 'nama key di luar daftar ditolak');
  r = await call(putS, { params: { name: 'VT_API_KEY' }, body: { value: 'pendek' } });
  assert.strictEqual(r.code, 400);
  r = await call(putS, { params: { name: 'VT_API_KEY' }, body: { value: 'vt-key-uji-ABCDEF123456', label: 'Uji' } });
  assert.strictEqual(r.code, 200);
  assert.strictEqual(r.body.secret.last4, '3456');
  assert.ok(!JSON.stringify(r.body).includes('vt-key-uji'), 'respons PUT tanpa nilai');
  r = await call(getS, {});
  assert.ok(!JSON.stringify(r.body).includes('vt-key-uji') && r.body.secrets[0].name === 'VT_API_KEY', 'GET tanpa nilai');
  const config = require(`${root}/server/config`);
  assert.strictEqual(config.ti.vtKey, 'vt-key-uji-ABCDEF123456', 'config memakai key dari brankas');
  r = await call(delS, { params: { name: 'VT_API_KEY' } });
  assert.deepStrictEqual(r.body, { removed: true });
  assert.strictEqual(config.ti.vtKey, '', 'kembali ke .env (kosong) setelah dihapus');
  const auditTxt = fs.readFileSync(path.join(dataDir, 'audit.log'), 'utf8');
  assert.ok(auditTxt.includes('secret.set') && auditTxt.includes('secret.delete') && !auditTxt.includes('vt-key-uji'), 'audit rute rahasia');

  // bersihkan jejak uji pada data/
  if (!hadVault) fs.rmSync(path.join(dataDir, 'vault.json'), { force: true });
  fs.rmSync(path.join(dataDir, 'audit.log'), { force: true });
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log('security tests OK');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
