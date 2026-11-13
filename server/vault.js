'use strict';
/**
 * Brankas rahasia: API key disimpan terenkripsi (AES-256-GCM) di data/vault.json (mode 0600).
 * Master key (32 byte) berasal dari VAULT_KEY atau file VAULT_KEY_FILE dan TIDAK disimpan di folder data.
 * Nama rahasia dipakai sebagai AAD, sehingga entri tidak bisa ditukar antar nama.
 * Nilai rahasia tidak pernah dikembalikan oleh meta() maupun API.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const NAME_RE = /^[A-Za-z0-9_:.-]{1,64}$/;

function loadMasterKey(env = process.env) {
  let raw = env.VAULT_KEY || '';
  if (!raw && env.VAULT_KEY_FILE) raw = fs.readFileSync(env.VAULT_KEY_FILE, 'utf8');
  raw = String(raw).trim();
  if (!raw) return null;
  const buf = /^[0-9a-f]{64}$/i.test(raw) ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'base64');
  if (buf.length !== 32) {
    throw new Error('VAULT_KEY harus 32 byte (base64 atau 64 karakter hex). Buat dengan: openssl rand -base64 32');
  }
  return buf;
}

function codeErr(code, msg) { return Object.assign(new Error(msg), { code }); }

function createVault({ file, key }) {
  let db = {};
  try { db = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { db = {}; }

  const persist = () => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, file);
    try { fs.chmodSync(file, 0o600); } catch (_) { /* sistem file tanpa chmod */ }
  };
  const checkName = (name) => {
    if (!NAME_RE.test(String(name))) throw codeErr('BAD_NAME', 'Nama rahasia tidak valid');
  };

  function set(name, secret, { label = '' } = {}) {
    checkName(name);
    if (!key) throw codeErr('NO_MASTER_KEY', 'VAULT_KEY belum diatur di .env');
    const s = String(secret == null ? '' : secret).trim();
    if (s.length < 8 || s.length > 4096 || /[\u0000-\u001f\u007f\s]/.test(s)) {
      throw codeErr('BAD_VALUE', 'Nilai rahasia tidak valid (8–4096 karakter, tanpa spasi atau baris baru)');
    }
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(Buffer.from(name));
    const ct = Buffer.concat([c.update(s, 'utf8'), c.final()]);
    const now = new Date().toISOString();
    db[name] = {
      iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), ct: ct.toString('base64'),
      label: String(label || '').trim().slice(0, 80),
      last4: s.length >= 12 ? s.slice(-4) : '',
      added_at: (db[name] && db[name].added_at) || now,
      updated_at: now,
    };
    persist();
    return metaOf(name);
  }

  /** Hanya untuk pemakaian internal server. Mengembalikan null bila tidak ada. */
  function get(name) {
    checkName(name);
    const e = db[name];
    if (!e) return null;
    if (!key) throw codeErr('NO_MASTER_KEY', 'VAULT_KEY belum diatur di .env');
    try {
      const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(e.iv, 'base64'));
      d.setAAD(Buffer.from(name));
      d.setAuthTag(Buffer.from(e.tag, 'base64'));
      return Buffer.concat([d.update(Buffer.from(e.ct, 'base64')), d.final()]).toString('utf8');
    } catch (_) {
      throw codeErr('DECRYPT_FAILED', 'Gagal membuka rahasia (master key salah atau data berubah)');
    }
  }

  /** Nilai dari brankas bila ada dan terbaca, kalau tidak pakai cadangan (mis. dari .env). */
  function getOr(name, fallback = '') {
    try { return get(name) || fallback || ''; } catch (e) {
      if (!getOr.warned) { getOr.warned = true; console.error(`[vault] ${e.message}`); }
      return fallback || '';
    }
  }

  function metaOf(name) {
    const e = db[name];
    if (!e) return null;
    return { name, label: e.label, last4: e.last4, added_at: e.added_at, updated_at: e.updated_at };
  }
  const meta = () => Object.keys(db).sort().map(metaOf);
  function remove(name) {
    checkName(name);
    if (!db[name]) return false;
    delete db[name];
    persist();
    return true;
  }

  return { set, get, getOr, meta, remove, has: (n) => Boolean(db[n]), available: Boolean(key) };
}

let defaultVault = null;
/** Instance bawaan (lazy) memakai data/vault.json dan master key dari environment. */
function instance() {
  if (!defaultVault) {
    let key = null;
    try { key = loadMasterKey(); } catch (e) { console.error(`[vault] ${e.message}`); }
    defaultVault = createVault({ file: path.join(__dirname, '..', 'data', 'vault.json'), key });
  }
  return defaultVault;
}

module.exports = { createVault, loadMasterKey, instance, NAME_RE };
