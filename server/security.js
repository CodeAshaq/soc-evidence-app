'use strict';
/**
 * Pengaman untuk aplikasi lokal:
 *  - hostOriginGuard : tolak DNS rebinding (header Host) dan CSRF lintas situs (Origin / Sec-Fetch-Site)
 *  - jsonOnly        : metode yang mengubah data wajib Content-Type: application/json
 *  - tokenAuth       : token hanya lewat header x-api-token (bukan cookie / query), dengan penguncian setelah gagal berulang
 *  - redactText      : menyembunyikan key/token pada teks log
 * Semua fungsi hanya memakai req.headers, req.method, req.path, res.status().json() sehingga bisa diuji tanpa express.
 */
const crypto = require('crypto');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function hostname(h) {
  const v = String(h || '').trim().toLowerCase();
  if (!v) return '';
  if (v[0] === '[') { const i = v.indexOf(']'); return i < 0 ? '' : v.slice(1, i); }
  return v.split(':')[0];
}

function clientIp(req) {
  return (req.socket && req.socket.remoteAddress) || req.ip || '-';
}

function hostOriginGuard({ allowedHosts = [], audit = null } = {}) {
  // entri IPv6 polos (mis. ::1) dipakai apa adanya; entri lain dinormalkan seperti header Host (tanpa port)
  const norm = (x) => (String(x).split(':').length > 2 && !String(x).includes('[') ? String(x).trim().toLowerCase() : hostname(x));
  const allow = new Set(['localhost', '127.0.0.1', '::1', ...allowedHosts].map(norm).filter(Boolean));
  const deny = (req, res, why) => {
    if (audit) audit.record({ action: 'guard.denied', ok: false, ip: clientIp(req), detail: { why, method: req.method, path: req.path || req.url }, throttle: true });
    return res.status(403).json({ error: 'Permintaan ditolak oleh pengaman akses lokal' });
  };
  return (req, res, next) => {
    const h = req.headers || {};
    if (!allow.has(hostname(h.host))) return deny(req, res, 'host');
    const sfs = h['sec-fetch-site'];
    if (sfs && sfs !== 'same-origin' && sfs !== 'none') return deny(req, res, 'sec-fetch-site');
    if (h.origin !== undefined) {
      let o;
      try { o = new URL(h.origin); } catch (_) { return deny(req, res, 'origin'); }
      if (o.host.toLowerCase() !== String(h.host || '').toLowerCase()) return deny(req, res, 'origin');
    }
    return next();
  };
}

function jsonOnly() {
  return (req, res, next) => {
    if (SAFE_METHODS.has(req.method)) return next();
    const ct = String((req.headers || {})['content-type'] || '').toLowerCase();
    if (/^application\/json(\s*;|$)/.test(ct)) return next();
    return res.status(415).json({ error: 'Content-Type harus application/json' });
  };
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

function tokenAuth({ token, audit = null, maxFails = 10, lockMs = 5 * 60 * 1000, now = Date.now } = {}) {
  const fails = new Map(); // ip -> { n, until }
  return (req, res, next) => {
    if (!token || req.path === '/health') return next();
    const ip = clientIp(req);
    const f = fails.get(ip);
    if (f && f.until > now()) return res.status(429).json({ error: 'Terlalu banyak percobaan gagal. Coba lagi beberapa menit lagi.' });
    if (safeEqual((req.headers || {})['x-api-token'] || '', token)) { fails.delete(ip); return next(); }
    const cur = fails.get(ip) || { n: 0, until: 0 };
    cur.n += 1;
    if (cur.n >= maxFails) { cur.until = now() + lockMs; cur.n = 0; }
    fails.set(ip, cur);
    if (fails.size > 500) fails.clear();
    if (audit) audit.record({ action: 'auth.failed', ok: false, ip, detail: { path: req.path }, throttle: true });
    return res.status(401).json({ error: 'Token tidak valid' });
  };
}

/** Sembunyikan key/token pada teks (mis. pesan error dari library) sebelum masuk log. */
function redactText(s) {
  return String(s == null ? '' : s)
    .replace(/(ApiKey|Bearer|Basic)\s+[A-Za-z0-9+/=._-]{8,}/gi, '$1 [disembunyikan]')
    .replace(/((?:api[-_ ]?key|x-apikey|authorization|token|secret|password|passwd)["']?\s*[:=]\s*["']?)[^\s"',;}]+/gi, '$1[disembunyikan]');
}

module.exports = { hostOriginGuard, jsonOnly, tokenAuth, redactText, hostname, safeEqual };
