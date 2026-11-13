'use strict';
/**
 * Audit log (JSON lines) di data/audit.log. Mencatat siapa/apa/kapan.
 * Nilai rahasia (key, token, password) TIDAK PERNAH ditulis: field bernama sensitif disembunyikan.
 */
const fs = require('fs');
const path = require('path');

const SENSITIVE = /(key|token|secret|password|passwd|authorization|credential|value)/i;

function redact(v, depth = 0) {
  if (depth > 4 || v == null) return v;
  if (Array.isArray(v)) return v.slice(0, 20).map((x) => redact(x, depth + 1));
  if (typeof v === 'object') {
    const out = {};
    for (const [k, val] of Object.entries(v)) out[k] = SENSITIVE.test(k) ? '[disembunyikan]' : redact(val, depth + 1);
    return out;
  }
  if (typeof v === 'string') return v.length > 300 ? `${v.slice(0, 300)}…` : v;
  return v;
}

function createAudit({ file, maxBytes = 5 * 1024 * 1024, throttleMs = 10000 } = {}) {
  const last = new Map(); // action|ip -> waktu terakhir, agar serangan berulang tidak membanjiri log

  function rotateIfNeeded() {
    try {
      if (fs.statSync(file).size >= maxBytes) fs.renameSync(file, `${file}.1`);
    } catch (_) { /* file belum ada */ }
  }

  function record({ action, ok = true, ip = '-', actor = '-', detail = {}, throttle = false }) {
    try {
      if (throttle) {
        const k = `${action}|${ip}`;
        const now = Date.now();
        if (now - (last.get(k) || 0) < throttleMs) return;
        last.set(k, now);
        if (last.size > 500) last.clear();
      }
      fs.mkdirSync(path.dirname(file), { recursive: true });
      rotateIfNeeded();
      const line = JSON.stringify({
        ts: new Date().toISOString(),
        action: String(action).slice(0, 60),
        ok: Boolean(ok),
        ip: String(ip).slice(0, 64),
        actor: String(actor || '-').slice(0, 60),
        detail: redact(detail),
      });
      fs.appendFileSync(file, `${line}\n`, { mode: 0o600 });
    } catch (e) {
      console.error('[audit] gagal menulis:', e.message); // audit tidak boleh menjatuhkan aplikasi
    }
  }

  function tail(n = 100) {
    const lim = Math.min(Math.max(parseInt(n, 10) || 100, 1), 500);
    try {
      const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).slice(-lim);
      return lines.map((l) => { try { return JSON.parse(l); } catch (_) { return null; } }).filter(Boolean).reverse();
    } catch (_) {
      return [];
    }
  }

  return { record, tail };
}

module.exports = { createAudit, redact };
