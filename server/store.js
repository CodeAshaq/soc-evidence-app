'use strict';
/** Penyimpanan triage lokal (JSON file). Cukup untuk 1 analis / tim kecil; ganti ke DB bila perlu. */
const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, '..', 'data', 'triage.json');
let db = {};

try {
  db = JSON.parse(fs.readFileSync(FILE, 'utf8'));
} catch (_) {
  db = {};
}

function persist() {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  const tmp = `${FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, FILE); // atomic agar file tidak rusak saat crash
}

const VERDICTS = ['unreviewed', 'true_positive', 'false_positive', 'benign', 'needs_investigation'];

function get(id) {
  return db[id] || { verdict: 'unreviewed', verdict_source: null, status: null, notes: [], updated_at: null };
}

/** Perubahan oleh analis (manual). Verdict yang ditetapkan analis tidak akan ditimpa otomatis. */
function update(id, { verdict, note, status, analyst }) {
  const cur = get(id);
  if (verdict) {
    if (!VERDICTS.includes(verdict)) throw new Error('verdict tidak valid');
    cur.verdict = verdict;
    cur.verdict_source = 'analyst';
  }
  if (status) cur.status = status;
  if (note && String(note).trim()) {
    cur.notes.push({
      at: new Date().toISOString(),
      by: String(analyst || 'analyst').slice(0, 60),
      text: String(note).trim().slice(0, 4000),
    });
  }
  cur.updated_at = new Date().toISOString();
  db[id] = cur;
  persist();
  return cur;
}

/**
 * Verdict otomatis dari analyzer. Tidak menimpa verdict yang ditetapkan analis.
 * mode: 'all' (semua verdict) | 'tp_only' (hanya true positive).
 */
function applyAuto(id, { verdict, note, mode }) {
  if (!VERDICTS.includes(verdict) || verdict === 'unreviewed') return { applied: false, reason: 'invalid' };
  const cur = get(id);
  if (cur.verdict !== 'unreviewed' && cur.verdict_source !== 'auto') return { applied: false, reason: 'analyst' };
  if (mode === 'tp_only' && verdict !== 'true_positive') return { applied: false, reason: 'mode' };
  const now = new Date().toISOString();
  const changed = cur.verdict !== verdict || cur.verdict_source !== 'auto';
  cur.verdict = verdict;
  cur.verdict_source = 'auto';
  cur.updated_at = now;
  if (changed && note) cur.notes.push({ at: now, by: 'auto-analyzer', text: String(note).slice(0, 4000) });
  db[id] = cur;
  persist();
  return { applied: true, changed };
}

module.exports = { get, update, applyAuto, VERDICTS };
