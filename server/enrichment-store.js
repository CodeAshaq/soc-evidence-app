'use strict';
/** Penyimpanan hasil analisa otomatis (JSON, atomic write). Retensi diatur ENRICH_RETENTION_DAYS (0 = tanpa batas). */
const fs = require('fs');
const path = require('path');
const config = require('./config');

const FILE = path.join(__dirname, '..', 'data', 'enrichment.json');
const MAX_AGE_MS = config.auto.retentionDays * 24 * 3600 * 1000;
let db = {};

try {
  db = JSON.parse(fs.readFileSync(FILE, 'utf8'));
} catch (_) {
  db = {};
}
if (!db._meta) db._meta = {};

function persist() {
  if (MAX_AGE_MS > 0) {
    const cutoff = Date.now() - MAX_AGE_MS;
    for (const [id, rec] of Object.entries(db)) {
      if (id !== '_meta' && rec.enriched_at && new Date(rec.enriched_at).getTime() < cutoff) delete db[id];
    }
  }
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  const tmp = `${FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, FILE);
}

const get = (id) => (id !== '_meta' && db[id]) || null;
function set(id, rec) {
  if (id === '_meta') return;
  db[id] = rec;
  persist();
}
const getMeta = () => db._meta || {};
function setMeta(m) {
  db._meta = { ...db._meta, ...m };
  persist();
}
const count = () => Object.keys(db).filter((k) => k !== '_meta').length;

module.exports = { get, set, getMeta, setMeta, count };
