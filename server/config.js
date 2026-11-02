'use strict';
require('dotenv').config();
const path = require('path');

const bool = (v, d = false) => (v === undefined || v === '' ? d : String(v).toLowerCase() === 'true');
const list = (v, d) => (v ? v.split(',').map((s) => s.trim()).filter(Boolean) : d);
const num = (v, d, min, max) => {
  const n = parseInt(v, 10);
  return Number.isNaN(n) ? d : Math.min(Math.max(n, min), max);
};

module.exports = {
  port: parseInt(process.env.PORT || '3000', 10),
  host: process.env.HOST || '127.0.0.1',
  demoMode: bool(process.env.DEMO_MODE, false),
  appToken: process.env.APP_TOKEN || '',

  es: {
    node: process.env.ES_NODE || 'https://localhost:9200',
    apiKey: process.env.ES_API_KEY || '',
    username: process.env.ES_USERNAME || '',
    password: process.env.ES_PASSWORD || '',
    rejectUnauthorized: bool(process.env.ES_TLS_REJECT_UNAUTHORIZED, true),
    caCert: process.env.ES_CA_CERT || '',
    alertIndex: process.env.ES_ALERT_INDEX || '.alerts-security.alerts-default',
    eventIndex: list(process.env.ES_EVENT_INDEX, ['logs-*', 'filebeat-*', 'winlogbeat-*']),
  },

  kibana: {
    url: (process.env.KIBANA_URL || '').replace(/\/$/, ''),
    apiKey: process.env.KIBANA_API_KEY || '',
  },

  ti: {
    vtKey: process.env.VT_API_KEY || '',
    abuseKey: process.env.ABUSEIPDB_API_KEY || '',
    cacheMinutes: parseInt(process.env.IOC_CACHE_MINUTES || '60', 10),
  },

  // Analisa otomatis (worker). Hanya memberi rekomendasi; tidak mengubah verdict/status alert.
  auto: {
    enabled: bool(process.env.AUTO_ENRICH, false),
    severities: list(process.env.AUTO_SEVERITIES, ['high', 'critical']).map((s) => s.toLowerCase()),
    pollSeconds: num(process.env.AUTO_POLL_SECONDS, 60, 15, 3600),
    maxPerCycle: num(process.env.AUTO_MAX_PER_CYCLE, 10, 1, 50),
    // Jendela pemeriksaan alert baru. Boleh sampai 1 tahun (525600 menit).
    lookbackMinutes: num(process.env.AUTO_LOOKBACK_MINUTES, 60, 5, 525600),
    // Bila worker sempat mati, seberapa jauh ke belakang ia menyusul alert yang terlewat (jam).
    catchupHours: num(process.env.AUTO_MAX_CATCHUP_HOURS, 168, 1, 8760),
    // 'all' = semua verdict otomatis tersimpan; 'tp_only' = hanya true positive; 'off' = hanya rekomendasi.
    applyVerdict: ['all', 'tp_only', 'off'].includes(String(process.env.AUTO_APPLY_VERDICT || 'all').toLowerCase())
      ? String(process.env.AUTO_APPLY_VERDICT || 'all').toLowerCase() : 'all',
    backfillMax: num(process.env.AUTO_BACKFILL_MAX, 300, 1, 2000),
    retentionDays: num(process.env.ENRICH_RETENTION_DAYS, 365, 0, 3650),
    // jeda antar lookup API eksternal; 16000 ms ~ batas VirusTotal gratis (4/menit). Set 0 untuk API berbayar.
    tiIntervalMs: num(process.env.AUTO_TI_INTERVAL_MS, 16000, 0, 120000),
    windowMinutes: num(process.env.AUTO_WINDOW_MINUTES, 15, 1, 43200),
    rulesFile: process.env.RULES_FILE || path.join(__dirname, '..', 'rules.json'),
  },
};
