'use strict';
const fs = require('fs');
const net = require('net');
const { Client } = require('@elastic/elasticsearch');
const config = require('./config');
const { flatten } = require('./extract');

let client;
function getClient() {
  if (client) return client;
  const opts = { node: config.es.node, tls: { rejectUnauthorized: config.es.rejectUnauthorized } };
  if (config.es.caCert) opts.tls.ca = fs.readFileSync(config.es.caCert);
  if (config.es.apiKey) opts.auth = { apiKey: config.es.apiKey };
  else if (config.es.username) opts.auth = { username: config.es.username, password: config.es.password };
  client = new Client(opts);
  return client;
}

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const STATUSES = ['open', 'acknowledged', 'closed', 'in-progress'];

function clampInt(v, min, max, d) {
  const n = parseInt(v, 10);
  if (Number.isNaN(n)) return d;
  return Math.min(Math.max(n, min), max);
}

function isoOrDefault(v, fallback) {
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? fallback : d.toISOString();
}

/** Ringkas satu hit alert untuk tampilan daftar. */
function summarize(hit) {
  const f = flatten(hit._source);
  const g = (k) => (Array.isArray(f[k]) ? f[k][0] : f[k]);
  return {
    id: hit._id,
    timestamp: g('@timestamp'),
    rule: g('kibana.alert.rule.name'),
    severity: g('kibana.alert.severity'),
    risk_score: g('kibana.alert.risk_score'),
    status: g('kibana.alert.workflow_status'),
    source_ip: g('source.ip'),
    source_port: g('source.port'),
    destination_ip: g('destination.ip'),
    destination_port: g('destination.port'),
    host: g('host.name'),
    user: g('user.name'),
    dataset: g('event.dataset'),
    reason: g('kibana.alert.reason'),
  };
}

async function searchAlerts(p = {}) {
  const now = new Date();
  const from = isoOrDefault(p.from, new Date(now - 24 * 3600 * 1000).toISOString());
  const to = isoOrDefault(p.to, now.toISOString());
  const filter = [{ range: { '@timestamp': { gte: from, lte: to } } }];

  if (SEVERITIES.includes(p.severity)) filter.push({ term: { 'kibana.alert.severity': p.severity } });
  if (STATUSES.includes(p.status)) filter.push({ term: { 'kibana.alert.workflow_status': p.status } });

  const must = [];
  if (p.q && String(p.q).trim()) {
    const q = String(p.q).trim().slice(0, 200);
    if (net.isIP(q)) {
      filter.push({
        bool: {
          should: [
            { term: { 'source.ip': q } },
            { term: { 'destination.ip': q } },
            { term: { 'host.ip': q } },
          ],
          minimum_should_match: 1,
        },
      });
    } else {
      must.push({
        simple_query_string: {
          query: q,
          fields: ['kibana.alert.rule.name', 'kibana.alert.reason', 'host.name', 'user.name', 'process.name', 'event.dataset'],
          default_operator: 'and',
        },
      });
    }
  }

  // size s.d. 500 per halaman; offset untuk halaman berikutnya (batas jendela hasil Elasticsearch = 10.000)
  const size = clampInt(p.size, 1, 500, 50);
  const offset = Math.min(clampInt(p.offset, 0, 10000, 0), 10000 - size);
  const res = await getClient().search({
    index: config.es.alertIndex,
    size,
    from: offset,
    sort: [{ '@timestamp': 'desc' }],
    ignore_unavailable: true,
    track_total_hits: true,
    query: { bool: { filter, must } },
  });
  const total = typeof res.hits.total === 'object' ? res.hits.total.value : res.hits.total;
  return { total, alerts: res.hits.hits.map(summarize) };
}

async function getAlert(id) {
  const res = await getClient().search({
    index: config.es.alertIndex,
    size: 1,
    query: { ids: { values: [String(id)] } },
  });
  const hit = res.hits.hits[0];
  return hit ? { id: hit._id, source: hit._source } : null;
}

/** Cari event terkait (pivot) berdasarkan IP / host / user pada jendela waktu tertentu. */
async function relatedEvents({ ips = [], hosts = [], users = [], from, to, size }) {
  const should = [];
  for (const ip of ips.filter((x) => net.isIP(x)).slice(0, 10)) {
    should.push({ term: { 'source.ip': ip } }, { term: { 'destination.ip': ip } });
  }
  for (const h of hosts.slice(0, 5)) should.push({ term: { 'host.name': String(h).slice(0, 255) } });
  for (const u of users.slice(0, 5)) should.push({ term: { 'user.name': String(u).slice(0, 255) } });
  if (!should.length) return { total: 0, events: [] };

  const res = await getClient().search({
    index: config.es.eventIndex,
    size: clampInt(size, 1, 200, 100),
    sort: [{ '@timestamp': 'desc' }],
    ignore_unavailable: true,
    track_total_hits: true,
    query: {
      bool: {
        filter: [{ range: { '@timestamp': { gte: from, lte: to } } }],
        should,
        minimum_should_match: 1,
      },
    },
  });
  const total = typeof res.hits.total === 'object' ? res.hits.total.value : res.hits.total;
  return {
    total,
    events: res.hits.hits.map((h) => {
      const f = flatten(h._source);
      const g = (k) => (Array.isArray(f[k]) ? f[k][0] : f[k]);
      return {
        id: h._id,
        index: h._index,
        timestamp: g('@timestamp'),
        dataset: g('event.dataset'),
        action: g('event.action'),
        outcome: g('event.outcome'),
        source_ip: g('source.ip'),
        source_port: g('source.port'),
        destination_ip: g('destination.ip'),
        destination_port: g('destination.port'),
        protocol: g('network.transport') || g('network.protocol'),
        host: g('host.name'),
        user: g('user.name'),
        process: g('process.name'),
        message: g('message') || g('event.original'),
      };
    }),
  };
}

/** Ubah status alert melalui Kibana Detections API (opsional). */
async function setAlertStatus(id, status, reason) {
  if (!config.kibana.url) return { ok: false, skipped: true, message: 'KIBANA_URL belum diatur; status hanya disimpan lokal.' };
  const map = { 'in-progress': 'acknowledged' };
  const body = { signal_ids: [id], status: map[status] || status };
  if (reason) body.reason = String(reason).slice(0, 200);
  const headers = { 'Content-Type': 'application/json', 'kbn-xsrf': 'true' };
  if (config.kibana.apiKey) headers.Authorization = `ApiKey ${config.kibana.apiKey}`;
  const r = await fetch(`${config.kibana.url}/api/detection_engine/signals/status`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  if (!r.ok) return { ok: false, message: `Kibana menjawab ${r.status}` };
  return { ok: true };
}

async function health() {
  const info = await getClient().info();
  return { cluster: info.cluster_name, version: info.version && info.version.number };
}

module.exports = { searchAlerts, getAlert, relatedEvents, setAlertStatus, health, SEVERITIES, STATUSES };
