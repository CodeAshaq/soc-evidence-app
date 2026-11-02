'use strict';
const net = require('net');

/** Ratakan objek bersarang menjadi { 'a.b.c': value } (alert Elastic bisa nested atau sudah flat). */
function flatten(obj, prefix = '', out = {}) {
  if (obj === null || obj === undefined) return out;
  if (Array.isArray(obj)) {
    if (obj.every((x) => typeof x !== 'object' || x === null)) {
      out[prefix] = obj;
    } else {
      obj.forEach((x, i) => flatten(x, `${prefix}[${i}]`, out));
    }
    return out;
  }
  if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      flatten(v, prefix ? `${prefix}.${k}` : k, out);
    }
    return out;
  }
  out[prefix] = obj;
  return out;
}

const first = (v) => (Array.isArray(v) ? v[0] : v);
const all = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
const uniq = (a) => [...new Set(a.filter(Boolean))];
const isObj = (x) => x && typeof x === 'object' && !Array.isArray(x);

const TACTIC_IDS = {
  reconnaissance: 'TA0043', 'resource development': 'TA0042', 'initial access': 'TA0001', execution: 'TA0002',
  persistence: 'TA0003', 'privilege escalation': 'TA0004', 'defense evasion': 'TA0005', 'credential access': 'TA0006',
  discovery: 'TA0007', 'lateral movement': 'TA0008', collection: 'TA0009', 'command and control': 'TA0011',
  exfiltration: 'TA0010', impact: 'TA0040',
};

/** Ambil nilai dari dokumen yang kuncinya bisa bersarang ATAU berupa string bertitik ("a.b.c"). */
function pick(o, p) {
  if (o === null || o === undefined || typeof o !== 'object') return undefined;
  if (Object.prototype.hasOwnProperty.call(o, p)) return o[p];
  const parts = p.split('.');
  for (let i = 1; i < parts.length; i++) {
    const head = parts.slice(0, i).join('.');
    if (Object.prototype.hasOwnProperty.call(o, head)) {
      const r = pick(o[head], parts.slice(i).join('.'));
      if (r !== undefined) return r;
    }
  }
  return undefined;
}

/**
 * Baca pemetaan MITRE ATT&CK dari rule Elastic. Mendukung struktur asli
 * (kibana.alert.rule.parameters.threat[].tactic / technique[].subtechnique[]) dan bentuk datar
 * (array paralel kibana.alert.rule.threat.*). Hasil: [{tactic_id, tactic, technique_id, technique}]
 */
function parseThreat(source, f) {
  const rows = [];
  const push = (tac, tech, sub) => {
    const tName = tac && tac.name ? String(tac.name) : '';
    const tId = (tac && tac.id) || TACTIC_IDS[tName.toLowerCase()] || '';
    const id = (sub && sub.id) || (tech && tech.id) || '';
    if (!id && !tName) return;
    const name = sub && sub.name ? `${tech && tech.name ? `${tech.name}: ` : ''}${sub.name}` : (tech && tech.name) || '';
    rows.push({ tactic_id: String(tId), tactic: tName, technique_id: String(id), technique: String(name) });
  };

  let list = all(pick(source, 'kibana.alert.rule.parameters.threat'));
  if (!list.length) list = all(pick(source, 'kibana.alert.rule.threat'));
  if (list.some((t) => isObj(t) && (t.tactic || t.technique))) {
    for (const t of list) {
      if (!isObj(t)) continue;
      const tac = all(t.tactic)[0];
      const techs = all(t.technique);
      if (!techs.length) push(tac, null, null);
      for (const tech of techs) {
        const subs = all(tech && tech.subtechnique);
        if (subs.length) subs.forEach((s) => push(tac, tech, s));
        else push(tac, tech, null);
      }
    }
  }
  if (rows.length) return rows;

  // Bentuk datar: hubungan tactic-technique hilang, jadi tactic hanya dipakai bila tunggal.
  const tNames = all(f['kibana.alert.rule.threat.tactic.name']);
  const tIds = all(f['kibana.alert.rule.threat.tactic.id']);
  const tacs = tNames.map((n, i) => ({ name: n, id: tIds[i] }));
  const only = tacs.length === 1 ? tacs[0] : null;
  const subIds = all(f['kibana.alert.rule.threat.technique.subtechnique.id']);
  const subNames = all(f['kibana.alert.rule.threat.technique.subtechnique.name']);
  const techIds = all(f['kibana.alert.rule.threat.technique.id']);
  const techNames = all(f['kibana.alert.rule.threat.technique.name']);
  subIds.forEach((id, i) => push(only, { id: String(id).split('.')[0], name: '' }, { id, name: subNames[i] }));
  techIds.forEach((id, i) => { if (!subIds.some((s) => String(s).startsWith(`${id}.`))) push(only, { id, name: techNames[i] }, null); });
  if (!rows.length && only) push(only, null, null);
  return rows;
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 10 ||
      a === 127 ||
      a === 0 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127) || // CGNAT
      a >= 224
    );
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::1' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80');
  }
  return false;
}

const RE = {
  md5: /^[a-f0-9]{32}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  sha256: /^[a-f0-9]{64}$/i,
  domain: /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i,
};

/** Tentukan tipe IOC dari string. Mengembalikan null bila tidak valid. */
function detectIocType(value) {
  const v = String(value || '').trim();
  if (!v || v.length > 2048) return null;
  if (net.isIP(v)) return 'ip';
  if (RE.sha256.test(v)) return 'sha256';
  if (RE.sha1.test(v)) return 'sha1';
  if (RE.md5.test(v)) return 'md5';
  if (/^https?:\/\/[^\s]+$/i.test(v)) return 'url';
  if (RE.domain.test(v)) return 'domain';
  return null;
}

/** Field ECS yang dianggap sumber IOC / evidence. */
const FIELD_MAP = [
  { fields: ['source.ip'], type: 'ip', role: 'source' },
  { fields: ['destination.ip'], type: 'ip', role: 'destination' },
  { fields: ['client.ip'], type: 'ip', role: 'client' },
  { fields: ['server.ip'], type: 'ip', role: 'server' },
  { fields: ['host.ip'], type: 'ip', role: 'host' },
  { fields: ['source.nat.ip'], type: 'ip', role: 'source-nat' },
  { fields: ['dns.question.name', 'url.domain', 'destination.domain', 'source.domain'], type: 'domain', role: 'domain' },
  { fields: ['url.full', 'url.original'], type: 'url', role: 'url' },
  { fields: ['file.hash.sha256', 'process.hash.sha256', 'dll.hash.sha256'], type: 'sha256', role: 'file-hash' },
  { fields: ['file.hash.sha1', 'process.hash.sha1'], type: 'sha1', role: 'file-hash' },
  { fields: ['file.hash.md5', 'process.hash.md5'], type: 'md5', role: 'file-hash' },
];

/**
 * Ekstrak evidence terstruktur dari satu dokumen alert (_source).
 * Hasilnya dipakai oleh UI untuk ringkasan, tombol pivot, dan validasi IOC.
 */
function extractEvidence(source) {
  const f = flatten(source);
  const g = (k) => first(f[k]);

  const iocs = [];
  const seen = new Set();
  for (const m of FIELD_MAP) {
    for (const field of m.fields) {
      for (const val of all(f[field])) {
        const v = String(val).trim();
        const key = `${m.type}:${v.toLowerCase()}`;
        if (!v || seen.has(key)) continue;
        seen.add(key);
        iocs.push({
          type: m.type,
          value: v,
          role: m.role,
          field,
          private: m.type === 'ip' ? isPrivateIp(v) : false,
        });
      }
    }
  }

  const network = {
    source_ip: g('source.ip'),
    source_port: g('source.port'),
    destination_ip: g('destination.ip'),
    destination_port: g('destination.port'),
    protocol: g('network.transport') || g('network.protocol'),
    direction: g('network.direction'),
    bytes: g('network.bytes'),
    action: g('event.action') || g('event.outcome'),
    source_country: g('source.geo.country_name'),
  };

  const host = {
    name: g('host.name'),
    os: g('host.os.name'),
    ip: all(f['host.ip']),
    mac: all(f['host.mac']),
  };

  const user = {
    name: g('user.name'),
    domain: g('user.domain'),
    email: g('user.email'),
  };

  const process = {
    name: g('process.name'),
    pid: g('process.pid'),
    command_line: g('process.command_line') || (Array.isArray(f['process.args']) ? f['process.args'].join(' ') : undefined),
    executable: g('process.executable'),
    parent_name: g('process.parent.name'),
    parent_command_line: g('process.parent.command_line'),
  };

  const file = {
    path: g('file.path'),
    name: g('file.name'),
    sha256: g('file.hash.sha256') || g('process.hash.sha256'),
  };

  const threat = parseThreat(source, f);

  const rule = {
    name: g('kibana.alert.rule.name'),
    description: g('kibana.alert.rule.description'),
    severity: g('kibana.alert.severity'),
    risk_score: g('kibana.alert.risk_score'),
    reason: g('kibana.alert.reason'),
    status: g('kibana.alert.workflow_status'),
    tags: all(f['kibana.alert.rule.tags']),
    threat,
    mitre_tactic: uniq(threat.map((t) => t.tactic)),
    mitre_technique: uniq(threat.map((t) => t.technique)),
    mitre_ids: uniq(threat.map((t) => t.technique_id)),
    references: all(f['kibana.alert.rule.references']),
  };

  const meta = {
    event_dataset: g('event.dataset'),
    event_module: g('event.module'),
    event_category: all(f['event.category']),
    event_original: g('event.original') || g('message'),
    agent_name: g('agent.name'),
  };

  return { rule, network, host, user, process, file, meta, iocs };
}

module.exports = { flatten, extractEvidence, detectIocType, isPrivateIp, first, all, pick, parseThreat, TACTIC_IDS };
