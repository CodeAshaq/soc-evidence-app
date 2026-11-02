'use strict';
/**
 * Analisa otomatis berbasis aturan dan MITRE ATT&CK.
 * Menghasilkan: skor, verdict, prioritas, tabel TTP (Tactic / Technique / Procedure), dan narasi analis
 * (root cause, aktivitas threat actor, hasil pemeriksaan, kesimpulan triage, rekomendasi tindakan).
 * Semua kalimat disusun dari bukti yang benar-benar ada pada alert; tidak ada fakta yang dikarang.
 * Bobot dan daftar aman dibaca dari rules.json (bila tidak ada, dipakai nilai bawaan).
 */
const fs = require('fs');
const net = require('net');
const config = require('./config');
const { isPrivateIp, TACTIC_IDS } = require('./extract');

const SCHEMA = 2;

const DEFAULT_RULES = {
  version: 2,
  weights: {
    severity: { critical: 35, high: 25, medium: 10, low: 0 },
    ioc_malicious: 40, ioc_suspicious: 20, ioc_cap: 60,
    suspicious_chain: 25, suspicious_cmdline: 20,
    scan_pattern: 15, bruteforce: 20, bruteforce_then_success: 30,
    allowlist: -50,
  },
  thresholds: { likely_tp: 85, investigate: 25 },
  scan: { min_distinct_ports: 4 },
  bruteforce: { min_failures: 4 },
  allowlist: { ips: [], hosts: [], users: [] },
  suspicious_chains: [
    ['winword.exe', 'powershell.exe'], ['winword.exe', 'cmd.exe'], ['excel.exe', 'powershell.exe'],
    ['excel.exe', 'cmd.exe'], ['outlook.exe', 'powershell.exe'], ['mshta.exe', 'powershell.exe'], ['wmiprvse.exe', 'powershell.exe'],
  ],
  suspicious_cmdline: [
    '-enc ', '-encodedcommand', 'downloadstring', 'downloadfile', 'invoke-expression', 'iex ',
    'frombase64string', '-nop', '-w hidden', 'certutil -urlcache', 'bitsadmin /transfer',
  ],
};

const isObj = (x) => x && typeof x === 'object' && !Array.isArray(x);
function merge(base, extra) {
  const out = { ...base };
  for (const [k, v] of Object.entries(extra || {})) out[k] = isObj(v) && isObj(base[k]) ? merge(base[k], v) : v;
  return out;
}

let cache = { mtime: 0, rules: DEFAULT_RULES, warned: false };
function loadRules() {
  try {
    const st = fs.statSync(config.auto.rulesFile);
    if (!st.isFile() || st.mtimeMs === cache.mtime) return cache.rules;
    const user = JSON.parse(fs.readFileSync(config.auto.rulesFile, 'utf8'));
    cache = { ...cache, mtime: st.mtimeMs, rules: merge(DEFAULT_RULES, user) };
  } catch (e) {
    if (e.code !== 'ENOENT' && !cache.warned) {
      console.warn(`[auto] rules.json tidak bisa dibaca (${e.message}); memakai aturan sebelumnya/bawaan.`);
      cache.warned = true;
    }
  }
  return cache.rules;
}

// ---------- Katalog MITRE ATT&CK yang dipakai detektor ----------
const TACTIC_ORDER = ['TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011', 'TA0010', 'TA0040'];
const TACTIC_NAME = {};
for (const [name, id] of Object.entries(TACTIC_IDS)) TACTIC_NAME[id] = name.replace(/\b\w/g, (c) => c.toUpperCase()).replace(/ And /, ' and ');

// id -> [nama teknik, id tactic utama]
const TECH = {
  'T1566.001': ['Phishing: Spearphishing Attachment', 'TA0001'],
  'T1078': ['Valid Accounts', 'TA0001'],
  'T1204.002': ['User Execution: Malicious File', 'TA0002'],
  'T1059.001': ['Command and Scripting Interpreter: PowerShell', 'TA0002'],
  'T1059.003': ['Command and Scripting Interpreter: Windows Command Shell', 'TA0002'],
  'T1047': ['Windows Management Instrumentation', 'TA0002'],
  'T1564.003': ['Hide Artifacts: Hidden Window', 'TA0005'],
  'T1027': ['Obfuscated Files or Information', 'TA0005'],
  'T1110': ['Brute Force', 'TA0006'],
  'T1046': ['Network Service Discovery', 'TA0007'],
  'T1105': ['Ingress Tool Transfer', 'TA0011'],
  'T1071.001': ['Application Layer Protocol: Web Protocols', 'TA0011'],
  'T1571': ['Non-Standard Port', 'TA0011'],
};
const CONF_RANK = { indicated: 1, strong: 2, confirmed: 3 };

const OFFICE = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'onenote.exe', 'msaccess.exe'];
const SHELLS = ['powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe'];
const AUTH_RE = /log(in|on)|auth|sign-?in|userloggedin|462[45]/i;
const ALLOW_RE = /accept|allow|permit|pass|success/i;
const DENY_RE = /deny|drop|block|reject|fail/i;

const lower = (s) => String(s === undefined || s === null ? '' : s).toLowerCase();
const trunc = (s, n) => { const t = String(s || ''); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };
const baseName = (p) => String(p || '').split(/[\\/]/).pop();
const dirName = (p) => { const s = String(p || ''); const i = Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/')); return i > 0 ? s.slice(0, i) : ''; };

// Narasi = array bagian: string biasa atau { v: nilai } (ditampilkan monospace oleh UI)
const V = (x) => ({ v: String(x) });
function vals(list, max = 4) {
  const out = [];
  list.slice(0, max).forEach((x, i) => { if (i) out.push(', '); out.push(V(x)); });
  if (list.length > max) out.push(` dan ${list.length - max} lainnya`);
  return out;
}

function ipv4ToInt(ip) { return ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0; }
function inList(ip, list) {
  for (const raw of list || []) {
    const s = String(raw).trim();
    if (s === ip) return true;
    if (s.includes('/') && net.isIPv4(ip)) {
      const [base, bitsStr] = s.split('/');
      const bits = Number(bitsStr);
      if (net.isIPv4(base) && Number.isInteger(bits) && bits >= 0 && bits <= 32) {
        const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
        if ((ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask)) return true;
      }
    }
  }
  return false;
}

function relTime(alertTs, evTs) {
  const d = Math.round((new Date(alertTs) - new Date(evTs)) / 60000);
  if (Number.isNaN(d) || Math.abs(d) < 1) return 'bersamaan dengan alert';
  return d > 0 ? `sekitar ${d} menit sebelum alert` : `sekitar ${-d} menit setelah alert`;
}

function analyze({ evidence: rawEv, related, iocResults, rules, windowMinutes }) {
  // Normalisasi: bagian evidence yang kosong tidak boleh membuat analisa gagal
  const ev = { ...rawEv, rule: rawEv.rule || {}, network: rawEv.network || {}, host: rawEv.host || {}, user: rawEv.user || {}, process: rawEv.process || {}, file: rawEv.file || {}, meta: rawEv.meta || {}, iocs: rawEv.iocs || [] };
  const R = rules || loadRules();
  const W = R.weights;
  const events = related.events || [];
  const winMin = windowMinutes || config.auto.windowMinutes;
  const reasons = [];
  const notes = [];
  let score = 0;
  const add = (points, text, kind) => { score += points; reasons.push({ points, text, kind }); };

  const n = ev.network;
  const host = ev.host.name;
  const user = ev.user.name ? (ev.user.domain ? `${ev.user.domain}\\${ev.user.name}` : ev.user.name) : '';
  const srcIp = n.source_ip;
  const dstIp = n.destination_ip;
  const dstPort = n.destination_port;
  const domainIoc = (ev.iocs.find((i) => i.type === 'domain') || {}).value;
  const dest = domainIoc || dstIp;

  // ---------- Sinyal skor (sama seperti sebelumnya) ----------
  const sev = lower(ev.rule.severity);
  const sevPts = (W.severity || {})[sev] || 0;
  if (sevPts) add(sevPts, `Severity rule Elastic: ${sev}`, 'severity');

  const mal = iocResults.filter((r) => r.verdict === 'malicious');
  const sus = iocResults.filter((r) => r.verdict === 'suspicious');
  const clean = iocResults.filter((r) => r.verdict === 'clean');
  const unknown = iocResults.length - mal.length - sus.length - clean.length;
  const simulated = iocResults.some((r) => r.note && String(r.note).startsWith('Mode demo'));
  const iocPts = Math.min(W.ioc_cap, mal.length * W.ioc_malicious + sus.length * W.ioc_suspicious);
  if (iocPts > 0) add(iocPts, `IOC berreputasi buruk: ${[...mal, ...sus].map((r) => `${r.value} (${r.verdict})`).join(', ')}${simulated ? ' [simulasi]' : ''}`, 'ioc');

  const proc = lower(ev.process.name);
  const parent = lower(ev.process.parent_name);
  const cmdRaw = ev.process.command_line || '';
  const cmd = lower(cmdRaw);
  const chain = (R.suspicious_chains || []).find(([p, c]) => lower(p) === parent && lower(c) === proc);
  if (chain) add(W.suspicious_chain, `Rantai proses mencurigakan: ${ev.process.parent_name} → ${ev.process.name}`, 'process');
  const cmdHits = cmd ? (R.suspicious_cmdline || []).filter((p) => cmd.includes(lower(p))) : [];
  if (cmdHits.length) add(W.suspicious_cmdline, `Command line mengandung pola mencurigakan: ${cmdHits.slice(0, 4).map((x) => x.trim()).join(', ')}`, 'process');

  let scan = false;
  let scanPorts = [];
  if (srcIp) {
    const ports = new Set(events.filter((e) => e.source_ip === srcIp && e.destination_port != null).map((e) => Number(e.destination_port)));
    if (dstPort != null) ports.add(Number(dstPort));
    if (ports.size >= R.scan.min_distinct_ports) {
      scan = true;
      scanPorts = [...ports].sort((a, b) => a - b);
      add(W.scan_pattern, `Sumber ${srcIp} menjangkau ${ports.size} port tujuan berbeda (${scanPorts.slice(0, 8).join(', ')})`, 'network');
    }
  }

  const sameActor = (e) => (srcIp ? e.source_ip === srcIp : Boolean(ev.user.name) && e.user === ev.user.name);
  const fails = events.filter((e) => AUTH_RE.test(String(e.action || '')) && lower(e.outcome) === 'failure' && sameActor(e));
  let bf = false;
  let successAfter = false;
  if (fails.length >= R.bruteforce.min_failures) {
    bf = true;
    const firstFail = Math.min(...fails.map((e) => new Date(e.timestamp).getTime()));
    successAfter = events.some((e) => AUTH_RE.test(String(e.action || '')) && lower(e.outcome) === 'success' && sameActor(e) && new Date(e.timestamp).getTime() > firstFail);
    if (successAfter) add(W.bruteforce_then_success, `Login berhasil dari sumber yang sama setelah ${fails.length} kegagalan: kredensial kemungkinan berhasil ditebak`, 'auth');
    else add(W.bruteforce, `${fails.length} kegagalan login berulang dari sumber yang sama`, 'auth');
  }

  const al = R.allowlist || {};
  const allowHit = [];
  if (srcIp && inList(srcIp, al.ips)) allowHit.push(`IP sumber ${srcIp}`);
  if (dstIp && inList(dstIp, al.ips)) allowHit.push(`IP tujuan ${dstIp}`);
  if (host && (al.hosts || []).some((x) => lower(x) === lower(host))) allowHit.push(`host ${host}`);
  if (ev.user.name && (al.users || []).some((x) => lower(x) === lower(ev.user.name))) allowHit.push(`user ${ev.user.name}`);
  if (allowHit.length) add(W.allowlist, `Cocok dengan daftar aman: ${allowHit.join(', ')}`, 'allowlist');

  score = Math.max(0, Math.min(100, score));

  // ---------- Verdict & prioritas ----------
  const T = R.thresholds;
  let verdict;
  if (score >= T.likely_tp) verdict = 'true_positive';
  else if (score >= T.investigate) verdict = 'needs_investigation';
  else if (allowHit.length || (['low', 'medium'].includes(sev) && !mal.length && !sus.length)) verdict = 'false_positive';
  else verdict = 'needs_investigation'; // severity tinggi tanpa sinyal lain: jangan diturunkan otomatis
  const level = { true_positive: 'high', needs_investigation: 'medium', false_positive: 'low' }[verdict];
  const label = { true_positive: 'True positive', needs_investigation: 'Perlu investigasi', false_positive: 'Kemungkinan false positive' }[verdict];
  let priority;
  if (verdict === 'true_positive') priority = ['critical', 'high'].includes(sev) || score >= 90 ? 'P1' : 'P2';
  else if (verdict === 'needs_investigation') priority = score >= 60 ? 'P2' : 'P3';
  else priority = 'P4';

  const haveTI = clean.length + mal.length + sus.length > 0 && !simulated;
  const haveCtx = (related.total || 0) > 0;
  const confidence = haveTI && haveCtx ? 'tinggi' : haveTI || haveCtx ? 'sedang' : 'rendah';

  if (iocResults.length && !haveTI && !simulated) notes.push('Reputasi IOC belum tersedia (API key belum diisi, kuota habis, atau IOC tidak dikenal layanan threat intelligence). Skor hanya berdasar konteks.');
  if (iocResults.some((r) => (r.sources || []).some((s) => s.error && /429/.test(s.error)))) notes.push('Kuota API threat intelligence terlampaui; sebagian IOC belum tervalidasi.');
  if (simulated) notes.push('Hasil validasi IOC adalah simulasi (mode demo).');
  if (related.error) notes.push('Event terkait gagal dimuat; konteks analisa terbatas.');
  if (clean.length && !mal.length && !sus.length) notes.push('IOC berstatus "clean" bukan jaminan aman: infrastruktur baru sering belum terdaftar di layanan threat intelligence.');

  // ---------- Sinyal perilaku untuk TTP & narasi ----------
  const isOfficeParent = OFFICE.includes(parent);
  const isShell = SHELLS.includes(proc);
  const hidden = /(^|\s)-(w|win|window|windowstyle)\s+hidden/.test(cmd);
  const encoded = /(^|\s)-(e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{20,}/.test(cmd) || cmd.includes('frombase64string');
  const download = /downloadstring|downloadfile|invoke-webrequest|(^|\s)iwr(\s|$)|start-bitstransfer|certutil.*-urlcache|bitsadmin.*\/transfer|(^|\s)(curl|wget)(\s|\.exe)/.test(cmd);
  const iex = /(^|[\s;(|])iex(\s|\()|invoke-expression/.test(cmd);
  const fileName = ev.file.name || baseName(ev.file.path);
  const conn = events.filter((e) => dstIp && e.destination_ip === dstIp && (!srcIp || e.source_ip === srcIp));
  const connAllowed = conn.filter((e) => ALLOW_RE.test(`${e.action || ''} ${e.outcome || ''}`));
  const connDenied = conn.filter((e) => DENY_RE.test(`${e.action || ''} ${e.outcome || ''}`));

  // ---------- TTP (Tactic / Technique / Procedure) ----------
  const found = new Map();
  const info = (id) => {
    const c = TECH[id] || [];
    return { technique: c[0] || '', tactic_id: c[1] || '' };
  };
  const addTtp = (id, procedure, confidence, source) => {
    const prev = found.get(id);
    if (prev) {
      if (source === 'evidence' && prev.source === 'rule') {
        prev.source = 'rule+evidence';
        prev.procedure = procedure;
        prev.confidence = CONF_RANK[confidence] > CONF_RANK[prev.confidence] ? confidence : prev.confidence;
      } else if (CONF_RANK[confidence] > CONF_RANK[prev.confidence]) {
        prev.confidence = confidence;
        prev.procedure = procedure;
      }
      return;
    }
    const i = info(id);
    found.set(id, {
      tactic_id: i.tactic_id, tactic: TACTIC_NAME[i.tactic_id] || '', technique_id: id, technique: i.technique || id,
      procedure, confidence, source,
    });
  };

  // a) dari rule Elastic
  for (const t of ev.rule.threat || []) {
    const id = t.technique_id || '';
    if (!id && !t.tactic) continue;
    const cat = TECH[id];
    const tid = (cat && cat[1]) || t.tactic_id || '';
    const key = id || `${t.tactic}:${t.technique}`;
    const row = {
      tactic_id: tid, tactic: TACTIC_NAME[tid] || t.tactic || '', technique_id: id,
      technique: (cat && cat[0]) || t.technique || id,
      procedure: `Dipetakan oleh rule Elastic "${ev.rule.name || '-'}".`, confidence: 'indicated', source: 'rule',
    };
    if (!found.has(key)) found.set(key, row);
  }

  // b) dari bukti pada alert dan event terkait
  if (isOfficeParent && isShell) {
    addTtp('T1204.002', `${ev.process.parent_name} membuka ${fileName || 'dokumen'} lalu memunculkan ${ev.process.name}.`, 'strong', 'evidence');
    addTtp('T1566.001', fileName
      ? `Dokumen ${fileName}${dirName(ev.file.path) ? ` (${dirName(ev.file.path)})` : ''} menjadi induk eksekusi; jalur kirim (email/unduhan) belum terkonfirmasi.`
      : 'Aplikasi Office memunculkan shell; jalur kirim awal belum terkonfirmasi.', 'indicated', 'evidence');
  }
  if (/powershell|pwsh/.test(proc) || /powershell|pwsh/.test(cmd)) addTtp('T1059.001', `Command line: ${trunc(cmdRaw || ev.process.name, 300)}`, cmdRaw ? 'confirmed' : 'strong', 'evidence');
  if (proc === 'cmd.exe' && (isOfficeParent || cmdHits.length)) addTtp('T1059.003', `cmd.exe dijalankan${ev.process.parent_name ? ` oleh ${ev.process.parent_name}` : ''}: ${trunc(cmdRaw, 200)}`, 'strong', 'evidence');
  if (hidden) addTtp('T1564.003', 'Argumen jendela tersembunyi pada command line (-w hidden).', 'confirmed', 'evidence');
  if (encoded) addTtp('T1027', 'Perintah ter-encode (Base64) pada command line.', 'confirmed', 'evidence');
  if (download) addTtp('T1105', `Command line mengunduh konten${dest ? ` dari ${dest}` : ''}.`, 'confirmed', 'evidence');
  if (parent === 'wmiprvse.exe' && isShell) addTtp('T1047', 'Proses dibuat oleh WmiPrvSE.exe.', 'strong', 'evidence');
  if (lower(n.direction) === 'outbound' && [80, 443, 8080, 8443].includes(Number(dstPort)) && (download || mal.length)) {
    addTtp('T1071.001', `Koneksi ${n.protocol || 'tcp'} keluar ke ${dstIp}:${dstPort}${n.action ? ` (${n.action})` : ''}.`, 'strong', 'evidence');
  }
  if (scan) addTtp('T1046', `Sumber ${srcIp} menjangkau ${scanPorts.length} port tujuan berbeda (${scanPorts.slice(0, 8).join(', ')}).`, 'strong', 'evidence');
  if (bf) addTtp('T1110', `${fails.length} kegagalan autentikasi berulang dari sumber yang sama.`, 'strong', 'evidence');
  if (bf && successAfter) addTtp('T1078', 'Login berhasil dari sumber yang sama setelah rangkaian kegagalan.', 'strong', 'evidence');

  const ttps = [...found.values()].sort((a, b) => {
    const ia = TACTIC_ORDER.indexOf(a.tactic_id);
    const ib = TACTIC_ORDER.indexOf(b.tactic_id);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.technique_id.localeCompare(b.technique_id);
  });
  const ttpIds = ttps.map((t) => t.technique_id).filter(Boolean);

  // ---------- Skenario & narasi ----------
  let scenario = 'generic';
  if (isOfficeParent && isShell) scenario = 'phish_exec';
  else if ((download || encoded || hidden) && (isShell || /powershell|pwsh/.test(cmd))) scenario = 'script_exec';
  else if (bf) scenario = 'bruteforce';
  else if (scan) scenario = 'scan';
  else if (/sign-?in|travel|login|logon|authentication/i.test(`${ev.rule.name} ${(ev.meta.event_category || []).join(' ')}`) && ev.user.name) scenario = 'account';

  const tiParts = () => {
    if (mal.length) return ['Reputasi: ', ...vals(mal.map((r) => r.value)), ` dinilai malicious oleh layanan threat intelligence${simulated ? ' (hasil simulasi mode demo)' : ''}. `];
    if (sus.length) return ['Reputasi: ', ...vals(sus.map((r) => r.value)), ' dinilai suspicious oleh layanan threat intelligence. '];
    if (clean.length) return ['IOC publik berstatus clean pada layanan threat intelligence; ini tidak menjamin aman karena infrastruktur baru sering belum terdaftar. '];
    if (iocResults.length) return ['Reputasi IOC belum tersedia (API key belum diisi, kuota habis, atau IOC tidak dikenal). '];
    return [];
  };
  const scopeParts = () => (related.total
    ? [`Dari ${related.total} event terkait pada jendela ±${winMin} menit, belum ditemukan aktivitas lanjutan pada log yang tersedia (misalnya proses anak lain atau koneksi ke host internal lain). Cakupan penuh perlu divalidasi lewat telemetri EDR.`]
    : [`Tidak ada event terkait pada jendela ±${winMin} menit, sehingga cakupan analisa terbatas pada isi alert.`]);
  const connParts = () => {
    if (!dstIp) return [];
    if (connAllowed.length) return ['Log jaringan mencatat koneksi ', V(`${srcIp || '?'} → ${dstIp}${dstPort ? `:${dstPort}` : ''}`), ` dengan status diizinkan (${relTime(ev.timestamp, connAllowed[0].timestamp)}), sehingga permintaan kemungkinan besar mencapai tujuan. `];
    if (connDenied.length) return ['Koneksi ke ', V(dstIp), ` tercatat diblokir sebanyak ${connDenied.length} kali pada jendela pemeriksaan; upaya kemungkinan tidak berhasil mencapai tujuan. `];
    return [`Belum ada log jaringan pada jendela ±${winMin} menit yang mengonfirmasi apakah koneksi ke `, V(dstIp), ' berhasil. '];
  };

  let rootCause;
  let activity;
  let findings;
  let checks;
  let actions;

  if (scenario === 'phish_exec' || scenario === 'script_exec') {
    const proto = scenario === 'phish_exec';
    rootCause = proto
      ? [`Aktivitas diawali ketika user `, V(user || 'tidak diketahui'), ' membuka ', fileName ? V(fileName) : 'dokumen Office', ` pada host `, V(host || '-'), '. ', V(ev.process.parent_name || 'Aplikasi Office'), ' kemudian memunculkan ', V(ev.process.name || 'shell'), ' sebagai proses anak, pola yang umum pada eksekusi makro dari lampiran phishing. Jalur kirim awal (email, unduhan, atau media lain) belum dapat dikonfirmasi dari data yang tersedia.']
      : ['Proses ', V(ev.process.name || '-'), ev.process.parent_name ? ' (induk: ' : '', ev.process.parent_name ? V(ev.process.parent_name) : '', ev.process.parent_name ? ')' : '', ' berjalan pada host ', V(host || '-'), user ? ' atas nama ' : '', user ? V(user) : '', ' dengan argumen yang mengindikasikan eksekusi skrip jarak jauh. Cara aktivitas ini pertama kali masuk belum dapat dipastikan dari data yang tersedia.'];
    activity = ['Threat actor menjalankan ', V(ev.process.name || 'shell'), hidden ? ' dengan jendela tersembunyi' : '', encoded ? (hidden ? ' dan perintah ter-encode' : ' dengan perintah ter-encode') : '',
      download ? [', mengunduh payload dari ', V(dest || 'server eksternal'), iex ? ' lalu langsung mengeksekusinya' : ''] : '', `. Teknik ini lazim dipakai untuk memperoleh pijakan awal sambil menekan jejak di disk (${ttpIds.filter((i) => ['T1059.001', 'T1564.003', 'T1027', 'T1105'].includes(i)).join(', ') || 'lihat tabel TTP'}). Tujuan yang paling mungkin adalah menanam tahap berikutnya (second-stage) pada host.`].flat(2);
    findings = [...connParts(), ...tiParts(), ...scopeParts()];
    checks = ['telemetri EDR pada host (proses anak, persistence, koneksi lain)', 'asal file atau proses pemicu', 'apakah user lain menerima file/email yang sama'];
    actions = [
      host ? `Isolasi ${host} dari jaringan setelah dikonfirmasi di EDR.` : 'Isolasi host terkait setelah dikonfirmasi di EDR.',
      mal.length ? `Blokir ${mal.slice(0, 3).map((r) => r.value).join(', ')} di firewall/proxy.` : (dest ? `Pertimbangkan blokir ${dest} setelah reputasinya dikonfirmasi.` : 'Tinjau tujuan koneksi keluar dan blokir bila terbukti berbahaya.'),
      user ? `Reset kredensial ${user} dan tinjau sesi yang aktif.` : 'Tinjau akun yang login pada host tersebut.',
      fileName ? `Amankan ${fileName} untuk analisa lanjut dan cari penerima lain dari berkas yang sama.` : 'Kumpulkan berkas dan hash pemicu untuk analisa lanjut.',
    ];
  } else if (scenario === 'bruteforce') {
    rootCause = ['Sumber ', V(srcIp || 'tidak diketahui'), ` melakukan ${fails.length} percobaan autentikasi gagal`, user ? [' terhadap akun ', V(user)] : '', host || dstIp ? [' pada ', V(host || dstIp)] : '', ` dalam jendela ±${winMin} menit.`].flat(2);
    activity = ['Pola ini konsisten dengan upaya password guessing/brute force terhadap layanan yang terekspos', successAfter ? '; terdapat login berhasil dari sumber yang sama setelah rangkaian kegagalan sehingga kredensial kemungkinan telah berhasil ditebak' : '', ` (${ttpIds.filter((i) => ['T1110', 'T1078'].includes(i)).join(', ')}).`];
    findings = [successAfter ? 'Ditemukan login berhasil setelah rangkaian kegagalan; sesi tersebut perlu diperlakukan sebagai berpotensi disalahgunakan. ' : 'Belum ditemukan login berhasil dari sumber yang sama setelah rangkaian kegagalan pada event yang tersedia. ', ...tiParts(), ...scopeParts()];
    checks = ['apakah ada login berhasil dari sumber yang sama pada layanan lain', 'apakah akun target valid dan aktif', 'apakah sumber juga muncul pada alert lain'];
    actions = [
      srcIp ? `Pertimbangkan blokir ${srcIp} dan batasi percobaan login (rate limit/lockout).` : 'Terapkan rate limit/lockout pada layanan terkait.',
      user ? (successAfter ? `Reset kredensial ${user} dan paksa MFA; tinjau sesi yang aktif.` : `Pastikan ${user} memakai MFA dan pantau percobaan berikutnya.`) : 'Pastikan MFA aktif pada layanan terkait.',
      'Batasi akses layanan hanya dari jaringan/IP yang dibutuhkan bila memungkinkan.',
    ];
  } else if (scenario === 'scan') {
    rootCause = ['Host ', V(srcIp || 'eksternal'), ` mengirim koneksi ke ${scanPorts.length} port tujuan berbeda`, dstIp ? [' pada ', V(dstIp)] : '', ' (', V(scanPorts.slice(0, 8).join(', ')), ') dalam waktu singkat.'].flat(2);
    activity = ['Pola ini konsisten dengan pemindaian layanan (network service discovery) untuk memetakan port terbuka sebelum eksploitasi atau brute force (', ...vals(ttpIds.filter((i) => i === 'T1046')), ').'];
    findings = [connAllowed.length ? `${connAllowed.length} koneksi dari sumber yang sama tercatat diizinkan; port tersebut perlu diverifikasi. ` : (connDenied.length ? `Seluruh ${connDenied.length} koneksi dari sumber yang sama tercatat diblokir firewall pada event yang tersedia. ` : 'Belum ada log yang mengonfirmasi hasil koneksi (diizinkan atau diblokir). '), ...tiParts(), ...scopeParts()];
    checks = ['apakah ada koneksi yang diizinkan ke port yang dipindai', 'apakah layanan pada port tersebut memang perlu terbuka ke internet', 'apakah sumber muncul pada alert lain'];
    actions = [
      srcIp ? `Pertimbangkan blokir ${srcIp} bila terus berulang.` : 'Pertimbangkan blokir sumber bila terus berulang.',
      'Pastikan layanan pada port yang dipindai memang perlu terbuka dan sudah ter-patch.',
      'Pantau apakah sumber yang sama berlanjut ke percobaan login atau eksploitasi.',
    ];
  } else if (scenario === 'account') {
    const others = [...new Set(events.filter((e) => AUTH_RE.test(String(e.action || '')) && e.user === ev.user.name && e.source_ip && e.source_ip !== srcIp).map((e) => e.source_ip))];
    rootCause = ['Akun ', V(user), ' tercatat berhasil melakukan autentikasi dari ', V(srcIp || 'sumber tidak diketahui'), n.source_country ? ` (${n.source_country})` : '', `, berbeda dari pola lokasi sebelumnya sesuai rule "${ev.rule.name || '-'}".`].flat(2);
    activity = ['Jika sign-in ini bukan dilakukan oleh pemilik akun, kondisi ini mengindikasikan penyalahgunaan akun valid oleh threat actor', ttpIds.includes('T1078') ? ' (T1078)' : '', '. Hal ini belum dapat dipastikan tanpa konfirmasi dari pemilik akun.'];
    findings = [others.length ? ['Akun yang sama juga tercatat login dari ', ...vals(others), ' pada jendela pemeriksaan. '] : 'Tidak ada sign-in lain dari akun yang sama pada event terkait. ', ...tiParts(), ...scopeParts()].flat(2);
    checks = ['konfirmasi aktivitas kepada pemilik akun', 'riwayat sign-in, perangkat, dan status MFA', 'aktivitas pasca-login (aturan inbox, akses file, pemberian izin aplikasi)'];
    actions = [
      `Konfirmasi sign-in kepada ${user || 'pemilik akun'} lewat kanal lain.`,
      'Jika tidak dikenali: cabut sesi aktif, reset kredensial, dan pastikan MFA aktif.',
      'Tinjau aktivitas pasca-login pada akun tersebut (mail rules, akses data, consent aplikasi).',
    ];
  } else {
    rootCause = [ev.rule.reason ? `${ev.rule.reason}.` : `Rule "${ev.rule.name || '-'}" terpicu${host ? ` pada host ${host}` : ''}.`];
    activity = [`Aktivitas sesuai deteksi rule "${ev.rule.name || '-'}"`, ttpIds.length ? ` yang dipetakan ke ${ttpIds.join(', ')}` : '', '. ', ev.rule.description ? ev.rule.description : 'Detail perilaku threat actor belum dapat disimpulkan dari data yang tersedia.'];
    findings = [...connParts(), ...tiParts(), ...scopeParts()];
    checks = ['konteks aktivitas pada host dan user terkait', 'apakah pola yang sama muncul pada alert lain'];
    actions = ['Tinjau evidence dan event terkait, lalu tetapkan tindak lanjut sesuai konteks bisnis.'];
  }

  const basis = [];
  if (isOfficeParent && isShell) basis.push('rantai eksekusi proses yang mencurigakan');
  if (cmdHits.length) basis.push('pola command line yang lazim dipakai untuk eksekusi skrip jarak jauh');
  if (mal.length) basis.push('keterlibatan infrastruktur berreputasi buruk');
  if (scan) basis.push('pola pemindaian port');
  if (bf) basis.push('pola brute force');
  if (successAfter) basis.push('login berhasil setelah rangkaian kegagalan');
  let conclusion;
  if (verdict === 'true_positive') {
    conclusion = [`Alert dinilai sebagai true positive dengan prioritas ${priority}. Penilaian didasarkan pada ${basis.length ? basis.join(', ') : 'kombinasi sinyal pada skor'}, serta selaras dengan teknik MITRE ATT&CK pada tabel TTP.`,
      ['phish_exec', 'script_exec'].includes(scenario) && host ? ` Host ${host} perlu diperlakukan sebagai berpotensi terkompromi sampai terbukti sebaliknya.` : '',
      scenario === 'bruteforce' && user ? ` Akun ${user} perlu diperlakukan sebagai berpotensi terkompromi.` : ''];
  } else if (verdict === 'needs_investigation') {
    conclusion = [`Indikator yang ada belum cukup untuk memastikan insiden, namun juga belum dapat menyingkirkannya, sehingga alert memerlukan investigasi lanjutan (prioritas ${priority}). Hal yang perlu diverifikasi: ${checks.join('; ')}.`];
  } else {
    conclusion = [`Sinyal pendukung minimal${allowHit.length ? ' dan aktivitas cocok dengan daftar aman' : ''}, sehingga alert dinilai kemungkinan false positive. Tetap dokumentasikan dasar penilaian dan pantau bila pola berulang.`];
  }

  const short = [
    `Alert "${ev.rule.name || '-'}" (${sev || '-'}, risk ${ev.rule.risk_score ?? '-'}) pada ${ev.timestamp}.`,
    srcIp || dstIp ? `Lalu lintas ${srcIp || '?'}${n.source_port ? `:${n.source_port}` : ''} → ${dstIp || '?'}${dstPort ? `:${dstPort}` : ''}${n.protocol ? ` (${n.protocol})` : ''}.` : '',
    host ? `Host: ${host}${user ? `, user: ${user}` : ''}.` : '',
    `Event terkait: ${related.total || 0}. IOC publik diperiksa: ${iocResults.length} (malicious ${mal.length}, suspicious ${sus.length}, clean ${clean.length}, belum diketahui ${unknown}).`,
  ].filter(Boolean).join(' ');

  return {
    schema: SCHEMA, score, level, label, verdict, suggested_verdict: verdict, priority, confidence, scenario,
    reasons, notes, ttps,
    narrative: {
      root_cause: rootCause.flat(2), activity: activity.flat(2), findings: findings.flat(2), conclusion: conclusion.flat(2), actions,
    },
    recommendations: actions, summary: short, rules_version: R.version, window_minutes: winMin,
  };
}

module.exports = { analyze, loadRules, inList, isPrivateIp, SCHEMA };
