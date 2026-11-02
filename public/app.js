'use strict';
/*
 * Frontend tanpa framework. Semua data dari log dianggap tidak tepercaya:
 * konten selalu dimasukkan lewat textContent (helper h()), tidak pernah innerHTML.
 */

// ---------- helpers ----------
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $ = (id) => document.getElementById(id);
const dash = (v) => (v === undefined || v === null || v === '' ? '-' : v);
const fmtTime = (t) => (t ? new Date(t).toLocaleString('id-ID', { hour12: false }) : '-');
const chip = (text, cls = 'mute') => h('span', { class: `chip ${cls}`, text });
const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : '');

let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

function token() { try { return sessionStorage.getItem('apiToken') || ''; } catch (_) { return ''; } }
async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.body) headers['Content-Type'] = 'application/json';
  if (token()) headers['x-api-token'] = token();
  const res = await fetch(path, { ...opts, headers });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.json()).error || msg; } catch (_) { /* abaikan */ }
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return opts.raw ? res : res.json();
}
const post = (path, body) => api(path, { method: 'POST', body: JSON.stringify(body || {}) });

// ---------- kamus istilah ----------
const SEV = { critical: 'crit', high: 'high', medium: 'med', low: 'low' };
const VERDICT = { true_positive: 'True positive', false_positive: 'False positive', needs_investigation: 'Perlu investigasi', benign: 'Benign', unreviewed: 'Belum ditinjau' };
const VERDICT_CLS = { true_positive: 'crit', needs_investigation: 'high', false_positive: 'low', benign: 'low', unreviewed: 'mute' };
const CONF = { indicated: 'Terindikasi', strong: 'Kuat', confirmed: 'Terkonfirmasi' };
const CONF_CLS = { indicated: 'info', strong: 'high', confirmed: 'crit' };
const SRC = { rule: 'Rule', evidence: 'Evidence', 'rule+evidence': 'Rule + evidence' };
const IOC_CLS = { malicious: 'crit', suspicious: 'med', clean: 'low' };
const IOC_LABEL = { malicious: 'Malicious', suspicious: 'Suspicious', clean: 'Clean', unknown: 'Tidak diketahui', private: 'Internal', invalid: 'Tidak valid' };
const TACTIC_ORDER = ['TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011', 'TA0010', 'TA0040'];
const NARR = [
  ['root_cause', 'Root cause'],
  ['activity', 'Aktivitas threat actor'],
  ['findings', 'Hasil pemeriksaan'],
  ['conclusion', 'Kesimpulan triage'],
];
const PRESETS = [[60, '1 jam'], [360, '6 jam'], [1440, '24 jam'], [10080, '7 hari'], [43200, '30 hari'], [129600, '90 hari'], [525600, '1 tahun'], [0, 'Kustom']];
const WINDOWS = [[15, '±15 menit'], [60, '±1 jam'], [360, '±6 jam'], [1440, '±24 jam'], [10080, '±7 hari'], [43200, '±30 hari']];

// ---------- state ----------
const state = { alerts: [], total: 0, selected: null, preset: 1440, win: 15, loading: false, seq: 0, pollTimer: null };

function getRange() {
  if (state.preset > 0) {
    const to = new Date();
    return { from: new Date(to.getTime() - state.preset * 60000), to };
  }
  const f = new Date($('from').value);
  const t = new Date($('to').value);
  if (Number.isNaN(f.getTime()) || Number.isNaN(t.getTime()) || f >= t) return null;
  return { from: f, to: t };
}

// ---------- status bar ----------
async function loadHealth() {
  const box = $('status');
  let d;
  try { d = await api('/api/health'); } catch (e) { box.replaceChildren(chip('Server tidak terjangkau', 'crit')); return null; }
  const pills = [];
  if (d.demo) pills.push(chip('Mode demo', 'med'));
  pills.push(d.elastic_ok ? chip('Elasticsearch terhubung', 'low') : chip('Elasticsearch tidak terhubung', 'crit'));
  pills.push(chip(`VirusTotal ${d.ti.virustotal ? 'aktif' : 'nonaktif'}`, d.ti.virustotal ? 'info' : 'mute'));
  pills.push(chip(`AbuseIPDB ${d.ti.abuseipdb ? 'aktif' : 'nonaktif'}`, d.ti.abuseipdb ? 'info' : 'mute'));
  const a = d.auto || {};
  if (a.enabled) pills.push(chip(`Auto-triage aktif · verdict ${a.apply_verdict === 'all' ? 'otomatis' : a.apply_verdict === 'tp_only' ? 'hanya TP' : 'manual'} · ${a.analyzed_total || 0} dianalisa`, 'info'));
  else pills.push(chip('Auto-triage nonaktif (AUTO_ENRICH=false)', 'mute'));
  box.replaceChildren(...pills);
  $('btn-token').hidden = !d.auth_required;
  return d;
}

// ---------- daftar alert ----------
function alertItem(a) {
  const li = h('li', { class: `sev-${a.severity}`, tabindex: '0', role: 'option', 'aria-selected': state.selected === a.id ? 'true' : 'false', 'data-id': a.id });
  const verdict = a.triage && a.triage !== 'unreviewed' ? a.triage : null;
  const top = h('div', { class: 'a-top' },
    chip(cap(a.severity || '-'), SEV[a.severity] || 'mute'),
    verdict ? chip(`${VERDICT[verdict]}${a.auto ? ` · ${a.auto.score}` : ''}`, VERDICT_CLS[verdict]) : chip('Belum dianalisa', 'mute'),
    a.auto && a.auto.priority ? chip(a.auto.priority, 'info') : null);
  li.append(top, h('div', { class: 'a-rule', text: dash(a.rule) }),
    h('div', { class: 'a-meta' },
      h('span', { text: `${dash(a.source_ip)}${a.source_port ? `:${a.source_port}` : ''} → ${dash(a.destination_ip)}${a.destination_port ? `:${a.destination_port}` : ''}` }),
      a.host ? h('span', { text: a.host }) : null,
      a.user ? h('span', { text: a.user }) : null,
      h('span', { text: fmtTime(a.timestamp) })));
  const open = () => selectAlert(a.id);
  li.addEventListener('click', open);
  li.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
  return li;
}

function renderList() {
  const ul = $('alerts');
  ul.setAttribute('role', 'listbox');
  ul.replaceChildren(...state.alerts.map(alertItem));
  $('count').textContent = state.total ? `Menampilkan ${state.alerts.length} dari ${state.total} alert` : 'Tidak ada alert pada rentang ini';
  $('more').hidden = state.alerts.length >= state.total;
}

async function loadAlerts(append = false) {
  const range = getRange();
  if (!range) { toast('Rentang waktu kustom tidak valid'); return; }
  const seq = ++state.seq;
  const q = new URLSearchParams({ from: range.from.toISOString(), to: range.to.toISOString(), size: '100', offset: append ? String(state.alerts.length) : '0' });
  if ($('f-sev').value) q.set('severity', $('f-sev').value);
  if ($('f-status').value) q.set('status', $('f-status').value);
  if ($('f-q').value.trim()) q.set('q', $('f-q').value.trim());
  $('count').textContent = 'Memuat…';
  try {
    const d = await api(`/api/alerts?${q}`);
    if (seq !== state.seq) return;
    state.alerts = append ? state.alerts.concat(d.alerts) : d.alerts;
    state.total = d.total;
    renderList();
  } catch (e) {
    if (seq !== state.seq) return;
    $('count').textContent = `Gagal memuat alert: ${e.message}`;
  }
}

function buildPresets() {
  const box = $('presets');
  box.replaceChildren(...PRESETS.map(([m, label]) => h('button', {
    type: 'button', 'aria-pressed': String(state.preset === m), text: label,
    onclick: () => {
      state.preset = m;
      $('custom').hidden = m !== 0;
      if (m === 0 && !$('from').value) {
        const now = new Date();
        const loc = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
        $('to').value = loc(now);
        $('from').value = loc(new Date(now.getTime() - 7 * 86400000));
      }
      buildPresets();
      if (m !== 0) loadAlerts();
    },
  })));
}

// ---------- detail ----------
const kvBox = (title, rows) => {
  const ok = rows.filter(([, v]) => v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length));
  if (!ok.length) return null;
  return h('div', { class: 'kvbox' }, h('h3', { text: title }), h('dl', null, ok.flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { text: Array.isArray(v) ? v.join(', ') : String(v) })])));
};

function narrP(parts) {
  const p = h('p');
  for (const x of parts || []) p.append(typeof x === 'string' ? document.createTextNode(x) : h('code', { text: String(x.v) }));
  return p;
}

function killChain(ttps) {
  const seen = new Map();
  for (const t of ttps) if (t.tactic_id && !seen.has(t.tactic_id)) seen.set(t.tactic_id, t.tactic || t.tactic_id);
  if (!seen.size) return null;
  const ids = [...seen.keys()].sort((a, b) => TACTIC_ORDER.indexOf(a) - TACTIC_ORDER.indexOf(b));
  const out = [];
  ids.forEach((id, i) => { if (i) out.push(h('span', { class: 'arrow', text: '→' })); out.push(h('span', { class: 'step', text: `${seen.get(id)} (${id})` })); });
  return h('div', { class: 'chain', 'aria-label': 'Urutan taktik ATT&CK' }, out);
}

function verdictBanner(d, an) {
  const t = d.triage;
  const verdict = t.verdict && t.verdict !== 'unreviewed' ? t.verdict : an.verdict;
  const bySrc = t.verdict_source === 'analyst' ? 'Ditetapkan analis' : t.verdict_source === 'auto' ? 'Otomatis' : 'Rekomendasi sistem';
  const box = h('section', { class: `panel verdict v-${verdict}` });
  box.append(
    h('div', null, h('div', { class: 'big', text: verdict === an.verdict ? `${VERDICT[verdict] || verdict} · ${an.priority}` : (VERDICT[verdict] || verdict) }),
      h('div', { class: 'small muted', text: verdict === an.verdict ? bySrc : `${bySrc} · rekomendasi sistem: ${VERDICT[an.verdict] || an.verdict} (${an.priority})` })),
    h('div', { class: 'kv' }, 'Keyakinan', h('b', { text: cap(an.confidence) })),
    h('div', { class: 'kv' }, 'Skor risiko', h('b', { text: `${an.score}/100` })),
    h('div', { class: 'kv' }, 'Status', h('b', { text: dash(d.evidence.rule.status) })));

  const sel = h('select', { 'aria-label': 'Verdict' }, ['true_positive', 'needs_investigation', 'false_positive', 'benign', 'unreviewed'].map((v) => h('option', { value: v, text: VERDICT[v], selected: v === verdict })));
  const st = h('select', { 'aria-label': 'Status workflow' }, h('option', { value: '', text: 'Status tidak diubah' }), ['open', 'acknowledged', 'in-progress', 'closed'].map((v) => h('option', { value: v, text: v })));
  const note = h('input', { type: 'text', placeholder: 'Catatan analis (opsional)', maxlength: '500', 'aria-label': 'Catatan' });
  const form = h('div', { class: 'override', hidden: true }, sel, note, h('button', {
    class: 'btn small', type: 'button', text: 'Simpan',
    onclick: async () => {
      try {
        let analyst = '';
        try { analyst = localStorage.getItem('analyst') || ''; if (!analyst) { analyst = window.prompt('Nama analis (untuk jejak audit):') || ''; localStorage.setItem('analyst', analyst); } } catch (_) { /* abaikan */ }
        await api(`/api/alerts/${encodeURIComponent(d.id)}/triage`, { method: 'PUT', body: JSON.stringify({ verdict: sel.value, note: note.value || undefined, status: st.value || undefined, analyst: analyst || undefined }) });
        toast('Verdict disimpan');
        await Promise.all([openAlert(d.id), loadAlerts()]);
      } catch (e) { toast(`Gagal: ${e.message}`); }
    },
  }), h('div', { class: 'full' }, st));

  const acts = h('div', { class: 'acts' },
    h('button', { class: 'btn ghost small', type: 'button', text: 'Ubah verdict', onclick: () => { form.hidden = !form.hidden; } }),
    h('button', { class: 'btn ghost small', type: 'button', text: 'Analisa ulang', onclick: async (e) => {
      e.target.disabled = true;
      try { await post(`/api/alerts/${encodeURIComponent(d.id)}/analysis`, { window_minutes: state.win }); toast('Analisa diperbarui'); await Promise.all([openAlert(d.id), loadAlerts()]); } catch (er) { toast(`Gagal: ${er.message}`); e.target.disabled = false; }
    } }),
    h('button', { class: 'btn small', type: 'button', text: 'Unduh PDF', onclick: (e) => exportReport(d.id, 'pdf', e.target) }));
  box.append(acts, form);
  return box;
}

async function exportReport(id, fmt, btn) {
  if (btn) { btn.disabled = true; btn.textContent = 'Membuat PDF…'; }
  try {
    const res = await api(`/api/alerts/${encodeURIComponent(id)}/report?format=${fmt}`, { raw: true });
    const blob = await res.blob();
    const a = h('a', { href: URL.createObjectURL(blob), download: `laporan-triage-${id.replace(/[^\w-]/g, '')}.${fmt}` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  } catch (e) { toast(`Report gagal dibuat: ${e.message}`); }
  if (btn) { btn.disabled = false; btn.textContent = 'Report PDF'; }
}

function iocTable(d, an) {
  const roles = new Map(d.evidence.iocs.map((i) => [i.value.toLowerCase(), i]));
  const rows = [...(an.ioc_results || [])];
  for (const i of d.evidence.iocs) if (i.private && !rows.some((r) => r.value === i.value)) rows.push({ value: i.value, type: i.type, verdict: 'private', score: null, sources: [], links: [] });
  if (!rows.length) return h('p', { class: 'muted', text: 'Tidak ada IOC pada alert ini.' });
  const body = rows.map((r) => {
    const meta = roles.get(String(r.value).toLowerCase());
    const cls = IOC_CLS[r.verdict] || 'mute';
    const srcs = (r.sources || []).map((s) => (s.error ? `${s.name} (${s.error})` : s.found === false ? `${s.name}: tidak ditemukan` : s.name));
    return h('tr', null,
      h('td', null, h('code', { text: r.value }), meta ? h('div', { class: 'small muted', text: meta.role }) : null),
      h('td', { text: String(r.type || '-').toUpperCase() }),
      h('td', null, r.score === null || r.score === undefined ? h('span', { class: 'muted', text: '-' }) : h('div', { class: 'score' }, h('div', { class: 'bar', 'aria-hidden': 'true' }, scoreFill(cls, r.score)), h('b', { text: String(r.score) }))),
      h('td', null, chip(IOC_LABEL[r.verdict] || r.verdict, cls)),
      h('td', null, h('div', { class: 'small', text: srcs.join(' · ') || (r.note || '-') }),
        h('div', { class: 'links' }, (r.links || []).filter((l) => /^https:\/\//.test(l.url)).map((l) => h('a', { href: l.url, target: '_blank', rel: 'noopener noreferrer', text: l.name })))));
  });
  return h('div', { class: 'tw' }, h('table', null, h('thead', null, h('tr', null, ['IOC', 'Tipe', 'Skor validasi', 'Verdict', 'Sumber'].map((x) => h('th', { text: x })))), h('tbody', null, body)));
}

function scoreFill(cls, score) {
  const i = h('i', { class: cls === 'mute' ? '' : cls });
  i.style.width = `${Math.max(0, Math.min(100, score))}%`;
  return i;
}

function ttpTable(an) {
  if (!an.ttps.length) return h('p', { class: 'muted', text: 'Belum ada pemetaan TTP. Rule tidak menyertakan MITRE ATT&CK dan evidence belum cukup untuk menyimpulkan teknik.' });
  const rows = an.ttps.map((t) => h('tr', null,
    h('td', null, h('div', { text: dash(t.tactic) }), h('div', { class: 'small muted', text: dash(t.tactic_id) })),
    h('td', null, h('div', { text: dash(t.technique) }), h('div', { class: 'small muted', text: dash(t.technique_id) })),
    h('td', { text: dash(t.procedure) }),
    h('td', null, chip(CONF[t.confidence] || t.confidence, CONF_CLS[t.confidence] || 'mute'), h('div', { class: 'small muted', text: SRC[t.source] || t.source }))));
  return h('div', { class: 'tw' }, h('table', null, h('thead', null, h('tr', null, ['Tactic', 'Technique', 'Procedure', 'Keyakinan'].map((x) => h('th', { text: x })))), h('tbody', null, rows)));
}

function evidenceSection(e) {
  const n = e.network;
  return h('div', { class: 'kvgrid' },
    kvBox('Jaringan', [['Sumber', n.source_ip ? `${n.source_ip}${n.source_port ? `:${n.source_port}` : ''}` : ''], ['Tujuan', n.destination_ip ? `${n.destination_ip}${n.destination_port ? `:${n.destination_port}` : ''}` : ''], ['Protokol', n.protocol], ['Arah', n.direction], ['Aksi', n.action], ['Byte', n.bytes], ['Negara sumber', n.source_country]]),
    kvBox('Host', [['Nama', e.host.name], ['OS', e.host.os], ['IP', e.host.ip], ['MAC', e.host.mac]]),
    kvBox('Pengguna', [['Nama', e.user.name], ['Domain', e.user.domain], ['Email', e.user.email]]),
    kvBox('Proses', [['Nama', e.process.name], ['PID', e.process.pid], ['Command line', e.process.command_line], ['Executable', e.process.executable], ['Parent', e.process.parent_name], ['Parent cmd', e.process.parent_command_line]]),
    kvBox('File', [['Nama', e.file.name], ['Path', e.file.path], ['SHA-256', e.file.sha256]]),
    kvBox('Rule', [['Nama', e.rule.name], ['Severity', e.rule.severity], ['Risk score', e.rule.risk_score], ['Alasan', e.rule.reason], ['Tag', e.rule.tags], ['Dataset', e.meta.event_dataset]]));
}

function relatedSection(id) {
  const out = h('div');
  const win = h('select', { 'aria-label': 'Jendela waktu event terkait', onchange: () => { state.win = Number(win.value); } }, WINDOWS.map(([m, l]) => h('option', { value: m, text: l, selected: m === state.win })));
  const btn = h('button', { class: 'btn small', type: 'button', text: 'Muat event terkait', onclick: async () => {
    btn.disabled = true;
    out.replaceChildren(h('p', { class: 'muted', text: 'Memuat…' }));
    try {
      const d = await post(`/api/alerts/${encodeURIComponent(id)}/related`, { window_minutes: state.win });
      const rows = (d.events || []).map((ev) => h('tr', null,
        h('td', { text: fmtTime(ev.timestamp) }), h('td', { text: dash(ev.dataset) }), h('td', { text: dash(ev.action || ev.outcome) }),
        h('td', { text: `${dash(ev.source_ip)}${ev.source_port ? `:${ev.source_port}` : ''} → ${dash(ev.destination_ip)}${ev.destination_port ? `:${ev.destination_port}` : ''}` }),
        h('td', { text: dash(ev.host) }), h('td', { text: dash(ev.message) })));
      out.replaceChildren(h('p', { class: 'small muted', text: `${d.total} event pada jendela ${fmtTime(d.window.from)} – ${fmtTime(d.window.to)}` }),
        rows.length ? h('div', { class: 'tw' }, h('table', null, h('thead', null, h('tr', null, ['Waktu', 'Dataset', 'Aksi', 'Koneksi', 'Host', 'Pesan'].map((x) => h('th', { text: x })))), h('tbody', null, rows))) : null);
    } catch (e) { out.replaceChildren(h('p', { class: 'warn', text: `Gagal memuat: ${e.message}` })); }
    btn.disabled = false;
  } });
  return h('details', { class: 'panel' }, h('summary', { text: 'Event terkait (pivot IP, host, user)' }), h('div', { class: 'row' }, win, btn), out);
}

function renderDetail(d, an) {
  const e = d.evidence;
  const root = $('detail');
  const nodes = [];
  nodes.push(h('section', { class: 'title' },
    h('h1', { text: dash(e.rule.name) }),
    h('div', { class: 'sub' }, chip(cap(e.rule.severity || '-'), SEV[e.rule.severity] || 'mute'), h('span', { text: fmtTime(e.timestamp) }), h('span', { text: `Host: ${dash(e.host.name)}` }), h('span', { text: `User: ${dash(e.user.name)}` }), h('code', { text: d.id }))));
  if (!an) {
    nodes.push(h('div', { class: 'warn', text: 'Analisa otomatis belum tersedia untuk alert ini.' }));
  } else {
    nodes.push(verdictBanner(d, an));
    const chain = killChain(an.ttps);
    if (chain) nodes.push(h('section', { class: 'panel' }, h('h2', { text: 'Urutan taktik (kill chain)' }), chain));
    const narr = h('section', { class: 'panel narr' }, h('h2', { text: 'Analisa' }));
    for (const [k, title] of NARR) if (an.narrative[k] && an.narrative[k].length) narr.append(h('h3', { text: title }), narrP(an.narrative[k]));
    if (an.narrative.actions && an.narrative.actions.length) narr.append(h('h3', { text: 'Tindakan yang disarankan' }), h('ul', null, an.narrative.actions.map((x) => h('li', { text: x }))));
    nodes.push(narr);
    (an.notes || []).forEach((n) => nodes.push(h('div', { class: 'warn', text: n })));
    nodes.push(h('section', { class: 'panel' }, h('h2', { text: 'Validasi IOC' }), iocTable(d, an)));
    nodes.push(h('section', { class: 'panel' }, h('h2', { text: 'TTP · MITRE ATT&CK' }), ttpTable(an)));
    if (an.reasons && an.reasons.length) {
      nodes.push(h('details', { class: 'panel' }, h('summary', { text: `Rincian skor (${an.score}/100)` }),
        h('div', { class: 'tw' }, h('table', null, h('tbody', null, an.reasons.map((r) => h('tr', null, h('td', { text: `${r.points > 0 ? '+' : ''}${r.points}` }), h('td', { text: r.text }))))))));
    }
  }
  nodes.push(h('section', { class: 'panel' }, h('h2', { text: 'Evidence' }), evidenceSection(e)));
  nodes.push(relatedSection(d.id));
  nodes.push(h('details', { class: 'panel' }, h('summary', { text: 'Data mentah (JSON)' }), h('pre', { class: 'raw', text: JSON.stringify(d.raw, null, 2) })));
  root.replaceChildren(...nodes);
}

let openSeq = 0;
async function openAlert(id) {
  const seq = ++openSeq;
  const root = $('detail');
  root.replaceChildren(h('div', { class: 'empty', text: 'Memuat alert…' }));
  try {
    const d = await api(`/api/alerts/${encodeURIComponent(id)}`);
    let an = null;
    try { an = (await api(`/api/alerts/${encodeURIComponent(id)}/analysis`)).analysis; } catch (_) { /* abaikan */ }
    if (!an || an.schema !== 2) {
      root.replaceChildren(h('div', { class: 'empty', text: 'Menganalisa alert (evidence, validasi IOC, TTP)…' }));
      try { an = (await post(`/api/alerts/${encodeURIComponent(id)}/analysis`, { window_minutes: state.win })).analysis; } catch (e) { an = null; toast(`Analisa gagal: ${e.message}`); }
      if (an) d.triage = (await api(`/api/alerts/${encodeURIComponent(id)}`)).triage;
    }
    if (seq !== openSeq) return;
    renderDetail(d, an);
    if (an) loadAlerts();
  } catch (e) {
    if (seq !== openSeq) return;
    root.replaceChildren(h('div', { class: 'warn', text: `Gagal memuat alert: ${e.message}` }));
  }
}

function selectAlert(id) {
  state.selected = id;
  document.querySelectorAll('#alerts li').forEach((li) => li.setAttribute('aria-selected', String(li.dataset.id === id)));
  openAlert(id);
}

// ---------- analisa massal (backfill) ----------
function renderBackfill(bf) {
  const s = $('bf-status');
  const bar = $('bf-bar');
  if (!bf) { s.textContent = ''; bar.hidden = true; $('bf-cancel').hidden = true; $('bf-run').disabled = false; return; }
  const pct = bf.total ? Math.round(((bf.done + bf.failed + bf.skipped) / bf.total) * 100) : bf.running ? 3 : 100;
  bar.hidden = false;
  bar.firstElementChild.style.width = `${pct}%`;
  $('bf-cancel').hidden = !bf.running;
  $('bf-run').disabled = bf.running;
  const extra = [bf.failed ? `${bf.failed} gagal` : '', bf.truncated ? 'dibatasi AUTO_BACKFILL_MAX' : ''].filter(Boolean).join(', ');
  s.textContent = bf.running ? `${cap(bf.phase)}: ${bf.done}/${bf.total}${extra ? ` (${extra})` : ''}` : `${cap(bf.phase)}: ${bf.done} dianalisa dari ${bf.total}${extra ? ` (${extra})` : ''}${bf.error ? ` · ${bf.error}` : ''}`;
}

async function pollBackfill() {
  clearTimeout(state.pollTimer);
  try {
    const st = await api('/api/auto/status');
    renderBackfill(st.backfill);
    if (st.backfill && st.backfill.running) { state.pollTimer = setTimeout(pollBackfill, 2000); return; }
    if (st.backfill) { await Promise.all([loadAlerts(), loadHealth()]); }
  } catch (_) { /* abaikan */ }
}

async function runBackfill() {
  const r = getRange();
  if (!r) { toast('Rentang waktu kustom tidak valid'); return; }
  const sev = $('f-sev').value;
  try {
    const d = await post('/api/auto/backfill', { from: r.from.toISOString(), to: r.to.toISOString(), severities: sev ? [sev] : ['all'], force: $('bf-force').checked });
    renderBackfill(d.backfill);
    pollBackfill();
  } catch (e) { toast(e.message); }
}

// ---------- init ----------
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

async function init() {
  buildPresets();
  $('apply-range').addEventListener('click', () => loadAlerts());
  ['f-sev', 'f-status'].forEach((id) => $(id).addEventListener('change', () => loadAlerts()));
  $('f-q').addEventListener('input', debounce(() => loadAlerts(), 350));
  $('more').addEventListener('click', () => loadAlerts(true));
  $('bf-run').addEventListener('click', runBackfill);
  $('bf-cancel').addEventListener('click', async () => { try { await post('/api/auto/backfill/cancel'); pollBackfill(); } catch (e) { toast(e.message); } });
  $('btn-token').addEventListener('click', () => {
    const t = window.prompt('Token akses (APP_TOKEN):');
    if (t !== null) { try { sessionStorage.setItem('apiToken', t.trim()); } catch (_) { /* abaikan */ } init2(); }
  });
  const hd = await loadHealth();
  if (hd && hd.auth_required && !token()) {
    const t = window.prompt('Aplikasi ini dilindungi token. Masukkan APP_TOKEN:');
    if (t) { try { sessionStorage.setItem('apiToken', t.trim()); } catch (_) { /* abaikan */ } }
  }
  init2();
}
function init2() { loadHealth(); loadAlerts(); pollBackfill(); }
init();
