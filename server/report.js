'use strict';
/** Pembuat laporan evidence (Markdown / HTML mandiri / JSON). Semua nilai dari log di-escape. */

const esc = (s) =>
  String(s === undefined || s === null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// '<' dan '>' di-escape agar HTML dari log tidak ikut ter-render oleh viewer Markdown
const mdEsc = (s) =>
  String(s === undefined || s === null ? '-' : s)
    .replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const dash = (v) => (v === undefined || v === null || v === '' ? '-' : v);

const CONF_LABEL = { confirmed: 'Terkonfirmasi', strong: 'Kuat', indicated: 'Terindikasi' };
const VERDICT_LABEL = { true_positive: 'True positive', needs_investigation: 'Perlu investigasi', false_positive: 'False positive', benign: 'Benign', unreviewed: 'Belum direview' };
// Narasi = array string / { v }; di laporan semuanya menjadi teks biasa
const partsText = (parts) => (parts || []).map((p) => (typeof p === 'string' ? p : p.v)).join('');
const NARR = [['root_cause', 'Root cause'], ['activity', 'Aktivitas threat actor'], ['findings', 'Hasil pemeriksaan'], ['conclusion', 'Kesimpulan triage']];

function analysisMd(a, mdEsc) {
  if (!a) return [];
  const L = ['## Hasil Auto Triage', '', `- Verdict: **${VERDICT_LABEL[a.verdict] || a.verdict}** · prioritas ${a.priority} · keyakinan ${a.confidence} · skor ${a.score}/100`, ''];
  L.push('## Analisa', '');
  NARR.forEach(([k, t]) => L.push(`**${t}.** ${mdEsc(partsText(a.narrative[k]))}`, ''));
  if (a.narrative.actions.length) { L.push('**Rekomendasi tindakan**'); a.narrative.actions.forEach((x) => L.push(`- ${mdEsc(x)}`)); L.push(''); }
  if (a.ttps.length) {
    L.push('## TTP (MITRE ATT&CK)', '', '| Tactic | Technique | Procedure | Keyakinan |', '|---|---|---|---|');
    a.ttps.forEach((t) => L.push(`| ${mdEsc(`${t.tactic} ${t.tactic_id}`.trim())} | ${mdEsc(`${t.technique} (${t.technique_id})`)} | ${mdEsc(t.procedure)} | ${CONF_LABEL[t.confidence] || t.confidence} |`));
    L.push('');
  }
  return L;
}

function analysisHtml(a) {
  if (!a) return '';
  const paras = NARR.map(([k, t]) => `<p><b>${esc(t)}.</b> ${esc(partsText(a.narrative[k]))}</p>`).join('');
  const acts = a.narrative.actions.map((x) => `<li>${esc(x)}</li>`).join('');
  const rows = a.ttps.map((t) => `<tr><td>${esc(`${t.tactic} ${t.tactic_id}`.trim())}</td><td>${esc(t.technique)} (${esc(t.technique_id)})</td><td>${esc(t.procedure)}</td><td>${esc(CONF_LABEL[t.confidence] || t.confidence)}</td></tr>`).join('');
  return `<h2>Hasil Auto Triage</h2><p><b>${esc(VERDICT_LABEL[a.verdict] || a.verdict)}</b> &middot; prioritas ${esc(a.priority)} &middot; keyakinan ${esc(a.confidence)} &middot; skor ${esc(a.score)}/100</p>
<h2>Analisa</h2>${paras}${acts ? `<p><b>Rekomendasi tindakan</b></p><ul>${acts}</ul>` : ''}
${rows ? `<h2>TTP (MITRE ATT&amp;CK)</h2><table><tr><th>Tactic</th><th>Technique</th><th>Procedure</th><th>Keyakinan</th></tr>${rows}</table>` : ''}`;
}

function kvRows(ev) {
  const n = ev.network;
  return [
    ['Waktu alert', ev.timestamp],
    ['Rule', ev.rule.name],
    ['Severity / Risk', `${dash(ev.rule.severity)} / ${dash(ev.rule.risk_score)}`],
    ['Status Elastic', ev.rule.status],
    ['Source IP : Port', `${dash(n.source_ip)} : ${dash(n.source_port)}`],
    ['Destination IP : Port', `${dash(n.destination_ip)} : ${dash(n.destination_port)}`],
    ['Protocol / Direction', `${dash(n.protocol)} / ${dash(n.direction)}`],
    ['Action / Outcome', n.action],
    ['Host', ev.host.name],
    ['User', ev.user.name],
    ['Process', ev.process.name],
    ['Command line', ev.process.command_line],
    ['Parent process', ev.process.parent_name],
    ['File', ev.file.path || ev.file.name],
    ['SHA256', ev.file.sha256],
    ['Dataset', ev.meta.event_dataset],
    ['MITRE', [...ev.rule.mitre_tactic, ...ev.rule.mitre_technique].join(', ')],
    ['Alasan alert', ev.rule.reason],
  ].filter(([, v]) => v !== undefined && v !== '' && v !== null && v !== ' / ' && !/^-( : -| \/ -)?$/.test(String(v)));
}

function toMarkdown(d) {
  const { id, evidence: ev, triage, related, iocs, generated_at, window_minutes } = d;
  const L = [];
  L.push(`# Evidence Report - ${mdEsc(ev.rule.name)}`);
  L.push('');
  L.push(`- Alert ID: \`${id}\``);
  L.push(`- Dibuat: ${generated_at}`);
  L.push(`- Verdict analis: **${triage.verdict}**`);
  L.push('');
  L.push('## Ringkasan Evidence');
  L.push('| Field | Nilai |', '|---|---|');
  kvRows(ev).forEach(([k, v]) => L.push(`| ${k} | ${mdEsc(v)} |`));
  L.push('');
  analysisMd(d.analysis, mdEsc).forEach((x) => L.push(x));
  L.push('## Validasi IOC');
  if (!iocs.length) L.push('_Tidak ada IOC._');
  else {
    L.push('| IOC | Tipe | Verdict | Skor | Sumber |', '|---|---|---|---|---|');
    iocs.forEach((i) => L.push(`| ${mdEsc(i.value)} | ${i.type} | ${i.verdict} | ${i.score} | ${mdEsc((i.sources || []).map((s) => s.name).join(', ') || i.note || '-')} |`));
  }
  L.push('');
  L.push(`## Event Terkait (jendela ±${window_minutes} menit, total ${related.total})`);
  if (!related.events.length) L.push('_Tidak ada event terkait._');
  else {
    L.push('| Waktu | Dataset | Aksi | Src | Dst | Host | User | Pesan |', '|---|---|---|---|---|---|---|---|');
    related.events.slice(0, 100).forEach((e) =>
      L.push(`| ${mdEsc(e.timestamp)} | ${mdEsc(e.dataset)} | ${mdEsc(e.action)} | ${mdEsc(e.source_ip)}:${mdEsc(e.source_port)} | ${mdEsc(e.destination_ip)}:${mdEsc(e.destination_port)} | ${mdEsc(e.host)} | ${mdEsc(e.user)} | ${mdEsc(String(e.message || '').slice(0, 160))} |`));
  }
  L.push('');
  L.push('## Catatan Analis');
  if (!triage.notes.length) L.push('_Belum ada catatan._');
  triage.notes.forEach((n) => L.push(`- ${n.at} (${mdEsc(n.by)}): ${mdEsc(n.text)}`));
  L.push('');
  return L.join('\n');
}

function toHtml(d) {
  const { id, evidence: ev, triage, related, iocs, generated_at, window_minutes } = d;
  const rows = kvRows(ev).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('');
  const iocRows = iocs.map((i) => `<tr><td>${esc(i.value)}</td><td>${esc(i.type)}</td><td class="v-${esc(i.verdict)}">${esc(i.verdict)}</td><td>${esc(i.score)}</td><td>${esc((i.sources || []).map((s) => s.name).join(', ') || i.note || '-')}</td></tr>`).join('');
  const evRows = related.events.slice(0, 100).map((e) => `<tr><td>${esc(e.timestamp)}</td><td>${esc(e.dataset)}</td><td>${esc(e.action)}</td><td>${esc(dash(e.source_ip))}:${esc(dash(e.source_port))}</td><td>${esc(dash(e.destination_ip))}:${esc(dash(e.destination_port))}</td><td>${esc(e.host)}</td><td>${esc(e.user)}</td><td>${esc(String(e.message || '').slice(0, 200))}</td></tr>`).join('');
  const notes = triage.notes.map((n) => `<li><b>${esc(n.at)}</b> (${esc(n.by)}): ${esc(n.text)}</li>`).join('');
  return `<!doctype html><html lang="id"><head><meta charset="utf-8"><title>Evidence ${esc(id)}</title>
<style>body{font:14px/1.5 system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1a1a1a}
h1{font-size:22px}h2{font-size:16px;border-bottom:1px solid #ddd;padding-bottom:4px;margin-top:28px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #ddd;padding:5px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#f4f4f4;width:200px}.v-malicious{color:#b00020;font-weight:700}.v-suspicious{color:#b26a00;font-weight:700}.v-clean{color:#1b7a3a}
.meta{color:#555}</style></head><body>
<h1>Evidence Report &mdash; ${esc(ev.rule.name)}</h1>
<p class="meta">Alert ID: <code>${esc(id)}</code> &middot; Dibuat: ${esc(generated_at)} &middot; Verdict: <b>${esc(triage.verdict)}</b></p>
<h2>Ringkasan Evidence</h2><table>${rows}</table>
${analysisHtml(d.analysis)}<h2>Validasi IOC</h2>${iocs.length ? `<table><tr><th>IOC</th><th>Tipe</th><th>Verdict</th><th>Skor</th><th>Sumber</th></tr>${iocRows}</table>` : '<p>Tidak ada IOC.</p>'}
<h2>Event Terkait (&plusmn;${esc(window_minutes)} menit, total ${esc(related.total)})</h2>${related.events.length ? `<table><tr><th>Waktu</th><th>Dataset</th><th>Aksi</th><th>Src</th><th>Dst</th><th>Host</th><th>User</th><th>Pesan</th></tr>${evRows}</table>` : '<p>Tidak ada event terkait.</p>'}
<h2>Catatan Analis</h2>${notes ? `<ul>${notes}</ul>` : '<p>Belum ada catatan.</p>'}
</body></html>`;
}

module.exports = { toMarkdown, toHtml };
