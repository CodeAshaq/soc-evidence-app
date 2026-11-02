'use strict';
/**
 * Laporan triage PDF (ringkas, ±2 halaman, A4). Memakai pdf-lib (JavaScript murni, tanpa browser/Chromium).
 * Font bawaan PDF (Helvetica/Courier) hanya mendukung aksara Latin; karakter lain diganti '?'.
 * Untuk mengubah tampilan: warna di C/TONE, ukuran halaman di W/H/M, isi bagian di fungsi toPdf() paling bawah.
 */
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');

const C = { ink: rgb(0.09, 0.11, 0.15), mute: rgb(0.38, 0.42, 0.48), line: rgb(0.85, 0.87, 0.9), navy: rgb(0.06, 0.14, 0.25), accent: rgb(0.15, 0.34, 0.84), band: rgb(0.96, 0.97, 0.98), white: rgb(1, 1, 1) };
const TONE = { crit: rgb(0.71, 0.14, 0.09), high: rgb(0.76, 0.34, 0.05), med: rgb(0.63, 0.38, 0.03), low: rgb(0.08, 0.5, 0.24), info: rgb(0.15, 0.34, 0.84), mute: rgb(0.38, 0.42, 0.48) };
const SEV_TONE = { critical: 'crit', high: 'high', medium: 'med', low: 'low' };
const VERDICT = { true_positive: 'True Positive', needs_investigation: 'Perlu Investigasi', false_positive: 'False Positive', benign: 'Benign', unreviewed: 'Belum Ditinjau' };
const VERDICT_TONE = { true_positive: 'crit', needs_investigation: 'high', false_positive: 'low', benign: 'low', unreviewed: 'mute' };
const IOC_TONE = { malicious: 'crit', suspicious: 'med', clean: 'low' };
const IOC_LABEL = { malicious: 'Malicious', suspicious: 'Suspicious', clean: 'Clean', unknown: 'Tidak diketahui', private: 'Internal', invalid: 'Tidak valid' };
const CONF = { indicated: 'Terindikasi', strong: 'Kuat', confirmed: 'Terkonfirmasi' };
const NARR = [['root_cause', 'Root cause'], ['activity', 'Aktivitas threat actor'], ['findings', 'Hasil pemeriksaan'], ['conclusion', 'Kesimpulan triage']];

const W = 595.28; const H = 841.89; const M = 42; const CW = W - 2 * M; const BOT = M + 20;
const TZ = process.env.REPORT_TZ || 'Asia/Jakarta';

const SUBS = [[/→/g, '->'], [/[–—]/g, '-'], [/[“”]/g, '"'], [/[‘’]/g, "'"], [/≥/g, '>='], [/≤/g, '<='], [/[  ]/g, ' ']];
const dash = (v) => (v === undefined || v === null || v === '' ? '-' : v);
const cap = (s) => (s ? String(s).charAt(0).toUpperCase() + String(s).slice(1) : '-');
const fmt = (t) => { try { return new Date(t).toLocaleString('id-ID', { timeZone: TZ, hour12: false }); } catch (_) { return String(t || '-'); } };
const partsText = (parts) => (parts || []).map((p) => (typeof p === 'string' ? p : p.v)).join('');

async function toPdf(d) {
  const pdf = await PDFDocument.create();
  pdf.setTitle(`Laporan Triage Alert ${d.id}`);
  pdf.setAuthor('SOC Evidence Collector');
  pdf.setCreator('SOC Evidence Collector');
  const F = { r: await pdf.embedFont(StandardFonts.Helvetica), b: await pdf.embedFont(StandardFonts.HelveticaBold), m: await pdf.embedFont(StandardFonts.Courier) };
  const OK = new Set(F.r.getCharacterSet());

  const clean = (s) => {
    let t = String(s === undefined || s === null ? '' : s);
    for (const [a, b] of SUBS) t = t.replace(a, b);
    let o = '';
    for (const ch of t) { const c = ch.codePointAt(0); o += c < 32 ? ' ' : OK.has(c) ? ch : '?'; }
    return o;
  };
  const wrap = (text, font, size, w) => {
    const width = (s) => font.widthOfTextAtSize(s, size);
    const lines = []; let cur = '';
    for (let word of clean(text).split(' ').filter(Boolean)) {
      while (width(word) > w) { // token panjang (hash, URL) dipecah per karakter
        let i = word.length;
        while (i > 1 && width(word.slice(0, i)) > w) i--;
        if (cur) { lines.push(cur); cur = ''; }
        lines.push(word.slice(0, i)); word = word.slice(i);
      }
      const t = cur ? `${cur} ${word}` : word;
      if (width(t) <= w) cur = t; else { lines.push(cur); cur = word; }
    }
    if (cur) lines.push(cur);
    return lines.length ? lines : [''];
  };

  let page; let y;
  const newPage = () => { page = pdf.addPage([W, H]); y = H - M; };
  const need = (h) => { if (y - h < BOT) newPage(); };
  const put = (s, x, yy, { font = F.r, size = 9, color = C.ink } = {}) => page.drawText(clean(s), { x, y: yy, font, size, color });

  function section(title) {
    need(34); y -= 12;
    put(title.toUpperCase(), M, y - 9, { font: F.b, size: 9.5, color: C.accent });
    y -= 15;
    page.drawLine({ start: { x: M, y }, end: { x: W - M, y }, thickness: 0.8, color: C.line });
    y -= 7;
  }
  function paragraph(text, { size = 9.5, lh = 13.5, x = M, w = CW, font = F.r } = {}) {
    for (const line of wrap(text, font, size, w)) { need(lh); put(line, x, y - size, { font, size }); y -= lh; }
    y -= 3;
  }
  function bullets(items) {
    for (const it of items) {
      const lines = wrap(it, F.r, 9.5, CW - 14);
      need(13.5 * Math.min(lines.length, 2));
      put('•', M + 2, y - 9.5, { size: 9.5, color: C.accent });
      for (const line of lines) { need(13.5); put(line, M + 14, y - 9.5); y -= 13.5; }
      y -= 1.5;
    }
  }
  function table(cols, rows, { size = 8.5 } = {}) {
    const pad = 4; const lh = size + 3; const ws = cols.map((c) => c.w * CW);
    const head = () => {
      need(lh + 2 * pad + 4);
      page.drawRectangle({ x: M, y: y - lh - 2 * pad + 2, width: CW, height: lh + 2 * pad - 2, color: C.band });
      let x = M;
      cols.forEach((c, i) => { put(c.label.toUpperCase(), x + pad, y - pad - size + 1, { font: F.b, size: size - 1, color: C.mute }); x += ws[i]; });
      y -= lh + 2 * pad - 2;
    };
    head();
    for (const row of rows) {
      const cells = row.map((c, i) => { const o = typeof c === 'object' && c !== null ? c : { t: c }; return { ...o, lines: wrap(o.t, o.font || F.r, size, ws[i] - 2 * pad) }; });
      const h = Math.max(...cells.map((c) => c.lines.length)) * lh + 2 * pad;
      if (y - h < BOT) { newPage(); head(); }
      let x = M;
      cells.forEach((c, i) => { c.lines.forEach((ln, k) => put(ln, x + pad, y - pad - size - k * lh + 1, { font: c.font || F.r, size, color: c.color || C.ink })); x += ws[i]; });
      y -= h;
      page.drawLine({ start: { x: M, y }, end: { x: W - M, y }, thickness: 0.4, color: C.line });
    }
    y -= 4;
  }

  const ev = d.evidence; const an = d.analysis; const tri = d.triage || {};
  const verdict = tri.verdict && tri.verdict !== 'unreviewed' ? tri.verdict : (an && an.verdict) || 'unreviewed';
  const sevTone = TONE[SEV_TONE[ev.rule.severity] || 'mute'];

  // ---- Kepala laporan ----
  newPage();
  page.drawRectangle({ x: 0, y: H - 74, width: W, height: 74, color: C.navy });
  put('LAPORAN TRIAGE ALERT', M, H - 36, { font: F.b, size: 17, color: C.white });
  put('SOC Evidence Collector  |  Rahasia - hanya untuk tim keamanan', M, H - 54, { size: 8.5, color: rgb(0.72, 0.78, 0.88) });
  put(`Dibuat ${fmt(d.generated_at)} (${TZ})`, W - M - 190, H - 54, { size: 8.5, color: rgb(0.72, 0.78, 0.88) });
  y = H - 74 - 16;

  // ---- Ringkasan ----
  for (const line of wrap(dash(ev.rule.name), F.b, 13, CW)) { need(18); put(line, M, y - 13, { font: F.b, size: 13 }); y -= 18; }
  put(`ID alert: ${d.id}`, M, y - 8, { font: F.m, size: 8, color: C.mute }); y -= 18;

  const boxH = 74; need(boxH + 8);
  page.drawRectangle({ x: M, y: y - boxH, width: CW, height: boxH, color: C.band });
  page.drawRectangle({ x: M, y: y - boxH, width: 4, height: boxH, color: TONE[VERDICT_TONE[verdict] || 'mute'] });
  put(`${VERDICT[verdict] || verdict}${an && verdict === an.verdict ? `  -  ${an.priority}` : ''}`, M + 14, y - 22, { font: F.b, size: 15, color: TONE[VERDICT_TONE[verdict] || 'mute'] });
  const by = tri.verdict_source === 'analyst' ? 'Ditetapkan analis' : tri.verdict_source === 'auto' ? 'Verdict otomatis' : 'Rekomendasi sistem';
  put(by + (an && verdict !== an.verdict ? ` (rekomendasi sistem: ${VERDICT[an.verdict] || an.verdict}, ${an.priority})` : ''), M + 14, y - 36, { size: 8.5, color: C.mute });
  const kv = [['Severity', cap(ev.rule.severity), sevTone], ['Skor risiko', an ? `${an.score}/100` : '-'], ['Keyakinan', an ? cap(an.confidence) : '-'], ['Status alert', dash(ev.rule.status)]];
  kv.forEach(([k, v, col], i) => { const x = M + 14 + i * 124; put(k, x, y - 52, { size: 7.5, color: C.mute }); put(v, x, y - 64, { font: F.b, size: 10, color: col || C.ink }); });
  y -= boxH + 8;
  const n = ev.network;
  table([{ label: 'Waktu alert', w: 0.22 }, { label: 'Host', w: 0.2 }, { label: 'Pengguna', w: 0.2 }, { label: 'Sumber → Tujuan', w: 0.38 }],
    [[fmt(ev.timestamp), dash(ev.host.name), dash(ev.user.name), `${dash(n.source_ip)}${n.source_port ? `:${n.source_port}` : ''} → ${dash(n.destination_ip)}${n.destination_port ? `:${n.destination_port}` : ''}`]]);

  if (an) {
    // ---- Analisa ----
    section('Analisa');
    for (const [k, title] of NARR) {
      const txt = partsText(an.narrative[k]);
      if (!txt) continue;
      need(30); put(title, M, y - 9, { font: F.b, size: 9.5 }); y -= 14;
      paragraph(txt, { size: 9.3, lh: 13 });
    }
    // ---- IOC ----
    section('Validasi IOC');
    const iocs = (an.ioc_results || []).filter((r) => r.verdict !== 'private');
    if (iocs.length) {
      table([{ label: 'IOC', w: 0.5 }, { label: 'Tipe', w: 0.1 }, { label: 'Skor', w: 0.1 }, { label: 'Verdict', w: 0.3 }],
        iocs.map((r) => [{ t: r.value, font: F.m }, String(r.type || '-').toUpperCase(), r.score === null || r.score === undefined ? '-' : String(r.score), { t: IOC_LABEL[r.verdict] || r.verdict, font: F.b, color: TONE[IOC_TONE[r.verdict] || 'mute'] }]), { size: 8 });
    } else paragraph('Tidak ada IOC publik yang perlu divalidasi.', { size: 9.3 });
    // ---- TTP ----
    section('TTP - MITRE ATT&CK');
    if (an.ttps.length) {
      table([{ label: 'Tactic', w: 0.18 }, { label: 'Technique', w: 0.24 }, { label: 'Procedure', w: 0.42 }, { label: 'Keyakinan', w: 0.16 }],
        an.ttps.map((t) => [`${dash(t.tactic)} (${dash(t.tactic_id)})`, `${dash(t.technique)} (${dash(t.technique_id)})`, dash(t.procedure), { t: CONF[t.confidence] || t.confidence, font: F.b }]), { size: 8 });
    } else paragraph('Belum ada pemetaan TTP pada alert ini.', { size: 9.3 });
    // ---- Tindakan ----
    if (an.narrative.actions && an.narrative.actions.length) { section('Tindakan yang disarankan'); bullets(an.narrative.actions); }
    if (an.notes && an.notes.length) { section('Catatan & keterbatasan'); bullets(an.notes); }
  }

  // ---- Evidence kunci ----
  section('Evidence utama');
  const p = ev.process; const f = ev.file;
  const rows = [
    ['Rule', dash(ev.rule.name)], ['Alasan alert', ev.rule.reason], ['Protokol / aksi', [n.protocol, n.action].filter(Boolean).join(' / ')],
    ['Proses', [p.parent_name && `${p.parent_name} ->`, p.name].filter(Boolean).join(' ')], ['Command line', p.command_line],
    ['File', f.path || f.name], ['SHA-256', f.sha256], ['MITRE (rule)', (ev.rule.mitre_ids || []).join(', ')],
  ].filter(([, v]) => v);
  table([{ label: 'Atribut', w: 0.2 }, { label: 'Nilai', w: 0.8 }], rows.map(([k, v]) => [{ t: k, font: F.b }, { t: String(v), font: k === 'Command line' || k === 'SHA-256' ? F.m : F.r }]), { size: 8 });

  // ---- Catatan analis ----
  const notes = (tri.notes || []).filter((x) => x.by !== 'auto-analyzer').slice(-3);
  if (notes.length) { section('Catatan analis'); bullets(notes.map((x) => `${fmt(x.at)} - ${x.by}: ${x.text}`)); }

  // ---- Footer tiap halaman ----
  const pages = pdf.getPages();
  pages.forEach((pg, i) => {
    pg.drawLine({ start: { x: M, y: M + 6 }, end: { x: W - M, y: M + 6 }, thickness: 0.5, color: C.line });
    pg.drawText(clean('Dihasilkan otomatis oleh SOC Evidence Collector. Kesimpulan perlu diverifikasi analis sebelum tindakan.'), { x: M, y: M - 6, font: F.r, size: 7, color: C.mute });
    const t = `Halaman ${i + 1} / ${pages.length}`;
    pg.drawText(t, { x: W - M - F.r.widthOfTextAtSize(t, 7), y: M - 6, font: F.r, size: 7, color: C.mute });
  });
  return Buffer.from(await pdf.save());
}

module.exports = { toPdf };
