'use strict';
const config = require('./config');
const { detectIocType, isPrivateIp } = require('./extract');

const cache = new Map(); // key -> { exp, value }
const ttl = () => config.ti.cacheMinutes * 60 * 1000;

function links(type, value) {
  const e = encodeURIComponent(value);
  const l = [];
  if (type === 'ip') {
    l.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${e}` });
    l.push({ name: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${e}` });
    l.push({ name: 'Shodan', url: `https://www.shodan.io/host/${e}` });
    l.push({ name: 'GreyNoise', url: `https://viz.greynoise.io/ip/${e}` });
  } else if (type === 'domain') {
    l.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/domain/${e}` });
    l.push({ name: 'urlscan', url: `https://urlscan.io/search/#domain%3A${e}` });
  } else if (['md5', 'sha1', 'sha256'].includes(type)) {
    l.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/file/${e}` });
    l.push({ name: 'MalwareBazaar', url: `https://bazaar.abuse.ch/browse.php?search=${e}` });
  } else if (type === 'url') {
    l.push({ name: 'urlscan', url: `https://urlscan.io/search/#${e}` });
  }
  return l;
}

async function vtLookup(type, value) {
  let path;
  if (type === 'ip') path = `ip_addresses/${encodeURIComponent(value)}`;
  else if (type === 'domain') path = `domains/${encodeURIComponent(value)}`;
  else if (type === 'url') path = `urls/${Buffer.from(value).toString('base64url')}`;
  else path = `files/${encodeURIComponent(value)}`;

  const r = await fetch(`https://www.virustotal.com/api/v3/${path}`, {
    headers: { 'x-apikey': config.ti.vtKey },
    signal: AbortSignal.timeout(15000),
  });
  if (r.status === 404) return { name: 'VirusTotal', found: false };
  if (!r.ok) return { name: 'VirusTotal', error: `HTTP ${r.status}` };
  const a = (await r.json()).data.attributes;
  const s = a.last_analysis_stats || {};
  return {
    name: 'VirusTotal',
    found: true,
    malicious: s.malicious || 0,
    suspicious: s.suspicious || 0,
    harmless: s.harmless || 0,
    undetected: s.undetected || 0,
    reputation: a.reputation,
    country: a.country,
    as_owner: a.as_owner,
    last_analysis: a.last_analysis_date ? new Date(a.last_analysis_date * 1000).toISOString() : undefined,
  };
}

async function abuseLookup(ip) {
  const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
    headers: { Key: config.ti.abuseKey, Accept: 'application/json' },
    signal: AbortSignal.timeout(15000),
  });
  if (!r.ok) return { name: 'AbuseIPDB', error: `HTTP ${r.status}` };
  const d = (await r.json()).data;
  return {
    name: 'AbuseIPDB',
    found: true,
    confidence: d.abuseConfidenceScore,
    reports: d.totalReports,
    country: d.countryCode,
    isp: d.isp,
    usage: d.usageType,
    last_reported: d.lastReportedAt,
  };
}

function decide(sources) {
  let verdict = 'unknown';
  let score = 0;
  for (const s of sources) {
    if (s.error || s.found === false) continue;
    if (s.name === 'VirusTotal') {
      const bad = (s.malicious || 0) + (s.suspicious || 0) * 0.5;
      score = Math.max(score, Math.min(100, Math.round(bad * 10)));
      if (s.malicious >= 3) verdict = 'malicious';
      else if (s.malicious >= 1 || s.suspicious >= 2) verdict = verdict === 'malicious' ? verdict : 'suspicious';
      else if (verdict === 'unknown') verdict = 'clean';
    }
    if (s.name === 'AbuseIPDB') {
      score = Math.max(score, s.confidence || 0);
      if (s.confidence >= 75) verdict = 'malicious';
      else if (s.confidence >= 25 && verdict !== 'malicious') verdict = 'suspicious';
      else if (verdict === 'unknown') verdict = 'clean';
    }
  }
  return { verdict, score };
}

/** Hasil simulasi untuk mode demo (tanpa API key / tanpa internet). */
function simulated(type, value) {
  const bad = ['203.0.113.45', '198.51.100.23', 'evil-login.example', 'update-check.example'];
  const isBad = bad.includes(value) || /^[a-f0-9]{64}$/i.test(value);
  return {
    sources: [
      isBad
        ? { name: 'VirusTotal (simulasi)', found: true, malicious: 14, suspicious: 2, harmless: 60, undetected: 12 }
        : { name: 'VirusTotal (simulasi)', found: true, malicious: 0, suspicious: 0, harmless: 70, undetected: 18 },
    ],
    verdict: isBad ? 'malicious' : 'clean',
    score: isBad ? 88 : 0,
  };
}

async function check(rawValue) {
  const value = String(rawValue || '').trim();
  const type = detectIocType(value);
  if (!type) return { value, type: null, verdict: 'invalid', score: 0, sources: [], links: [], note: 'Format IOC tidak dikenali.' };

  if (type === 'ip' && isPrivateIp(value)) {
    return { value, type, verdict: 'private', score: 0, sources: [], links: [], note: 'IP privat/internal tidak dikirim ke layanan eksternal.' };
  }

  const key = `${type}:${value.toLowerCase()}`;
  const hit = cache.get(key);
  if (hit && hit.exp > Date.now()) return { ...hit.value, cached: true };

  let result;
  if (config.demoMode && !config.ti.vtKey && !config.ti.abuseKey) {
    const s = simulated(type, value);
    result = { value, type, ...s, links: links(type, value), note: 'Mode demo: hasil ini simulasi, bukan data nyata.' };
  } else {
    const jobs = [];
    if (config.ti.vtKey) jobs.push(vtLookup(type, value));
    if (config.ti.abuseKey && type === 'ip') jobs.push(abuseLookup(value));
    if (!jobs.length) {
      return { value, type, verdict: 'unknown', score: 0, sources: [], links: links(type, value), note: 'Belum ada API key (VT_API_KEY / ABUSEIPDB_API_KEY). Gunakan tautan manual.' };
    }
    const settled = await Promise.allSettled(jobs);
    const sources = settled.map((s, i) => (s.status === 'fulfilled' ? s.value : { name: `source-${i}`, error: String(s.reason && s.reason.message) }));
    result = { value, type, ...decide(sources), sources, links: links(type, value) };
  }
  cache.set(key, { exp: Date.now() + ttl(), value: result });
  return result;
}

async function checkMany(values) {
  const uniq = [...new Set(values.map((v) => String(v).trim()))].slice(0, 20);
  const out = [];
  for (const v of uniq) out.push(await check(v)); // berurutan agar tidak melewati rate limit API gratis
  return out;
}

module.exports = { check, checkMany };
