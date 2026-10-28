// build.mjs — يجمع كونفيغات عمومية، يحتفظ غير بلي وراء Cloudflare،
// ويبدل الـ address بـ IP ديال Cloudflare باش يمر على *6.

import { promises as fs } from 'node:fs';
import dns from 'node:dns/promises';
import tls from 'node:tls';

const CF_IPS = (process.env.CF_IPS || '104.18.37.127,172.64.80.1,104.16.0.1')
  .split(',').map((s) => s.trim()).filter(Boolean);

const SOURCES = [
  'https://github.com/0xRadikal/Free-v2ray-Configs/raw/refs/heads/main/all/configs.txt',
];

const ALLOWED_NET = new Set(['ws', 'grpc', 'httpupgrade', 'xhttp']);
const OUT_DIR = 'dist';
const CONCURRENCY = 48;
const MAX_LINES = 80000;
const MAX_PROBE = 1500;
const MAX_OUT = 300;
const TLS_TIMEOUT = 7000;

const CF_V4 = [
  '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
  '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
  '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
  '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22',
];

/* ---------- utils ---------- */
const ip2int = (ip) =>
  ip.split('.').reduce((a, o) => ((a << 8) >>> 0) + Number(o), 0) >>> 0;

const isIPv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);

const inCidr = (ip, cidr) => {
  try {
    const [base, bits] = cidr.split('/');
    const mask = bits === '0' ? 0 : (~0 << (32 - Number(bits))) >>> 0;
    return (ip2int(ip) & mask) === (ip2int(base) & mask);
  } catch { return false; }
};

const isCfIp = (ip) => isIPv4(ip) && CF_V4.some((c) => inCidr(ip, c));

const isHostname = (h) =>
  !!h && h.length < 254 && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(h) && !isIPv4(h);

function safeDecode(s) {
  if (!s) return '';
  try { return decodeURIComponent(s); } catch { return s; }
}

async function mapPool(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) || 1 }, async () => {
      while (true) {
        const idx = i++;
        if (idx >= items.length) return;
        try { out[idx] = await fn(items[idx]); } catch { out[idx] = null; }
      }
    }),
  );
  return out;
}

async function fetchText(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 30000);
  try {
    const r = await fetch(url, {
      signal: ctl.signal,
      headers: { 'user-agent': 'cf-sub-builder/1.0' },
    });
    if (!r.ok) { console.log(`[!] ${r.status} ${url}`); return null; }
    return await r.text();
  } catch (e) { console.log(`[!] فشل ${url}: ${e.message}`); return null; }
  finally { clearTimeout(t); }
}

/* ---------- اكتشاف Cloudflare ---------- */
function tlsProbe(ip, domain) {
  return new Promise((resolve) => {
    let settled = false, sock;
    const done = (v) => {
      if (settled) return;
      settled = true;
      try { sock?.destroy(); } catch {}
      resolve(v);
    };
    try {
      sock = tls.connect(
        { host: ip, port: 443, servername: domain, rejectUnauthorized: false,
          ALPNProtocols: ['h2', 'http/1.1'] },
        () => {
          const c = sock.getPeerCertificate() || {};
          const issuer = JSON.stringify(c.issuer || {});
          const san = String(c.subjectaltname || '');
          done({ cf: /cloudflare/i.test(issuer), covers: san.includes(domain) });
        },
      );
    } catch { return done({ cf: false, covers: false }); }
    sock.setTimeout(TLS_TIMEOUT, () => done({ cf: false, covers: false }));
    sock.on('error', () => done({ cf: false, covers: false }));
  });
}

async function isBehindCloudflare(domain) {
  const p = await tlsProbe(CF_IPS[0], domain);
  if (p.cf && p.covers) return true;
  try {
    const ips = await dns.resolve4(domain);
    if (ips.some(isCfIp)) return true;
  } catch {}
  return false;
}

/* ---------- parsing ---------- */
function parseEntry(line) {
  const raw = (line || '').trim();
  if (!raw || !raw.includes('://') || raw.length > 2000) return null;
  const scheme = raw.slice(0, raw.indexOf('://')).toLowerCase();

  if (scheme === 'vless' || scheme === 'trojan') {
    let u;
    try { u = new URL(raw); } catch { return null; }
    const p = u.searchParams;
    const domain = (p.get('host') || p.get('sni') || u.hostname || '').toLowerCase();
    if (!isHostname(domain) && !isCfIp(domain)) return null;
    return {
      kind: scheme, url: u, params: p, domain,
      id: safeDecode(u.username),
      security: (p.get('security') || 'none').toLowerCase(),
      network: (p.get('type') || 'tcp').toLowerCase(),
      path: p.get('path') || '/',
      name: safeDecode((u.hash || '').slice(1)) || domain,
    };
  }

  if (scheme === 'vmess') {
    try {
      const b64 = raw.slice(8).replace(/-/g, '+').replace(/_/g, '/');
      const j = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
      const domain = String(j.host || j.sni || j.add || '').toLowerCase();
      if (!isHostname(domain) && !isCfIp(domain)) return null;
      return {
        kind: 'vmess', json: j, domain,
        id: String(j.id || ''),
        security: String(j.tls || '').toLowerCase(),
        network: String(j.net || 'tcp').toLowerCase(),
        path: j.path || '/',
        name: String(j.ps || domain),
      };
    } catch { return null; }
  }
  return null;
}

function rebuild(e, ip) {
  if (e.kind === 'vmess') {
    const j = { ...e.json, add: ip, port: '443', tls: 'tls' };
    return 'vmess://' + Buffer.from(JSON.stringify(j)).toString('base64');
  }
  const u = e.url;
  u.hostname = ip;
  u.port = '443';
  const p = u.searchParams;
  p.set('security', 'tls');
  p.set('sni', e.domain);
  if (!p.get('host')) p.set('host', e.domain);
  if (!p.get('fp')) p.set('fp', 'chrome');
  u.hash = '#' + encodeURIComponent(`${e.name} | ${e.domain}`);
  return u.toString();
}

/* ---------- main ---------- */
async function main() {
  await fs.mkdir(OUT_DIR, { recursive: true });

  const texts = await mapPool(SOURCES, 6, fetchText);
  const alive = texts.filter(Boolean);
  console.log(`[+] مصادر خدامة: ${alive.length}/${SOURCES.length}`);
  if (!alive.length) throw new Error('ما كاين حتى مصدر خدام');

  const lines = alive.flatMap((t) => {
    const s = t.trim();
    const body = s.includes('://') ? s : Buffer.from(s, 'base64').toString('utf8');
    return body.split(/\r?\n/);
  }).slice(0, MAX_LINES);
  console.log(`[+] سطور خام: ${lines.length}`);

  // parseEntry محمية بوحدها — سطر خايب ما كيقتلش الـ run
  const parsed = lines.map((l) => { try { return parseEntry(l); } catch { return null; } })
                      .filter(Boolean);
  console.log(`[+] محلّلة: ${parsed.length}`);

  const cand = parsed.filter(
    (e) => e.security === 'tls' && ALLOWED_NET.has(e.network),
  );

  const seen = new Set();
  const uniq = [];
  for (const e of cand) {
    const k = `${e.kind}|${e.id}|${e.domain}|${e.network}|${e.path}`;
    if (seen.has(k)) continue;
    seen.add(k); uniq.push(e);
  }
  console.log(`[+] مرشحة بعد الفلترة والتوحيد: ${uniq.length}`);

  const probeList = uniq.slice(0, MAX_PROBE);
  let n = 0;
  const ok = (await mapPool(probeList, CONCURRENCY, async (e) => {
    const v = await isBehindCloudflare(e.domain);
    if (++n % 200 === 0) console.log(`    ... فحص ${n}/${probeList.length}`);
    return v ? e : null;
  })).filter(Boolean);

  const good = ok.slice(0, MAX_OUT);
  console.log(`[+] وراء Cloudflare وخدامة: ${good.length}`);
  if (!good.length) console.log('[!] تنبيه: ما لقيت حتى كونفيغ — جرب مصادر أخرى');

  const mainList = good.map((e) => rebuild(e, CF_IPS[0]));
  await fs.writeFile(`${OUT_DIR}/cf.txt`, mainList.join('\n') + '\n');
  await fs.writeFile(
    `${OUT_DIR}/cf-sub.txt`,
    Buffer.from(mainList.join('\n')).toString('base64') + '\n',
  );

  if (CF_IPS[1]) {
    const alt = good.slice(0, 120).map((e) => rebuild(e, CF_IPS[1]));
    await fs.writeFile(`${OUT_DIR}/cf-alt.txt`, alt.join('\n') + '\n');
  }

  await fs.writeFile(
    `${OUT_DIR}/stats.json`,
    JSON.stringify({
      updated: new Date().toISOString(), raw: lines.length, parsed: parsed.length,
      candidates: uniq.length, live: good.length, cfIp: CF_IPS[0],
    }, null, 2) + '\n',
  );
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
