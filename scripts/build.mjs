// build.mjs — يجمع كونفيغات عمومية، يحتفظ غير بلي وراء Cloudflare،
// ويبدل الـ address بـ IP ديال Cloudflare باش يمر على *6.

import { promises as fs } from 'node:fs';
import dns from 'node:dns/promises';
import tls from 'node:tls';

const CF_IPS = (process.env.CF_IPS || '104.18.37.127,172.64.80.1,104.16.0.1')
  .split(',').map((s) => s.trim()).filter(Boolean);

const SOURCES = [
  'https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt',
  'https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt',
  'https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray',
  'https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt',
  'https://raw.githubusercontent.com/ts-sf/fly/main/v2',
  'https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2',
  'https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_1.txt',
];

const ALLOWED_NET = new Set(['ws', 'grpc', 'httpupgrade', 'xhttp']);
const OUT_DIR = 'dist';
const CONCURRENCY = 48;
const MAX_PROBE = 1500;
const MAX_OUT = 300;
const TLS_TIMEOUT = 7000;

// ranges رسمية ديال Cloudflare
const CF_V4 = [
  '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
  '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
  '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
  '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22',
];

/* ---------- utils ---------- */
const ip2int = (ip) =>
  ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;

const inCidr = (ip, cidr) => {
  const [base, bits] = cidr.split('/');
  const mask = bits === '0' ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return (ip2int(ip) & mask) === (ip2int(base) & mask);
};

const isCfIp = (ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip) && CF_V4.some((c) => inCidr(ip, c));
const isHostname = (h) => /^(?!\d+\.\d+\.\d+\.\d+$)[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(h);

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
    if (!r.ok) return null;
    return await r.text();
  } catch { return null; } finally { clearTimeout(t); }
}

/* ---------- اكتشاف Cloudflare ---------- */
function tlsProbe(ip, domain) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; try { s.destroy(); } catch {} resolve(v); } };
    const s = tls.connect(
      { host: ip, port: 443, servername: domain, rejectUnauthorized: false, ALPNProtocols: ['h2', 'http/1.1'] },
      () => {
        const c = s.getPeerCertificate() || {};
        const issuer = JSON.stringify(c.issuer || {});
        const san = String(c.subjectaltname || '');
        finish({ cf: /cloudflare/i.test(issuer), covers: san.includes(domain) });
      },
    );
    s.setTimeout(TLS_TIMEOUT, () => finish({ cf: false, covers: false }));
    s.on('error', () => finish({ cf: false, covers: false }));
  });
}

async function isBehindCloudflare(domain) {
  // 1) الفحص الحاسم: الشهادة لي كترجع من IP ديال Cloudflare
  const p = await tlsProbe(CF_IPS[0], domain);
  if (p.cf && p.covers) return true;
  // 2) فحص احتياطي: DNS + ranges
  try {
    const ips = await dns.resolve4(domain);
    if (ips.some(isCfIp)) return true;
  } catch {}
  return false;
}

/* ---------- parsing ---------- */
function parseEntry(line) {
  const raw = line.trim();
  if (!raw || !raw.includes('://')) return null;
  const scheme = raw.slice(0, raw.indexOf('://')).toLowerCase();

  if (scheme === 'vless' || scheme === 'trojan') {
    let u; try { u = new URL(raw); } catch { return null; }
    const p = u.searchParams;
    const domain = (p.get('host') || p.get('sni') || u.hostname || '').toLowerCase();
    if (!domain) return null;
    return {
      kind: scheme, url: u, params: p, domain,
      id: decodeURIComponent(u.username),
      port: u.port || '443',
      security: (p.get('security') || 'none').toLowerCase(),
      network: (p.get('type') || 'tcp').toLowerCase(),
      path: p.get('path') || '/',
      name: decodeURIComponent((u.hash || '').slice(1)) || domain,
    };
  }

  if (scheme === 'vmess') {
    try {
      const b64 = raw.slice(8).replace(/-/g, '+').replace(/_/g, '/');
      const j = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
      const domain = String(j.host || j.sni || j.add || '').toLowerCase();
      if (!domain) return null;
      return {
        kind: 'vmess', json: j, domain,
        id: j.id, port: String(j.port || '443'),
        security: String(j.tls || '').toLowerCase(),
        network: String(j.net || 'tcp').toLowerCase(),
        path: j.path || '/',
        name: j.ps || domain,
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
  const lines = texts.filter(Boolean).flatMap((t) => {
    const s = t.trim();
    return s.includes('://') ? s.split(/\r?\n/) : Buffer.from(s, 'base64').toString('utf8').split(/\r?\n/);
  });
  console.log(`[+] سطور خام: ${lines.length}`);

  const parsed = lines.map(parseEntry).filter(Boolean);
  console.log(`[+] محلّلة: ${parsed.length}`);

  const cand = parsed.filter(
    (e) => e.security === 'tls' && ALLOWED_NET.has(e.network) && (isHostname(e.domain) || isCfIp(e.domain)),
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
  const ok = (await mapPool(probeList, CONCURRENCY, (e) =>
    isBehindCloudflare(e.domain).then((v) => (v ? e : null)),
  )).filter(Boolean);

  const good = ok.slice(0, MAX_OUT);
  console.log(`[+] وراء Cloudflare وخدامة: ${good.length}`);

  const mainList = good.map((e) => rebuild(e, CF_IPS[0]));
  await fs.writeFile(`${OUT_DIR}/cf.txt`, mainList.join('\n') + '\n');
  await fs.writeFile(
    `${OUT_DIR}/cf-sub.txt`,
    Buffer.from(mainList.join('\n')).toString('base64') + '\n',
  );

  // نسخ احتياطية على IP ديال Cloudflare آخر
  if (CF_IPS[1]) {
    const alt = good.slice(0, 120).map((e) => rebuild(e, CF_IPS[1]));
    await fs.writeFile(`${OUT_DIR}/cf-alt.txt`, alt.join('\n') + '\n');
  }

  await fs.writeFile(
    `${OUT_DIR}/stats.json`,
    JSON.stringify(
      { updated: new Date().toISOString(), raw: lines.length, parsed: parsed.length,
        candidates: uniq.length, live: good.length, cfIp: CF_IPS[0] },
      null, 2,
    ) + '\n',
  );
}

main().catch((e) => { console.error(e); process.exit(1); });
