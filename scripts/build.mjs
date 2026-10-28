// ss-ws.mjs — يستخرج Shadowsocks + v2ray-plugin (TLS) ويطبق Domain Fronting مع CF
import { promises as fs } from 'node:fs';
import net from 'node:net';

const env = (k, d) => (process.env[k] || d).split(',').map(s => s.trim()).filter(Boolean);

// المصادر
const SOURCES = env('SOURCES', [
  'https://github.com/0xRadikal/Free-v2ray-Configs/raw/refs/heads/main/all/configs.txt',
  'https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt',
  'https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/subscriptions/mix-normal.txt',
  'https://github.com/barry-far/V2ray-Config/raw/refs/heads/main/All_Configs_Sub.txt',
  'https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt',
  'https://github.com/0xRadikal/Free-v2ray-Configs/raw/refs/heads/main/top100.txt',
  'https://github.com/0xRadikal/Free-v2ray-Configs/raw/refs/heads/main/all/configs.txt',
  'https://github.com/YawStar/Proxy-Hunter/raw/refs/heads/main/configs/proxy_configs.txt',
  'https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_013.txt',
  'https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/011.txt',
  'https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/trojan.txt',
  'https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/008.txt',
  'https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-telegram-configs-collector-trojan',
  'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/tls.txt',
  'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/all.txt',
  'https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/009.txt',
  'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt',
  'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt',
  'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/medium.txt',
  'https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_015.txt',
  'https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/002.txt',
  'https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity'
].join(','));

const CF_IPS = env('CF_IPS', '104.18.37.127,x.com,www.getlucky.com,104.18.36.146,172.64.150.129,172.64.151.110,canary-proxsee-cf.pscp.tv,game01.circus.nl,104.18.41.245,185.199.108.153,api.server.io,104.16.132.229');
const OUT = 'dist', MAX_OUT = 250, CONC = 40, T = 4000;

function parseSS(line) {
  const raw = (line || '').trim();
  if (!raw.startsWith('ss://') || raw.length > 2000) return null;
  
  const parts = raw.split('#');
  const cleanLink = parts[0];
  
  // 🟢 التصحيح 1: حماية decodeURIComponent باش ما يطيحش السكريبت
  let remark = '';
  if (parts[1]) {
    try {
      remark = decodeURIComponent(parts[1]);
    } catch (e) {
      remark = parts[1]; 
    }
  }

  const body = cleanLink.slice(5);
  
  if (!body.includes('@')) return null; 

  const atIdx = body.indexOf('@');
  const userinfo = body.slice(0, atIdx);
  const rest = body.slice(atIdx + 1);
  
  const qIdx = rest.indexOf('?');
  if (qIdx === -1) return null;

  const hostPort = rest.slice(0, qIdx);
  const query = rest.slice(qIdx + 1);

  // 🟢 التصحيح 2: استعمال lastIndexOf باش ما يطيحش مع IPv6
  const colonIdx = hostPort.lastIndexOf(':');
  if (colonIdx === -1) return null;
  
  const host = hostPort.slice(0, colonIdx);
  const portStr = hostPort.slice(colonIdx + 1);
  const port = parseInt(portStr, 10);
  
  if (port !== 443) return null; 

  const params = new URLSearchParams(query);
  const plugin = params.get('plugin') || '';
  
  if (!plugin.toLowerCase().includes('v2ray-plugin')) return null;
  if (!plugin.toLowerCase().includes('tls')) return null;

  const pluginParts = plugin.split(';');
  const hostOpt = pluginParts.find(p => p.startsWith('host='));
  const realHost = hostOpt ? hostOpt.replace('host=', '') : host;

  return {
    raw: cleanLink,
    originalHost: host,
    port,
    realHost,
    userinfo,
    plugin,
    remark: remark || realHost
  };
}

const tcpAlive = (host, port) => new Promise(res => {
  const s = net.connect({ host, port });
  const done = v => { try { s.destroy(); } catch {} res(v); };
  s.setTimeout(T, () => done(false));
  s.once('connect', () => done(true));
  s.once('error', () => done(false));
});

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) || 1 }, async () => {
    while (true) { const k = i++; if (k >= items.length) return;
      try { out[k] = await fn(items[k]); } catch { out[k] = null; } }
  }));
  return out;
}

function rebuildLink(e, cfIp) {
  // كنعاودو نبنيو الرابط بالـ CF IP
  return `ss://${e.userinfo}@${cfIp}:${e.port}?plugin=${encodeURIComponent(e.plugin)}#${encodeURIComponent(e.remark)}`;
}

async function getText(url) {
  const c = new AbortController(); const t = setTimeout(() => c.abort(), 30000);
  try { const r = await fetch(url, { signal: c.signal }); return r.ok ? await r.text() : null; }
  catch { return null; } finally { clearTimeout(t); }
}

async function main() {
  await fs.mkdir(OUT, { recursive: true });
  const texts = (await Promise.all(SOURCES.map(getText))).filter(Boolean);
  console.log(`[+] مصادر: ${texts.length}/${SOURCES.length}`);
  if (!texts.length) throw new Error('ما كاين حتى مصدر');

  const lines = texts.flatMap(t => {
    const s = t.trim();
    let body = s;
    if (!s.includes('://')) {
      try { body = Buffer.from(s, 'base64').toString('utf8'); } catch(e) {}
    }
    return body.split(/\r?\n/);
  });

  const seen = new Set(), uniq = [];
  for (const l of lines) {
    const e = parseSS(l); if (!e) continue;
    const k = `${e.userinfo}|${e.originalHost}|${e.port}|${e.plugin}`;
    if (seen.has(k)) continue; 
    seen.add(k); 
    uniq.push(e);
  }
  console.log(`[+] SS+WS+TLS فريد: ${uniq.length}`);

  const list = uniq.slice(0, 1500); 
  let n = 0;
  
  // فحص الـ TCP ضد الـ IP ديال Cloudflare
  const live = (await pool(list, CONC, async e => {
    const cfIp = CF_IPS[Math.floor(Math.random() * CF_IPS.length)];
    const ok = await tcpAlive(cfIp, e.port);
    if (++n % 200 === 0) console.log(`    فحص ${n}/${list.length}`);
    return ok ? { ...e, cfIp } : null;
  })).filter(Boolean).slice(0, MAX_OUT);
  
  console.log(`[+] حي (متصل بـ CF): ${live.length}`);

  if (live.length === 0) {
    console.log('⚠️ ما لقيناش حتى واحد حي كيدوز من CF. (هادي نتيجة عادية حيت SS+WS نادرين فـ GitHub)');
    return;
  }

  const finalLinks = live.map(e => rebuildLink(e, e.cfIp));

  await fs.writeFile(`${OUT}/ss-ws.txt`, finalLinks.join('\n') + '\n');
  console.log('[✓] dist/ss-ws.txt تم إنشاؤه بنجاح');
}

main().catch(e => { console.error('FAILED:', e); process.exit(1); });
