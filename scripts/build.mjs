// build.mjs — يجمع أي SS مع ws + tls + 443، يطبق Test حقيقي ويقيس Delay
import { promises as fs } from 'node:fs';
import tls from 'node:tls';

const env = (k, d) => (process.env[k] || d).split(',').map(s => s.trim()).filter(Boolean);

// الليستة اللي عطيتيها
const CF_IPS = env('CF_IPS', '104.18.37.127,x.com,www.getlucky.com,104.18.36.146,172.64.150.129,172.64.151.110,canary-proxsee-cf.pscp.tv,game01.circus.nl,104.18.41.245,185.199.108.153,api.server.io,104.16.132.229');

const SOURCES = env('SOURCES', [
  'https://github.com/0xRadikal/Free-v2ray-Configs/raw/refs/heads/main/all/configs.txt',
  'https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt',
  'https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/subscriptions/mix-normal.txt',
  'https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt',
  'https://github.com/YawStar/Proxy-Hunter/raw/refs/heads/main/configs/proxy_configs.txt',
  'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/tls.txt',
  'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/all.txt',
  'https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity'
].join(','));

const OUT = 'dist', MAX_OUT = 200, CONC = 30, T = 5000;

// ------------------------------------------------------------------
// 🟢 دالة الفحص الحقيقي (TLS Handshake + HTTP GET)
// ------------------------------------------------------------------
function realTest(cfIp, sni) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = tls.connect({
      host: cfIp,
      port: 443,
      servername: sni,
      rejectUnauthorized: false,
      timeout: T
    }, () => {
      const req = `GET / HTTP/1.1\r\nHost: ${sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`;
      socket.write(req);
    });

    socket.on('data', (chunk) => {
      const text = chunk.toString();
      if (text.includes('HTTP/1.1') || text.includes('HTTP/1.0')) {
        const delay = Date.now() - start;
        socket.destroy();
        resolve(delay);
      }
    });

    socket.on('error', () => { socket.destroy(); resolve(null); });
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
  });
}

// ------------------------------------------------------------------
// 🟢 قراءة وتصفية SS (مرن)
// ------------------------------------------------------------------
function parseSS(line) {
  const raw = (line || '').trim();
  if (!raw.startsWith('ss://') || raw.length > 2000) return null;
  
  const parts = raw.split('#');
  const cleanLink = parts[0];
  
  let remark = '';
  if (parts[1]) {
    try { remark = decodeURIComponent(parts[1]); } catch (e) { remark = parts[1]; }
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

  const colonIdx = hostPort.lastIndexOf(':');
  if (colonIdx === -1) return null;
  
  const host = hostPort.slice(0, colonIdx);
  const port = parseInt(hostPort.slice(colonIdx + 1), 10);
  
  if (port !== 443) return null; 

  const params = new URLSearchParams(query);
  const plugin = params.get('plugin') || '';
  const lowerPlugin = plugin.toLowerCase();

  // 🟢 التوسيع: أي بلوڭين فيه tls و ws (سواء v2ray-plugin, xray-plugin, ولا أي حاجة فيها ws/websocket)
  if (!lowerPlugin.includes('tls')) return null;
  if (!lowerPlugin.includes('ws') && !lowerPlugin.includes('v2ray') && !lowerPlugin.includes('xray')) return null;

  // استخراج الـ SNI من الـ plugin
  const pluginParts = plugin.split(';');
  const hostOpt = pluginParts.find(p => p.startsWith('host='));
  const sni = hostOpt ? hostOpt.replace('host=', '').trim() : host;

  return { userinfo, plugin, sni, remark: remark || sni };
}

// ------------------------------------------------------------------
// 🟢 إعادة بناء الرابط بالـ IP ديال CF
// ------------------------------------------------------------------
function rebuildLink(e, cfIp) {
  return `ss://${e.userinfo}@${cfIp}:443?plugin=${encodeURIComponent(e.plugin)}#${encodeURIComponent(e.remark + ' | ' + e.delay + 'ms')}`;
}

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) || 1 }, async () => {
    while (true) { 
      const k = i++; 
      if (k >= items.length) return;
      try { out[k] = await fn(items[k]); } catch { out[k] = null; } 
    }
  }));
  return out;
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
    const e = parseSS(l); 
    if (!e) continue;
    const k = `${e.userinfo}|${e.sni}|${e.plugin}`;
    if (seen.has(k)) continue; 
    seen.add(k); 
    uniq.push(e);
  }
  console.log(`[+] SS+WS+TLS فريد: ${uniq.length}`);

  const list = uniq.slice(0, 1000); 
  let n = 0;
  
  // الفحص الحقيقي
  const live = (await pool(list, CONC, async e => {
    const cfIp = CF_IPS[Math.floor(Math.random() * CF_IPS.length)];
    const delay = await realTest(cfIp, e.sni);
    
    if (++n % 50 === 0) console.log(`    فحص ${n}/${list.length}`);
    
    return delay !== null ? { ...e, cfIp, delay } : null;
  })).filter(Boolean);

  // ترتيب حسب الأسرع
  live.sort((a, b) => a.delay - b.delay);

  console.log(`[+] حي (نجح الـ Real Test): ${live.length}`);

  if (live.length === 0) {
    console.log('⚠️ ما لقيناش حتى واحد حي كيدوز من CF.');
    return;
  }

  const finalLinks = live.slice(0, MAX_OUT).map(e => rebuildLink(e, e.cfIp));

  await fs.writeFile(`${OUT}/ss-ws.txt`, finalLinks.join('\n') + '\n');
  console.log('[✓] dist/ss-ws.txt تم إنشاؤه بنجاح (مرتب من الأسرع للأبطأ)');
}

main().catch(e => { console.error('FAILED:', e); process.exit(1); });
