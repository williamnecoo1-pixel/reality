// build.mjs — يجمع WS + TLS + 443 من أي بروتوكول، يغير IP لـ CF، ويقيس التأخير الحقيقي
import { promises as fs } from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';

const env = (k, d) => (process.env[k] || d).split(',').map(s => s.trim()).filter(Boolean);

// الليستة اللي عطيتيها ديال CF IPs والدومينات
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

const OUT = 'dist', MAX_OUT = 200, CONC = 50, T = 3000;

// دالة قياس التأخير الحقيقي (TLS Handshake)
function measureDelay(ip, port, sni, timeout = T) {
  return new Promise((resolve) => {
    const start = Date.now();
    // كنستعملو TLS Connect حيت هو اللي كيتبادل الشهادة (SNI) مع Cloudflare
    const socket = tls.connect({
      host: ip,
      port: port,
      servername: sni, 
      rejectUnauthorized: false, // ما كيهمش واش الشهادة صحيحة، المهم واش كاين اتصال
      timeout: timeout
    }, () => {
      const delay = Date.now() - start;
      socket.destroy();
      resolve(delay);
    });

    socket.on('error', () => { socket.destroy(); resolve(null); });
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
  });
}

// دالة قراءة وتصفية الكونفيغات
function parseConfig(line) {
  const raw = line.trim();
  if (!raw) return null;

  let protocol = '';
  let host = '', port = 0, sni = '', path = '/', userinfo = '', vmessJson = null;

  try {
    if (raw.startsWith('vless://') || raw.startsWith('trojan://')) {
      protocol = raw.startsWith('vless://') ? 'vless' : 'trojan';
      const u = new URL(raw);
      const p = u.searchParams;
      if ((p.get('type') || '').toLowerCase() !== 'ws') return null;
      if ((p.get('security') || '').toLowerCase() !== 'tls') return null;
      
      port = u.port === '' ? 443 : parseInt(u.port, 10);
      if (port !== 443) return null;

      host = u.hostname;
      sni = p.get('sni') || p.get('host') || host;
      path = p.get('path') || '/';
      userinfo = u.username;
      
    } else if (raw.startsWith('vmess://')) {
      protocol = 'vmess';
      const b64 = raw.split('#')[0].slice(8).trim();
      // تصحيح Base64
      const jsonStr = Buffer.from(b64, 'base64').toString('utf8');
      const config = JSON.parse(jsonStr);

      if ((config.net || '').toLowerCase() !== 'ws') return null;
      if ((config.tls || '').toLowerCase() !== 'tls') return null;
      port = parseInt(config.port, 10);
      if (port !== 443) return null;

      host = config.add;
      sni = config.sni || config.host || host;
      path = config.path || '/';
      vmessJson = config;
      userinfo = config.id;

    } else if (raw.startsWith('ss://')) {
      protocol = 'ss';
      const parts = raw.split('#');
      const cleanLink = parts[0];
      const body = cleanLink.slice(5);
      if (!body.includes('@')) return null;

      const atIdx = body.indexOf('@');
      userinfo = body.slice(0, atIdx);
      const rest = body.slice(atIdx + 1);
      
      const qIdx = rest.indexOf('?');
      if (qIdx === -1) return null;

      const hostPort = rest.slice(0, qIdx);
      const query = rest.slice(qIdx + 1);

      const colonIdx = hostPort.lastIndexOf(':');
      host = hostPort.slice(0, colonIdx);
      port = parseInt(hostPort.slice(colonIdx + 1), 10);
      
      if (port !== 443) return null;

      const params = new URLSearchParams(query);
      const plugin = params.get('plugin') || '';
      
      if (!plugin.toLowerCase().includes('v2ray-plugin')) return null;
      if (!plugin.toLowerCase().includes('tls')) return null;

      const pluginParts = plugin.split(';');
      const hostOpt = pluginParts.find(p => p.startsWith('host='));
      sni = hostOpt ? hostOpt.replace('host=', '') : host;
      
    } else {
      return null;
    }
  } catch (e) {
    return null;
  }

  // الفلتر النهائي: خاصنا SNI باش نقدرو نديرو Domain Fronting
  if (!sni || sni === '') return null;

  return { raw, protocol, host, port, sni, userinfo, vmessJson };
}

// دالة إعادة بناء الكونفيغ بالـ IP ديال CF
function rebuildConfig(item, cfIp) {
  const { raw, protocol, sni, userinfo, vmessJson } = item;

  if (protocol === 'vless' || protocol === 'trojan') {
    const u = new URL(raw);
    u.hostname = cfIp; // نبدلو السيرفر بـ CF IP
    return u.toString();
    
  } else if (protocol === 'vmess') {
    vmessJson.add = cfIp; // نبدلو السيرفر بـ CF IP
    // كنرجعو نكوديو الـ JSON
    const b64 = Buffer.from(JSON.stringify(vmessJson), 'utf8').toString('base64');
    const remark = raw.includes('#') ? raw.split('#')[1] : '';
    return `vmess://${b64}${remark ? '#' + remark : ''}`;
    
  } else if (protocol === 'ss') {
    const parts = raw.split('#');
    const remark = parts[1] ? parts[1] : '';
    const body = parts[0].slice(5);
    const atIdx = body.indexOf('@');
    const userinfoPart = body.slice(0, atIdx);
    const rest = body.slice(atIdx + 1);
    const qIdx = rest.indexOf('?');
    const query = rest.slice(qIdx + 1); // الـ plugin كيبقى كيفما هو

    // كنبدلو غير السيرفر والبورت
    return `ss://${userinfoPart}@${cfIp}:443?${query}${remark ? '#' + remark : ''}`;
  }
  return null;
}

// إدارة العمليات المتوازية
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
    const e = parseConfig(l); 
    if (!e) continue;
    // منع التكرار بناءً على السيرفر والـ SNI
    const k = `${e.protocol}|${e.host}|${e.sni}`;
    if (seen.has(k)) continue; 
    seen.add(k); 
    uniq.push(e);
  }
  console.log(`[+] كونفيغات WS+TLS+443 فريدة: ${uniq.length}`);

  const list = uniq.slice(0, 1500); 
  let n = 0;
  
  // الفحص وقياس التأخير
  const live = (await pool(list, CONC, async e => {
    // كنختارو IP ديال CF بشكل عشوائي
    const cfIp = CF_IPS[Math.floor(Math.random() * CF_IPS.length)];
    
    // كنقيسو الوقت الحقيقي ديال الاتصال (TLS Handshake)
    const delay = await measureDelay(cfIp, 443, e.sni);
    
    if (++n % 100 === 0) console.log(`    فحص ${n}/${list.length}`);
    
    // إلا كان الاتصال ناجح، كنرجعو الكونفيغ مع الوقت ديالو
    return delay !== null ? { ...e, cfIp, delay } : null;
  })).filter(Boolean);

  // ترتيب النتائج من الأسرع للأبطأ
  live.sort((a, b) => a.delay - b.delay);

  const finalLinks = live.slice(0, MAX_OUT).map(e => rebuildConfig(e, e.cfIp));
  
  console.log(`[+] حي (متصل بـ CF) وسريع: ${finalLinks.length}`);

  if (finalLinks.length === 0) {
    console.log('⚠️ ما لقيناش حتى واحد حي كيدوز من CF.');
    return;
  }

  await fs.writeFile(`${OUT}/cf-sub.txt`, finalLinks.join('\n') + '\n');
  console.log('[✓] dist/cf-sub.txt تم إنشاؤه بنجاح (مرتب من الأسرع للأبطأ)');
}

main().catch(e => { console.error('FAILED:', e); process.exit(1); });
