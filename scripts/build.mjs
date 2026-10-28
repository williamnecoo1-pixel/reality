// scripts/reality.mjs — يستخرج VLESS+REALITY ويولّد جوج نسخ: بلا SNI / بـSNI مسموح
import { promises as fs } from 'node:fs';
import net from 'node:net';

const env = (k, d) => (process.env[k] || d).split(',').map(s => s.trim()).filter(Boolean);

const SOURCES = env('SOURCES', [
  'https://github.com/0xRadikal/Free-v2ray-Configs/raw/refs/heads/main/all/configs.txt',
].join(','));

const NO_SNI = env('NO_SNI_IPS', '104.18.37.127,104.18.36.146,172.64.150.129,172.64.151.110');
const OK_SNI = env('OK_SNIS', 'x.com,www.instagram.com,web.whatsapp.com,www.facebook.com,snapchat.com');

const OUT = 'dist', MAX_OUT = 250, CONC = 40, T = 4000;
const isIPv4 = s => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);

function parse(line) {
  const raw = (line || '').trim();
  if (!raw.startsWith('vless://') || raw.length > 2000) return null;
  let u; try { u = new URL(raw); } catch { return null; }
  const p = u.searchParams;
  if ((p.get('security') || '').toLowerCase() !== 'reality') return null;
  const pbk = p.get('pbk'); if (!pbk) return null;
  const addr = u.hostname.replace(/^\[|\]$/g, '');
  const port = Number(u.port || 443);
  if (!addr || !port) return null;
  return {
    uuid: decodeURIComponent(u.username || ''), addr, port,
    type: (p.get('type') || 'tcp').toLowerCase(), pbk,
    sid: p.get('sid') || '', fp: p.get('fp') || 'chrome',
    spx: p.get('spx') || '/', flow: p.get('flow') || '',
    sni: (p.get('sni') || '').toLowerCase(),
    name: decodeURIComponent((u.hash || '').slice(1)) || addr,
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

function link(e, sni) {
  const q = new URLSearchParams({ type: e.type, security: 'reality', sni, fp: e.fp, pbk: e.pbk });
  if (e.sid) q.set('sid', e.sid);
  if (e.spx) q.set('spx', e.spx);
  if (e.flow) q.set('flow', e.flow);          // ما نزيدوهش من عندنا — نعيّطو غير اللي كان
  return `vless://${e.uuid}@${e.addr}:${e.port}?${q}#${encodeURIComponent(`${e.name} | ${sni}`)}`;
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
    const body = s.includes('://') ? s : Buffer.from(s, 'base64').toString('utf8');
    return body.split(/\r?\n/);
  });

  const seen = new Set(), uniq = [];
  for (const l of lines) {
    const e = parse(l); if (!e) continue;
    const k = `${e.uuid}|${e.addr}|${e.port}`;
    if (seen.has(k)) continue; seen.add(k); uniq.push(e);
  }
  console.log(`[+] REALITY فريد: ${uniq.length}`);

  const list = uniq.slice(0, 1500); let n = 0;
  const live = (await pool(list, CONC, async e => {
    const ok = await tcpAlive(e.addr, e.port);
    if (++n % 200 === 0) console.log(`    فحص ${n}/${list.length}`);
    return ok ? e : null;
  })).filter(Boolean).slice(0, MAX_OUT);
  console.log(`[+] حي: ${live.length}`);

  const nosni  = live.map((e, i) => link(e, NO_SNI[i % NO_SNI.length]));
  const withsni = live.map((e, i) => link(e, e.sni && !isIPv4(e.sni) ? e.sni : OK_SNI[i % OK_SNI.length]));

  await fs.writeFile(`${OUT}/reality-nosni.txt`, nosni.join('\n') + '\n');
  await fs.writeFile(`${OUT}/reality-sni.txt`, withsni.join('\n') + '\n');
  await fs.writeFile(`${OUT}/reality-sub-nosni.txt`, Buffer.from(nosni.join('\n')).toString('base64') + '\n');
  console.log('[✓] dist/reality-nosni.txt + reality-sni.txt');
}
main().catch(e => { console.error('FAILED:', e); process.exit(1); });
