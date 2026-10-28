import { promises as fs } from 'node:fs';
import { spawn, execFile } from 'node:child_process';
import net from 'node:net';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const env = (key, fallback) =>
  (process.env[key] || fallback)
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);

const CF_IPS = env(
  'CF_IPS',
  '104.18.37.127,x.com,www.getlucky.com,104.18.36.146,172.64.150.129,172.64.151.110,canary-proxsee-cf.pscp.tv,game01.circus.nl,104.18.41.245,185.199.108.153,api.server.io,104.16.132.229'
);

const SOURCES = env(
  'SOURCES',
  [
    'https://github.com/0xRadikal/Free-v2ray-Configs/raw/refs/heads/main/all/configs.txt',
    'https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt',
    'https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/subscriptions/mix-normal.txt',
    'https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt',
    'https://github.com/YawStar/Proxy-Hunter/raw/refs/heads/main/configs/proxy_configs.txt',
    'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/tls.txt',
    'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/all.txt',
    'https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity'
  ].join(',')
);

const OUT = 'dist';
const MAX_OUT = 200;
const MAX_TEST = Number(process.env.MAX_TEST || 1000);
const CONC = 8;
const TIMEOUT = 9000;
const TEST_URL = 'https://www.google.com/generate_204';

let tested = 0;
let nextPort = 21000;

function decodeBase64(value) {
  try {
    const normalized = value
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    return Buffer.from(normalized, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function decodeCredentials(rawUserinfo) {
  let value;

  try {
    value = decodeURIComponent(rawUserinfo);
  } catch {
    value = rawUserinfo;
  }

  if (value.includes(':')) {
    const index = value.indexOf(':');
    return {
      method: value.slice(0, index),
      password: value.slice(index + 1)
    };
  }

  const decoded = decodeBase64(value);
  const index = decoded.indexOf(':');

  if (index <= 0) return null;

  return {
    method: decoded.slice(0, index),
    password: decoded.slice(index + 1)
  };
}

function parseSS(line) {
  const raw = (line || '').trim();

  if (!raw.startsWith('ss://') || raw.length > 2000) {
    return null;
  }

  let url;

  try {
    url = new URL(raw);
  } catch {
    return null;
  }

  if (url.protocol !== 'ss:' || url.port !== '443') {
    return null;
  }

  const plugin = url.searchParams.get('plugin') || '';
  if (!plugin) return null;

  const parts = plugin.split(';');
  const pluginName = parts.shift().trim().toLowerCase();
  const options = parts.filter(Boolean);

  const hasTLS = options.some(option =>
    option.toLowerCase() === 'tls'
  );

  const mode = options.find(option =>
    option.toLowerCase().startsWith('mode=')
  );

  // v2ray-plugin uses WebSocket by default.
  // Do not mistake QUIC or another transport for WebSocket.
  if (!hasTLS) return null;

  if (
    mode &&
    !['mode=websocket', 'mode=ws'].includes(mode.toLowerCase())
  ) {
    return null;
  }

  const hostOption = options.find(option =>
    option.toLowerCase().startsWith('host=')
  );

  const sni = hostOption
    ? hostOption.slice(hostOption.indexOf('=') + 1).trim()
    : url.hostname;

  if (!sni || !url.hostname) return null;

  const credentials = decodeCredentials(url.username);

  if (!credentials?.method || !credentials.password) {
    return null;
  }

  // Only test plugins actually installed by this workflow.
  // Other plugin implementations must not be reported as tested.
  if (pluginName !== 'v2ray-plugin') {
    return null;
  }

  return {
    raw,
    url,
    originalHost: url.hostname,
    method: credentials.method,
    password: credentials.password,
    plugin,
    pluginName,
    options,
    sni,
    remark: decodeURIComponentSafe(url.hash.slice(1)) || sni
  };
}

function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function chooseRandomIp() {
  return CF_IPS[Math.floor(Math.random() * CF_IPS.length)];
}

function rebuildLink(entry, server, delay) {
  const url = new URL(entry.raw);

  url.hostname = server;
  url.port = '443';
  url.hash = encodeURIComponent(`${entry.remark} | ${delay}ms`);

  return url.toString();
}

function waitForPort(port, child, timeout = 4000) {
  return new Promise(resolve => {
    const started = Date.now();

    function attempt() {
      if (child.exitCode !== null) {
        resolve(false);
        return;
      }

      const socket = net.connect({
        host: '127.0.0.1',
        port
      });

      let finished = false;

      const done = result => {
        if (finished) return;
        finished = true;
        socket.destroy();

        if (result) {
          resolve(true);
        } else if (Date.now() - started >= timeout) {
          resolve(false);
        } else {
          setTimeout(attempt, 100);
        }
      };

      socket.setTimeout(300);
      socket.once('connect', () => done(true));
      socket.once('error', () => done(false));
      socket.once('timeout', () => done(false));
    }

    attempt();
  });
}

async function realTest(entry, server) {
  const port = nextPort++;
  const pluginOptions = entry.options.join(';');

  const args = [
    '-s', server,
    '-p', '443',
    '-m', entry.method,
    '-k', entry.password,
    '-b', '127.0.0.1',
    '-l', String(port),
    '-t', '8',
    '--plugin', 'v2ray-plugin',
    '--plugin-opts', pluginOptions
  ];

  const child = spawn('ss-local', args, {
    stdio: 'ignore'
  });

  try {
    const ready = await waitForPort(port, child);

    if (!ready) return null;

    const start = Date.now();

    const { stdout } = await execFileAsync(
      'curl',
      [
        '--silent',
        '--show-error',
        '--output', '/dev/null',
        '--write-out', '%{http_code}',
        '--connect-timeout', '4',
        '--max-time', '8',
        '--socks5-hostname', `127.0.0.1:${port}`,
        TEST_URL
      ],
      {
        timeout: TIMEOUT + 1000,
        maxBuffer: 1024 * 1024
      }
    );

    const delay = Date.now() - start;
    const status = Number(stdout.trim());

    if (status < 200 || status >= 400) return null;

    return delay;
  } catch {
    return null;
  } finally {
    child.kill('SIGTERM');

    setTimeout(() => {
      if (child.exitCode === null) {
        child.kill('SIGKILL');
      }
    }, 300).unref();
  }
}

async function pool(items, concurrency, fn) {
  const results = new Array(items.length);
  let index = 0;

  await Promise.all(
    Array.from(
      { length: Math.min(concurrency, items.length) },
      async () => {
        while (true) {
          const current = index++;

          if (current >= items.length) return;

          try {
            results[current] = await fn(items[current]);
          } catch {
            results[current] = null;
          }
        }
      }
    )
  );

  return results;
}

async function getText(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'user-agent': 'NeverStops-Config-Collector/1.0'
      }
    });

    if (!response.ok) {
      console.log(`[!] Source HTTP ${response.status}: ${url}`);
      return null;
    }

    return await response.text();
  } catch {
    console.log(`[!] Source failed: ${url}`);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function expandText(text) {
  const trimmed = text.trim();

  if (!trimmed) return [];

  // Decode a subscription only when it looks like Base64,
  // rather than decoding ordinary plain-text configurations.
  if (!trimmed.includes('://') && /^[A-Za-z0-9+/_=-]+$/.test(trimmed)) {
    const decoded = decodeBase64(trimmed);

    if (decoded.includes('ss://')) {
      return decoded.split(/\r?\n/);
    }
  }

  return trimmed.split(/\r?\n/);
}

async function main() {
  await fs.mkdir(OUT, { recursive: true });

  console.log(`[+] Sources: ${SOURCES.length}`);
  console.log(`[+] Replacement addresses: ${CF_IPS.length}`);

  const texts = (await Promise.all(SOURCES.map(getText)))
    .filter(Boolean);

  console.log(`[+] Sources downloaded: ${texts.length}/${SOURCES.length}`);

  if (!texts.length) {
    throw new Error('No source could be downloaded');
  }

  const lines = texts.flatMap(expandText);
  const unique = [];
  const seen = new Set();

  for (const line of lines) {
    const entry = parseSS(line);

    if (!entry) continue;

    const key = [
      entry.method,
      entry.password,
      entry.originalHost,
      entry.plugin
    ].join('|');

    if (seen.has(key)) continue;

    seen.add(key);
    unique.push(entry);
  }

  console.log(`[+] Unique compatible SS+WS+TLS+443: ${unique.length}`);

  const candidates = unique.slice(0, MAX_TEST);
  const live = [];

  await pool(candidates, CONC, async entry => {
    const server = chooseRandomIp();
    const delay = await realTest(entry, server);

    const count = ++tested;

    if (count % 25 === 0 || count === candidates.length) {
      console.log(`[+] Tested ${count}/${candidates.length}; working: ${live.length}`);
    }

    if (delay !== null) {
      live.push({
        entry,
        server,
        delay
      });
    }
  });

  live.sort((a, b) => a.delay - b.delay);

  const finalLinks = live
    .slice(0, MAX_OUT)
    .map(item =>
      rebuildLink(item.entry, item.server, item.delay)
    );

  await fs.writeFile(
    `${OUT}/ss-ws.txt`,
    finalLinks.length ? `${finalLinks.join('\n')}\n` : '',
    'utf8'
  );

  console.log(`[+] Successful real HTTP tests: ${live.length}`);
  console.log(`[✓] Wrote ${finalLinks.length} links to ${OUT}/ss-ws.txt`);
}

main().catch(error => {
  console.error('FAILED:', error);
  process.exitCode = 1;
});
