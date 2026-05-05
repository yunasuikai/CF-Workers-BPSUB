import { connect } from 'cloudflare:sockets';

const authToken = '9e9fa47c-54e8-49e7-8064-d9bd0d6a5a0d';
let fallbackAddress = '';
const socks5Config = '';
const manualWorkerRegion = '';
const customPath = '';
const githubPreferredURL = 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';
const enableGitHubPreferred = true;
const enableOtherPreferred = true;
const apiBaseUrl = 'https://url.v1.mk/sub';

const MAX_CONN = 8, IDLE_MS = 90000;
const PAD_MIN = 64, PAD_MAX = 512, PAD_HDR = 0x0A;
const PAD_TINY = 128, PAD_SMALL = 1024, PAD_MED = 8192, PAD_LARGE = 65536;
const FRAME_BUCKETS = [256, 512, 1024, 1360, 2048, 4096, 8192, 16384];
// Timing jitter constants for realistic traffic patterns
const BURST_MIN = 5, BURST_MAX = 15, IDLE_MIN_MS = 50, IDLE_MAX_MS = 300;
const BACKPRESSURE_LIMIT = 262144; // 256KB pending threshold

const BLOCKED_UA = /crawl|spider|bot|scanner|detector|probe|httpclient|curl\/|wget\/|python-requests|masscan|nmap|zgrab|nikto|dirbuster|sqlmap|metasploit|burpsuite|headless/i;
const BLOCKED_PATH = /^\/\.env|^\/\.git|^\/wp-|^\/xmlrpc|^\/favicon|^\/robots\.txt|^\/sitemap|^\/\.well-known|^\/server-status|^\/admin|^\/config|^\/phpmy|^\/actuator|^\/\.svn|^\/shell|^\/cgi-bin/i;
const VALID_ORIGINS = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}/i;

const directDomains = [
 {name:"CA-Toronto",domain:"cloudflare.182682.xyz"},
 {name:"SG-Singapore",domain:"speed.marisalnc.com"},
 {name:"CN-Shanghai",domain:"freeyx.cloudflare88.eu.org"},
 {name:"CA-Toronto",domain:"bestcf.top"},
 {name:"CA-Toronto",domain:"cdn.2020111.xyz"},
 {name:"US-CouncilBluffs",domain:"cfip.cfcdn.vip"},
 {name:"CA-Toronto",domain:"cf.0sm.com"},
 {name:"CN-Beijing",domain:"cf.090227.xyz"},
 {name:"CN-HongKong",domain:"cf.zhetengsha.eu.org"},
 {name:"JP-Tokyo",domain:"cloudflare.9jy.cc"},
 {name:"UA-Kyiv",domain:"cf.zerone-cdn.pp.ua"},
 {name:"CA-Toronto",domain:"cfip.1323123.xyz"},
 {name:"CY-Nicosia",domain:"cnamefuckxxs.yuchen.icu"},
 {name:"CA-Toronto",domain:"cloudflare-ip.mofashi.ltd"},
 {name:"KR-Seoul",domain:"115155.xyz"},
 {name:"US-LosAngeles",domain:"cname.xirancdn.us"},
 {name:"DE-Frankfurt",domain:"f3058171cad.002404.xyz"},
 {name:"US-NewYork",domain:"8.889288.xyz"},
 {name:"CA-Toronto",domain:"cdn.tzpro.xyz"},
 {name:"CY-Nicosia",domain:"cf.877771.xyz"},
 {name:"CA-Toronto",domain:"xn--b6gac.eu.org"},
 { name: "宝岛正妹-1", domain: "165.154.226.214:27017" },
 { name: "宝岛正妹-2", domain: "60.251.232.240:995" },
 { name: "宝岛正妹-3", domain: "60.248.139.106:32770" },
 { name: "宝岛正妹-4", domain: "220.128.110.108:43" },
 { name: "宝岛正妹-5", domain: "114.32.9.249:16443" },
 { name: "宝岛正妹-6", domain: "60.248.139.106:10428" },
 { name: "宝岛正妹-7", domain: "60.248.139.106:23281" },
 { name: "宝岛正妹-8", domain: "60.248.139.106:12128" },
 { name: "宝岛正妹-9", domain: "60.248.139.106:11017" },
 { name: "宝岛正妹-10", domain: "114.32.9.249:51443" }
];

let enableRegionMatching = true;
let activeConns = 0;

const backupIPs = [
 { domain: 'ProxyIP.US.CMLiussss.net', regionCode: 'US', port: 443 },
 { domain: 'ProxyIP.SG.CMLiussss.net', regionCode: 'SG', port: 443 },
 { domain: 'ProxyIP.JP.CMLiussss.net', regionCode: 'JP', port: 443 },
 { domain: 'ProxyIP.HK.CMLiussss.net', regionCode: 'HK', port: 443 },
 { domain: 'ProxyIP.KR.CMLiussss.net', regionCode: 'KR', port: 443 },
 { domain: 'ProxyIP.DE.CMLiussss.net', regionCode: 'DE', port: 443 },
 { domain: 'ProxyIP.SE.CMLiussss.net', regionCode: 'SE', port: 443 },
 { domain: 'ProxyIP.NL.CMLiussss.net', regionCode: 'NL', port: 443 },
 { domain: 'ProxyIP.FI.CMLiussss.net', regionCode: 'FI', port: 443 },
 { domain: 'ProxyIP.GB.CMLiussss.net', regionCode: 'GB', port: 443 }
];

const rateLimiter = { count: 0, window: 0, WINDOW_MS: 60000, MAX_REQ: 120 };
const ipTracker = new Map();
const IP_MAX = 30, IP_WINDOW = 60000;

const hexT = Array.from({ length: 256 }, (_, i) => (i + 256).toString(16).slice(1));
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function fmtId(arr, o = 0) {
 const id = (hexT[arr[o]]+hexT[arr[o+1]]+hexT[arr[o+2]]+hexT[arr[o+3]]+'-'+hexT[arr[o+4]]+hexT[arr[o+5]]+'-'+hexT[arr[o+6]]+hexT[arr[o+7]]+'-'+hexT[arr[o+8]]+hexT[arr[o+9]]+'-'+hexT[arr[o+10]]+hexT[arr[o+11]]+hexT[arr[o+12]]+hexT[arr[o+13]]+hexT[arr[o+14]]+hexT[arr[o+15]]).toLowerCase();
 if (!UUID_RE.test(id)) throw new TypeError(atob('U3RyaW5naWZpZWQgaWRlbnRpZmllciBpcyBpbnZhbGlk'));
 return id;
}

const isValidFormat = uuid => UUID_RE.test(uuid);
function closeQ(s) { try { if (s.readyState === 1 || s.readyState === 2) s.close(); } catch {} }

function b64toArr(b) {
 if (!b) return { error: null };
 try { b = b.replace(/-/g, '+').replace(/_/g, '/'); return { earlyData: Uint8Array.from(atob(b), c => c.charCodeAt(0)).buffer, error: null }; }
 catch (e) { return { error: e }; }
}

function parseAddrPort(input) {
 if (!input) return { address: '', port: null };
 if (input.includes('[') && input.includes(']')) {
  const m = input.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (m) return { address: m[1], port: m[2] ? parseInt(m[2], 10) : null };
 }
 const i = input.lastIndexOf(':');
 if (i > 0) { const p = parseInt(input.substring(i + 1), 10); if (!isNaN(p) && p > 0 && p <= 65535) return { address: input.substring(0, i), port: p }; }
 return { address: input, port: null };
}

// Traffic shaping: normalize frame sizes to common web patterns
function normFrame(sz) {
 for (let i = 0; i < FRAME_BUCKETS.length; i++) {
  if (FRAME_BUCKETS[i] >= sz) { if (i > 0 && Math.random() < 0.3) return FRAME_BUCKETS[i - 1]; return FRAME_BUCKETS[i]; }
 }
 return sz;
}

// Adaptive padding — multi-tier traffic obfuscation
const padState = new WeakMap();
function addPadding(buf, ws = null) {
 const sz = buf.byteLength;
 const st = ws ? (padState.get(ws) || (() => { const s = { n: 0 }; padState.set(ws, s); return s; })()) : null;
 if (st) st.n++;
 // Tiny (DNS/control): always pad + normalize
 if (sz <= PAD_TINY) return _doPad(buf, normFrame(PAD_TINY + (Math.random() * PAD_TINY | 0)));
 // Small (handshake): always pad
 if (sz <= PAD_SMALL) return _doPad(buf, normFrame(sz + PAD_MIN + (Math.random() * (PAD_MAX - PAD_MIN) | 0)));
 // Medium: first 8 always, then 35%
 if (sz <= PAD_MED) { if (st && (st.n <= 8 || Math.random() < 0.35)) return _doPad(buf); return buf; }
 // Large streaming: first 3 always, then 15%
 if (st && (st.n <= 3 || Math.random() < 0.15)) return _doPad(buf);
 return buf;
}

function _doPad(buf, targetLen = 0) {
 const minP = targetLen > 0 ? Math.max(PAD_MIN, targetLen - buf.byteLength) : PAD_MIN;
 const maxP = targetLen > 0 ? minP + 64 : PAD_MAX;
 const len = minP + (Math.random() * (maxP - minP) | 0);
 const pad = new Uint8Array(len); crypto.getRandomValues(pad); pad[0] = PAD_HDR;
 new DataView(pad.buffer).setUint16(1, buf.byteLength, false);
 const out = new Uint8Array(3 + buf.byteLength + len);
 out.set(new Uint8Array(buf), 0); out[buf.byteLength] = PAD_HDR;
 new DataView(out.buffer).setUint16(buf.byteLength + 1, len, false);
 out.set(pad, buf.byteLength + 3);
 return out.buffer;
}

function stripPadding(buf) {
 const d = new Uint8Array(buf), tail = d.length - 1;
 // Quick check: decoy heartbeat (1 byte payload + padding)
 if (tail < 3 || d[tail - 2] !== PAD_HDR) return buf;
 const cl = new DataView(d.buffer).getUint16(tail - 1, false);
 if (cl >= PAD_MIN && cl <= PAD_MAX * 2 && tail + 1 === d.length) {
  // Skip decoy frames (payload ≤1 byte)
  if (tail - 2 <= 1) return new ArrayBuffer(0);
  return buf.slice(0, tail - 2);
 }
 for (let i = tail; i >= Math.max(0, d.length - PAD_MAX * 2 - 3); i--) {
  if (d[i - 2] === PAD_HDR) { const c2 = new DataView(d.buffer).getUint16(i - 1, false); if (i + c2 === d.length && i > 0) return buf.slice(0, i - 2); }
 }
 return buf;
}

// Burst/simulate traffic pattern: mimic real web browsing burst → idle → burst
const burstSt = new WeakMap();
function frameDelay(ws) {
 const st = burstSt.get(ws) || (() => { const s = { bc: 0, ib: true, ls: Date.now() }; burstSt.set(ws, s); return s; })();
 const now = Date.now();
 if (st.ib) {
  st.bc++;
  if (st.bc > BURST_MIN + (Math.random() * (BURST_MAX - BURST_MIN) | 0)) {
   st.ib = false; st.bc = 0; st.ls = now;
  }
  return 0;
 }
 const idle = IDLE_MIN_MS + (Math.random() * (IDLE_MAX_MS - IDLE_MIN_MS) | 0);
 if (now - st.ls < idle) return idle - (now - st.ls);
 st.ib = true; st.ls = now; return 0;
}

// Decoy heartbeat — occasional tiny frames during idle to mimic keepalive
const decoySt = new WeakMap();
function maybeDecoy(ws) {
 const st = decoySt.get(ws) || (() => { const s = { lastDecoy: Date.now() }; decoySt.set(ws, s); return s; })();
 const now = Date.now();
 if (now - st.lastDecoy > 30000 + (Math.random() * 30000 | 0)) {
  st.lastDecoy = now;
  if (ws.readyState === 1 && Math.random() < 0.4) {
   // Send tiny padded heartbeat frame to mask idle periods
   const hb = new Uint8Array(1); hb[0] = 0; ws.send(_doPad(hb.buffer, 0));
  }
 }
}
// Random WS protocol names — avoid fixed sec-websocket-protocol fingerprint
// Expanded pool with versioned protocols for more variety
const WS_PROTO_POOL = ['v2.json','graphql-ws','ocpp1.6','ocpp2.0','mqtt','mqttv5','stomp','socketio','srpc','grpc-web','wamp','fly.io','webwire','signalr'];
function randomWsProto() { return WS_PROTO_POOL[Math.floor(Math.random() * WS_PROTO_POOL.length)]; }
function extractEarlyData(proto) {
 if (!proto) return { earlyData: null, error: null };
 const parts = proto.split(',');
 for (const p of parts) { const r = b64toArr(p.trim()); if (r.earlyData) return r; }
 return { earlyData: null, error: null };
}

// Connection initiation delay — simulate real browser WS upgrade timing
const initDelaySt = new WeakMap();
function getInitJitter(ws) {
 const st = initDelaySt.get(ws) || (() => { const s = { delay: 20 + (Math.random() * 80 | 0) }; initDelaySt.set(ws, s); return s; })();
 return st.delay;
}

function checkRate(ip) {
 const now = Date.now();
 if (now - rateLimiter.window > rateLimiter.WINDOW_MS) { rateLimiter.count = 0; rateLimiter.window = now; }
 if (++rateLimiter.count > rateLimiter.MAX_REQ) return false;
 let ipE = ipTracker.get(ip);
 if (!ipE || now - ipE.window > IP_WINDOW) { ipE = { count: 0, window: now }; ipTracker.set(ip, ipE); }
 if (++ipE.count > IP_MAX) return false;
 if (ipTracker.size > 500) { for (const [k, v] of ipTracker) { if (now - v.window > IP_WINDOW) ipTracker.delete(k); } }
 return true;
}

async function dohResolve(hostname, type = 'A') {
 try {
  const r = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`, { headers: { 'Accept': 'application/dns-json' } });
  if (!r.ok) return null;
  const j = await r.json(); return j.Answer?.find(a => a.type === (type === 'A' ? 1 : 28))?.data || null;
 } catch { return null; }
}

function fakePage(status = 200) {
 const ts = Date.now(), dv = (ts / 1000 | 0).toString(36);
 const m = Array.from({length:6}, () => (Math.random()*99+.1).toFixed(1));
 const l = Array.from({length:6}, () => (Math.random()*200+5|0));
 const h = ['us-east-1','eu-west-2','ap-south-1','us-west-2','ap-northeast-1','eu-central-1'].sort(() => Math.random()-.5);
 return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>CloudDeck — Dashboard</title><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📊</text></svg>"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}.n{display:flex;justify-content:space-between;align-items:center;padding:1rem 2rem;border-bottom:1px solid #1e293b}.logo{font-size:1.25rem;font-weight:700;color:#38bdf8}.n a{color:#94a3b8;text-decoration:none;margin-left:1.5rem;font-size:.875rem}.h{padding:3rem 2rem;text-align:center}.h h1{font-size:2rem;margin-bottom:1rem;background:linear-gradient(135deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;padding:0 2rem 2rem;max-width:1100px;margin:0 auto}.c{background:#1e293b;border-radius:.75rem;padding:1.25rem;border:1px solid #334155}.c h3{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;margin-bottom:.4rem}.v{font-size:1.5rem;font-weight:700;color:#f1f5f9}.s{font-size:.7rem;color:#64748b;margin-top:.2rem}.lt{color:#38bdf8;font-weight:600}.sb{display:flex;gap:.75rem;padding:2rem;max-width:1100px;margin:0 auto;flex-wrap:wrap}.si{display:flex;align-items:center;gap:.5rem;font-size:.8rem;color:#94a3b8}.d{width:8px;height:8px;border-radius:50%;background:#22c55e}.dw{background:#f59e0b}.ft{padding:2rem;text-align:center;color:#475569;font-size:.75rem;border-top:1px solid #1e293b;margin-top:2rem}</style></head><body><nav class="n"><div class="logo">☁️ CloudDeck</div><div><a href="/status">Status</a><a href="/docs">Docs</a><a href="/api">API</a></div></nav><div class="h"><h1>Performance Dashboard</h1></div><div class="g"><div class="c"><h3>Requests</h3><div class="v">${m[0]}k/s</div><div class="s">current rate</div></div><div class="c"><h3>P99 Latency</h3><div class="v lt">${l[0]}ms</div><div class="s">99th percentile</div></div><div class="c"><h3>Errors</h3><div class="v">${m[2]}%</div><div class="s">5xx rate</div></div><div class="c"><h3>CPU</h3><div class="v">${m[3]}%</div><div class="s">cluster avg</div></div><div class="c"><h3>Memory</h3><div class="v">${m[4]}%</div><div class="s">utilization</div></div><div class="c"><h3>Uptime</h3><div class="v">99.${Math.random()*9|0}%</div><div class="s">30d SLA</div></div></div><div class="sb"><div class="si"><div class="d"></div>${h[0]} ok</div><div class="si"><div class="d"></div>${h[1]} ok</div><div class="si"><div class="d${Math.random()>.7?' dw':''}"></div>${h[2]} ${Math.random()>.7?'warn':'ok'}</div><div class="si"><div class="d"></div>${h[3]} ok</div><div class="si"><div class="d"></div>${h[4]} ok</div></div><footer class="ft">CloudDeck v${dv} · ${new Date().toISOString()} · <a href="/privacy" style="color:#64748b">Privacy</a></footer></body></html>`;
}

function fakeResp(s = 200) {
 return new Response(fakePage(s), {
 status: s,
 headers: {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'public, max-age=300',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Request-Id': crypto.randomUUID(),
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
  'X-RateLimit-Limit': '120', 'X-RateLimit-Remaining': '60',
  'Server': 'cloudflare',
  'CF-RAY': `${crypto.randomUUID().replace(/-/g,'').substring(0,16)}-IAD`,
  'Vary': 'Accept-Encoding',
  'ETag': `W/"${(Date.now()).toString(36)}"`,
  'X-Envoy-Upstream-Service-Time': `${Math.random()*50+1|0}`,
  'X-Powered-By': 'Next.js'
 }
 });
}

const REGION_MAP = {'US':'US','SG':'SG','JP':'JP','HK':'HK','KR':'KR','DE':'DE','SE':'SE','NL':'NL','FI':'FI','GB':'GB','CN':'HK','TW':'HK','AU':'SG','CA':'US','FR':'DE','IT':'DE','ES':'DE','CH':'DE','AT':'DE','BE':'NL','DK':'SE','NO':'SE','IE':'GB','IN':'SG','TH':'SG','MY':'SG','PH':'SG','ID':'SG','VN':'SG','NZ':'SG','PK':'SG','BD':'SG','MM':'SG','KH':'SG','LA':'SG'};
const NEARBY = {'US':['SG','JP','HK','KR'],'SG':['JP','HK','KR','US'],'JP':['SG','HK','KR','US'],'HK':['SG','JP','KR','US'],'KR':['JP','HK','SG','US'],'DE':['NL','GB','SE','FI'],'SE':['DE','NL','FI','GB'],'NL':['DE','GB','SE','FI'],'FI':['SE','DE','NL','GB'],'GB':['DE','NL','SE','FI']};
const ALL_R = ['US','SG','JP','HK','KR','DE','SE','NL','FI','GB'];

function detectRegion(req) { try { const c = req.cf?.country; return c && REGION_MAP[c] ? REGION_MAP[c] : 'HK'; } catch { return 'HK'; } }
function regionPriority(r) { const nb = NEARBY[r] || []; return [r, ...nb, ...ALL_R.filter(x => x !== r && !nb.includes(x))]; }
function smartSelect(wr, ips) { if (!enableRegionMatching || !wr) return ips; const p = regionPriority(wr); const s = []; for (const r of p) s.push(...ips.filter(ip => ip.regionCode === r)); return s; }

async function bestBackup(wr = '') {
 if (!backupIPs.length) return null;
 const avail = backupIPs.map(ip => ({ ...ip }));
 if (enableRegionMatching && wr) { const s = smartSelect(wr, avail); if (s.length) return s[0]; }
 return avail[0];
}

function isProbe(req) {
 const ua = req.headers.get('user-agent') || '';
 if (BLOCKED_UA.test(ua)) return true;
 const url = new URL(req.url);
 if (BLOCKED_PATH.test(url.pathname)) return true;
 if (/speed\.cloudflare|cparchive|cloudflare\.com\/cdn-cgi/i.test(req.headers.get('referer') || '')) return true;
 const accept = req.headers.get('accept') || '';
 if (!accept && req.method === 'GET') return true;
 const al = req.headers.get('accept-language') || '';
 if (ua && !al && req.method === 'GET') return true;
 if (/1\.1\s+\d+\.\d+\.\d+\.\d+/.test(req.headers.get('via') || '')) return true;
 if (ua.length > 0 && ua.length < 8) return true;
 if (/[?&](debug|test|probe|check|verify)=/i.test(url.search)) return true;
 if (req.method === 'GET') { const sd = req.headers.get('sec-fetch-dest') || '', sm = req.headers.get('sec-fetch-mode') || ''; if (!sd && !sm && ua.includes('Mozilla')) return true; }
 return false;
}

function parseHeader(chunk, token) {
 if (chunk.byteLength < 24) return { hasError: true, message: atob('aW52YWxpZCBkYXRh') };
 const ver = new Uint8Array(chunk.slice(0, 1));
 try { if (fmtId(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: atob('aW52YWxpZCB1c2Vy') }; }
 catch { return { hasError: true, message: atob('aW52YWxpZCB1c2Vy') }; }
 const optLen = new Uint8Array(chunk.slice(17, 18))[0];
 const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
 let isUDP = cmd === 2;
 if (cmd !== 1 && !isUDP) return { hasError: true, message: atob('Y29tbWFuZCBpcyBub3Qgc3VwcG9ydGVk') };
 const pi = 19 + optLen, port = new DataView(chunk.slice(pi, pi + 2)).getUint16(0);
 let ai = pi + 2, al = 0, avi = ai + 1, host = '';
 const at = new Uint8Array(chunk.slice(ai, avi))[0];
 if (at === 1) { al = 4; host = new Uint8Array(chunk.slice(avi, avi + al)).join('.'); }
 else if (at === 2) { al = new Uint8Array(chunk.slice(avi, avi + 1))[0]; avi += 1; host = new TextDecoder().decode(chunk.slice(avi, avi + al)); }
 else if (at === 3) { al = 16; const v6 = [], dv = new DataView(chunk.slice(avi, avi + al)); for (let i = 0; i < 8; i++) v6.push(dv.getUint16(i * 2).toString(16)); host = v6.join(':'); }
 else return { hasError: true, message: `${atob('aW52YWxpZCBhZGRyZXNzVHlwZQ==')}: ${at}` };
 if (!host) return { hasError: true, message: `${atob('YWRkcmVzc1ZhbHVlIGlzIGVtcHR5')}: ${at}` };
 return { hasError: false, addressType: at, port, hostname: host, isUDP, rawIndex: avi + al, version: ver };
}

function makeReadable(sock, earlyData) {
 let stop = false;
 return new ReadableStream({
 start(ctrl) {
  sock.addEventListener('message', e => { if (!stop) ctrl.enqueue(e.data); });
  sock.addEventListener('close', () => { if (!stop) { closeQ(sock); ctrl.close(); } });
  sock.addEventListener('error', e => ctrl.error(e));
  if (earlyData) ctrl.enqueue(earlyData);
 },
 cancel() { stop = true; closeQ(sock); }
 });
}

// Backpressure-aware pipe with burst pattern + decoy heartbeat
async function pipeStreams(remote, ws, hdr, retry) {
 let h = hdr, ok = false, pending = 0;
 await remote.readable.pipeTo(new WritableStream({
  async write(chunk, ctrl) {
   ok = true;
   if (ws.readyState !== 1) ctrl.error(atob('d2ViU29ja2V0LmVhZHlTdGF0ZSBpcyBub3Qgb3Blbg=='));
   const sz = chunk.byteLength;
   if (pending + sz > BACKPRESSURE_LIMIT) await new Promise(r => setTimeout(r, 1));
   pending += sz;
   const padded = addPadding(chunk, ws);
   const d = frameDelay(ws);
   if (d > 0) await new Promise(r => setTimeout(r, d));
   if (h) { ws.send(await new Blob([h, padded]).arrayBuffer()); h = null; }
   else ws.send(padded);
   pending = Math.max(0, pending - sz);
   // Decoy heartbeat during idle periods
   maybeDecoy(ws);
  },
  abort(r) { console.error('Pipe abort:', r); }
 })).catch(e => { console.error('Pipe err:', e); closeQ(ws); });
 if (!ok && retry) retry();
}

async function fwdTCP(host, port, raw, ws, hdr, rcw, fb, wr) {
 async function dial(addr, p) {
  if (socks5Config) {
   const sp = parseAddrPort(socks5Config);
   const s = connect({ hostname: sp.address, port: sp.port || 1080 });
   const w = s.writable.getWriter();
   w.write(new Uint8Array([0x05, 0x01, 0x00]));
   const de = new TextEncoder().encode(addr);
   w.write(new Uint8Array([0x05, 0x01, 0x00, 0x03, de.length, ...de, p >> 8, p & 0xFF]));
   w.releaseLock(); return s;
  }
  const s = connect({ hostname: addr, port: p });
  const w = s.writable.getWriter();
  await w.write(raw); w.releaseLock(); return s;
 }
 async function retry() {
  let fh, fp;
  if (fb?.trim()) { const p = parseAddrPort(fb); fh = p.address; fp = p.port || port; }
  else { const b = await bestBackup(wr); fh = b ? b.domain : host; fp = b ? b.port : port; }
  const s = await dial(fh || host, fp);
  rcw.socket = s;
  s.closed.catch(() => {}).finally(() => closeQ(ws));
  pipeStreams(s, ws, hdr, null);
 }
 try { const s = await dial(host, port); rcw.socket = s; pipeStreams(s, ws, hdr, retry); }
 catch { retry(); }
}

async function fwdDNS(chunk, ws, hdr) {
 try {
  const s = connect({ hostname: '1.1.1.1', port: 53 });
  let vh = hdr;
  const w = s.writable.getWriter();
  const lb = new Uint8Array(2); new DataView(lb.buffer).setUint16(0, chunk.byteLength);
  await w.write(lb.buffer); await w.write(chunk); w.releaseLock();
  await s.readable.pipeTo(new WritableStream({
   async write(c) {
    if (ws.readyState !== 1) return;
    const d = c.byteLength > 2 ? c.slice(2) : c;
    const padded = addPadding(d, ws);
    if (vh) { ws.send(await new Blob([vh, padded]).arrayBuffer()); vh = null; } else ws.send(padded);
   }
  }));
 } catch (e) {
  console.error('DNS TCP err, DoH fallback:', e.message);
  try {
   const dv = new DataView(chunk), qn = []; let off = 12;
   while (off < chunk.byteLength) { const l = new Uint8Array(chunk)[off]; if (l === 0) break; off++; qn.push(new TextDecoder().decode(chunk.slice(off, off + l))); off += l; }
   const domain = qn.join('.'), qt = dv.getUint16(off + 1);
   const resolved = await dohResolve(domain, qt === 28 ? 'AAAA' : 'A');
   if (resolved && vh) { ws.send(await new Blob([vh, addPadding(buildFakeDNS(chunk, resolved), ws)]).arrayBuffer()); vh = null; }
  } catch (e2) { console.error('DoH fallback err:', e2.message); }
 }
}

function buildFakeDNS(query, answer) {
 const q = new Uint8Array(query);
 const rsp = new Uint8Array(query.byteLength + 16);
 rsp.set(q, 0);
 const v = new DataView(rsp.buffer);
 v.setUint16(2, 0x8180); v.setUint16(6, 1);
 const a = query.byteLength;
 rsp[a] = 0xC0; rsp[a+1] = 0x0C;
 v.setUint16(a+2, q[q.length-3] === 28 ? 28 : 1);
 v.setUint16(a+4, 1); v.setUint32(a+6, 300);
 if (q[q.length-3] === 28) { v.setUint16(a+10, 16); }
 else { v.setUint16(a+10, 4); const ip = answer.split('.'); for (let i = 0; i < 4; i++) rsp[a+12+i] = +ip[i]; }
 return rsp.buffer.slice(0, a + (q[q.length-3] === 28 ? 28 : 16));
}

async function handleWs(req, fb, wr) {
 const pair = new WebSocketPair();
 const [cli, srv] = Object.values(pair);
 srv.accept();
 let rcw = { socket: null }, isDNS = false;
 if (activeConns >= MAX_CONN) { srv.close(1013); return new Response(null, { status: 101, webSocket: cli }); }
 activeConns++;
 const jIdle = IDLE_MS * (0.8 + Math.random() * 0.4);
 let timer = setTimeout(() => { closeQ(srv); if (rcw.socket) closeQ(rcw.socket); }, jIdle);
 function resetTimer() { clearTimeout(timer); timer = setTimeout(() => { closeQ(srv); if (rcw.socket) closeQ(rcw.socket); }, IDLE_MS * (0.8 + Math.random() * 0.4)); }
 const wsProto = req.headers.get('sec-websocket-protocol') || '';
 const { earlyData, error } = extractEarlyData(wsProto);
 // Simulate browser WS connection setup time
 const initJitter = getInitJitter(srv);
 makeReadable(srv, earlyData).pipeTo(new WritableStream({
  async write(chunk) {
   // Apply init delay on first frame only
   if (initJitter > 0) { await new Promise(r => setTimeout(r, initJitter)); initDelaySt.get(srv).delay = 0; }
   resetTimer();
   const clean = stripPadding(chunk);
   // Skip decoy heartbeat frames (empty after strip)
   if (clean.byteLength === 0) return;
   if (isDNS) return fwdDNS(clean, srv, null);
   if (rcw.socket) { const w = rcw.socket.writable.getWriter(); await w.write(clean); w.releaseLock(); return; }
   const p = parseHeader(clean, authToken);
   if (p.hasError) throw new Error(p.message);
   if (p.isUDP) { if (p.port === 53) isDNS = true; else throw new Error(atob('VURQIHByb3h5IG9ubHkgZW5hYmxlIGZvciBETlMgd2hpY2ggaXMgcG9ydCA1Mw==')); }
   const rh = new Uint8Array([p.version[0], 0]);
   const raw = clean.slice(p.rawIndex);
   if (isDNS) return fwdDNS(raw, srv, rh);
   await fwdTCP(p.hostname, p.port, raw, srv, rh, rcw, fb, wr);
  },
 })).catch(e => console.log('WS err:', e)).finally(() => { activeConns--; clearTimeout(timer); });
 return new Response(null, { status: 101, webSocket: cli });
}

function genLinks(list, uuid, dom) {
 const pt = crypto.randomUUID().replace(/-/g, '').substring(0, 8);
 return list.map(item => {
  const ip = item.ip.includes(':') ? `[${item.ip}]` : item.ip;
  const q = new URLSearchParams({ encryption:'none',security:'tls',sni:dom,fp:'randomized',type:'ws',host:dom,path:`/${pt}?ed=2048` });
  return `vless://${uuid}@${ip}:443?${q}#${encodeURIComponent((item.isp||item.name||item.ip).replace(/\s/g,'_')+'-443-WS-TLS')}`;
 });
}

async function fetchNewIPs() {
 try {
  const r = await fetch(githubPreferredURL);
  if (!r.ok) return [];
  const lines = (await r.text()).trim().replace(/\r/g, '').split('\n');
  const res = [], re = /^([^:]+):(\d+)#(.*)$/;
  for (const l of lines) { const t = l.trim(); if (!t) continue; const m = t.match(re); if (m) res.push({ ip: m[1], port: +m[2], name: m[3].trim() || m[1] }); }
  return res;
 } catch { return []; }
}

async function subReq(req, uuid, url) {
 if (!url) url = new URL(req.url);
 const links = [], dom = url.hostname;
 links.push(...genLinks([{ ip: dom, isp: '原生地址' }], uuid, dom));
 if (enableOtherPreferred) links.push(...genLinks(directDomains.map(d => ({ ip: d.domain, isp: d.name || d.domain })), uuid, dom));
 if (enableGitHubPreferred) { const n = await fetchNewIPs(); if (n.length) links.push(...genLinks(n, uuid, dom)); }
 if (!links.length) links.push(`vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=ws&host=error.com&path=%2F#${encodeURIComponent('所有节点获取失败')}`);
 return new Response(btoa(links.join('\n')), { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
}

async function subPage(req, uuid = null) {
 uuid = uuid || authToken;
 const h = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>订阅中心</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}.c{max-width:800px;margin:0 auto;padding:2rem}h1{text-align:center;margin-bottom:2rem;background:linear-gradient(135deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.cd{background:#1e293b;border-radius:.75rem;padding:1.5rem;margin-bottom:1rem;border:1px solid #334155}.cd h2{font-size:1rem;color:#94a3b8;margin-bottom:1rem}.bg{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:.5rem}.b{background:#334155;border:1px solid #475569;border-radius:.5rem;padding:.6rem;color:#e2e8f0;cursor:pointer;text-align:center;font-size:.8rem}.b:hover{background:#475569}.ub{background:#0f172a;border:1px solid #334155;border-radius:.5rem;padding:.75rem;word-break:break-all;margin-top:.75rem;display:none;font-family:monospace;font-size:.75rem;color:#38bdf8}</style></head><body><div class="c"><h1>📊 订阅中心</h1><div class="cd"><h2>选择客户端</h2><div class="bg"><button class="b" onclick="g('clash','CLASH')">CLASH</button><button class="b" onclick="g('surge','SURGE')">SURGE</button><button class="b" onclick="g('singbox','SING-BOX')">SING-BOX</button><button class="b" onclick="g('loon','LOON')">LOON</button><button class="b" onclick="g('quanx','QX')">QX</button><button class="b" onclick="g('v2ray','V2RAY')">V2RAY</button><button class="b" onclick="g('v2ray','Shadowrocket')">Shadowrocket</button><button class="b" onclick="g('v2ray','V2RAYNG')">V2RAYNG</button></div><div class="ub" id="u1"></div></div><div class="cd"><h2>快速获取</h2><button class="b" onclick="gs()" style="width:100%">获取订阅</button><div class="ub" id="u2"></div></div></div><script>var A="${apiBaseUrl}";function g(t,n){var u=location.href+"sub",f=t==="v2ray"?"":`&app=${t}`,s=encodeURIComponent(n),u2=u.includes("?")?u+f:u+"?app="+t;fetch(A+"?target="+t+"&url="+encodeURIComponent(btoa(u2))+"&insert=false&emoji=true&list=false&udp=true&tfo=true&scv=true&fdn=false&sort=false&expand=true&scv=true"+f).then(r=>r.text()).then(d=>{var el=document.getElementById("u1");el.style.display="block";el.textContent=d||"获取失败";}).catch(()=>{var el=document.getElementById("u1");el.style.display="block";el.textContent="请求失败";});}function gs(){var u=location.href+"sub",el=document.getElementById("u2");el.style.display="block";el.textContent=u;el.onclick=function(){navigator.clipboard.writeText(u).then(()=>{el.textContent="已复制!";setTimeout(()=>{el.textContent=u;},2000);});};}</script></body></html>`;
 return new Response(h, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

export default {
 async fetch(request, env, ctx) {
 try {
  const ip = request.headers.get('cf-connecting-ip') || '0.0.0.0';
  if (!checkRate(ip)) return new Response('429 Too Many Requests', { status: 429, headers: { 'Retry-After': '60', 'Content-Type': 'text/plain' } });
  const url = new URL(request.url);
  const wr = manualWorkerRegion?.trim() ? manualWorkerRegion.trim().toUpperCase() : detectRegion(request);
  if (isProbe(request)) return fakeResp(404);
  let fb = fallbackAddress;
  if (!fb && wr) { const b = await bestBackup(wr); if (b) fb = b.domain + ':' + b.port; }
  if (request.headers.get('Upgrade') === 'websocket') {
   const ua = request.headers.get('user-agent') || '';
   if (!ua || ua.length < 10) return fakeResp(403);
   const accept = request.headers.get('accept') || '';
   if (!accept.includes('text/html') && !accept.includes('*/*')) return fakeResp(403);
   const origin = request.headers.get('origin') || '';
   if (origin && !VALID_ORIGINS.test(origin)) return fakeResp(403);
   return await handleWs(request, fb, wr);
  }
  if (request.method === 'GET') {
   if (url.pathname === '/') return fakeResp(200);
   if (url.pathname === '/favicon.ico') return new Response(null, { status: 204 });
   if (url.pathname === '/privacy' || url.pathname === '/terms' || url.pathname === '/status') return fakeResp(200);
   if (customPath?.trim()) {
    const cp = '/' + customPath.trim().replace(/^\/+/, '').replace(/\/+$/, '');
    const np = url.pathname.replace(/\/+$/, '');
    if (np === cp) return await subPage(request, authToken);
    if (np === cp + '/sub') return await subReq(request, authToken, url);
    return fakeResp(404);
   }
   const seg = url.pathname.replace(/\/+$/, '').substring(1);
   if (seg && !url.pathname.includes('/sub')) {
    if (isValidFormat(seg)) { if (seg === authToken) return await subPage(request, seg); return fakeResp(403); }
   }
   if (url.pathname.includes('/sub')) {
    const parts = url.pathname.split('/');
    if (parts.length === 2 && parts[1] === 'sub') {
     const uuid = parts[0].substring(1);
     if (isValidFormat(uuid)) { if (uuid === authToken) return await subReq(request, uuid, url); return fakeResp(403); }
    }
   }
   if (url.pathname.toLowerCase().includes('/' + authToken)) return await subReq(request, authToken);
   return fakeResp(404);
  }
  return fakeResp(405);
 } catch { return fakeResp(500); }
 }
};
