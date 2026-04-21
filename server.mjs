import fs from 'node:fs';
import http2 from 'node:http2';
import https from 'node:https';
import { randomBytes } from 'node:crypto';

try { process.loadEnvFile(); } catch {}

const TARGET = new URL('https://preview-p22655-e59433.adobeaemcloud.com/');
const PORT = process.env.PORT || 3000;
const SSL_CERT = process.env.SSL_CERT;
const SSL_KEY = process.env.SSL_KEY;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const SCOPES = process.env.SCOPES;
const TOKEN_ENDPOINT = process.env.TOKEN_ENDPOINT || 'https://ims-na1.adobelogin.com/ims/token/v3';
const LOG_LEVEL = (process.env.LOG_LEVEL || 'debug').toLowerCase();
const LOG_CURL = !['0', 'false', 'no', 'off'].includes((process.env.LOG_CURL ?? 'true').toLowerCase());

if (!SSL_CERT || !SSL_KEY) {
  console.error('SSL_CERT and SSL_KEY environment variables are required (paths to PEM files)');
  process.exit(1);
}
if (!CLIENT_ID || !CLIENT_SECRET || !SCOPES) {
  console.error('CLIENT_ID, CLIENT_SECRET and SCOPES are required for IMS S2S token mint');
  process.exit(1);
}

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const ACTIVE_LEVEL = LEVELS[LOG_LEVEL] ?? LEVELS.debug;

// Downstream Cache-Control policy: the browser is the real cache.
// - Short max-age: freshness commitment.
// - Long stale-while-revalidate: near-instant perceived latency; the browser
//   serves the stale body immediately and revalidates in the background.
// - stale-if-error: keep serving stale briefly if upstream blips.
// Browser revalidation is cheap because ETag / Last-Modified pass through
// unchanged, so background refreshes are usually 304s.
const STAGE_CACHE_CONTROL =
  'public, max-age=15, stale-while-revalidate=604800, stale-if-error=604800';
const BYPASS_CACHE_CONTROL = 'no-store';

const SENSITIVE_HEADER_KEYS = new Set(['authorization', 'proxy-authorization']);
const OMIT_FROM_LOG = new Set(['cookie', 'set-cookie']);

function redactHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const lk = k.toLowerCase();
    if (OMIT_FROM_LOG.has(lk)) continue;
    out[k] = SENSITIVE_HEADER_KEYS.has(lk) ? '[REDACTED]' : v;
  }
  return out;
}

function stripResponseCookies(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === 'set-cookie') continue;
    out[k] = v;
  }
  return out;
}

function dropHeaders(headers, names) {
  const drop = new Set(names.map((n) => n.toLowerCase()));
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (drop.has(k.toLowerCase())) continue;
    out[k] = v;
  }
  return out;
}

function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

function buildCurl(method, path, headers) {
  const url = new URL(path, TARGET.origin).toString();
  const parts = [`curl -X ${method} ${shellQuote(url)}`];
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (lk === 'host' || lk === 'content-length') continue;
    parts.push(`  -H ${shellQuote(`${k}: ${v}`)}`);
  }
  return parts.join(' \\\n');
}

function logCurl(reqId, method, path, headers) {
  if (!LOG_CURL || LEVELS.debug > ACTIVE_LEVEL) return;
  console.log(`${new Date().toISOString()} [DEBUG] upstream curl reqId=${reqId}`);
  console.log(buildCurl(method, path, headers));
}

function log(level, msg, ctx) {
  if ((LEVELS[level] ?? 99) > ACTIVE_LEVEL) return;
  const line = `${new Date().toISOString()} [${level.toUpperCase()}] ${msg}`;
  if (ctx && Object.keys(ctx).length) {
    console.log(line, JSON.stringify(ctx));
  } else {
    console.log(line);
  }
}

const tlsOptions = {
  cert: fs.readFileSync(SSL_CERT),
  key: fs.readFileSync(SSL_KEY),
};

// Persistent TCP+TLS pool to upstream. Critical now that the browser does
// most caching: every browser SWR revalidation still traverses the proxy,
// and paying a handshake per 304 would dominate latency.
const upstreamAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 30_000,
  maxSockets: 64,
});

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host',
]);

// Headers from the incoming client request that must NOT be forwarded upstream:
//  - cookie / authorization: scoped to this proxy, useless (and large) to AEM;
//    we set our own Authorization below.
//  - cache-control / pragma: a mode signal for this proxy, not a directive
//    for AEM; AEM should decide caching on its own.
//  - sec-ch-* / sec-fetch-* / upgrade-insecure-requests / dnt / priority:
//    browser fetch metadata AEM doesn't use and that causes HTTP 431.
//  - referer / origin: point at this proxy, not upstream.
// Note: If-None-Match / If-Modified-Since are intentionally *not* dropped —
// they're the browser's conditional revalidation and must flow through.
const DROP_FROM_UPSTREAM = new Set([
  'cookie', 'authorization',
  'cache-control', 'pragma',
  'referer', 'origin',
  'upgrade-insecure-requests', 'dnt', 'priority',
  'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-ch-ua-arch',
  'sec-ch-ua-bitness', 'sec-ch-ua-full-version', 'sec-ch-ua-full-version-list',
  'sec-ch-ua-model', 'sec-ch-ua-platform-version', 'sec-ch-ua-wow64',
  'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
]);

const REFRESH_SKEW_MS = 5 * 60 * 1000;

let tokenCache = null;
let tokenInFlight = null;

async function mintToken() {
  log('info', 'token mint: requesting', { endpoint: TOKEN_ENDPOINT, scopes: SCOPES });
  const start = Date.now();
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: SCOPES,
  });
  const res = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const durationMs = Date.now() - start;
  if (!res.ok) {
    const text = await res.text();
    log('error', 'token mint: failed', { status: res.status, durationMs, body: text.slice(0, 500) });
    throw new Error(`Token request failed: ${res.status}`);
  }
  const data = await res.json();
  const expiresInSec = data.expires_in ?? 3600;
  log('info', 'token mint: success', { expiresInSec, durationMs });
  return { token: data.access_token, expiresAt: Date.now() + expiresInSec * 1000 - REFRESH_SKEW_MS };
}

async function getToken() {
  if (tokenCache && tokenCache.expiresAt > Date.now()) return tokenCache.token;
  if (!tokenInFlight) {
    log('debug', 'token cache miss, minting');
    tokenInFlight = mintToken()
      .then((t) => { tokenCache = t; return t.token; })
      .finally(() => { tokenInFlight = null; });
  }
  return tokenInFlight;
}

function parseMaxAge(headerValue) {
  if (!headerValue) return 0;
  const value = Array.isArray(headerValue) ? headerValue.join(',') : headerValue;
  const match = /(?:^|[,\s])max-age\s*=\s*(\d+)/i.exec(value);
  if (!match) return 0;
  const n = parseInt(match[1], 10);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n;
}

async function buildUpstreamHeaders(req) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const lk = k.toLowerCase();
    if (lk.startsWith(':')) continue;
    if (HOP_BY_HOP.has(lk) || DROP_FROM_UPSTREAM.has(lk)) continue;
    headers[k] = v;
  }
  headers['host'] = TARGET.host;
  headers['authorization'] = `Bearer ${await getToken()}`;
  return headers;
}

async function handleRequest(reqId, req, res, mode) {
  const headers = await buildUpstreamHeaders(req);
  const upstreamStart = Date.now();
  log('debug', 'upstream request', { reqId, method: req.method, path: req.url, mode });
  logCurl(reqId, req.method, req.url, headers);

  const proxyReq = https.request({
    hostname: TARGET.hostname,
    port: TARGET.port || 443,
    path: req.url,
    method: req.method,
    headers,
    agent: upstreamAgent,
  }, (proxyRes) => {
    log('info', 'upstream response', {
      reqId, status: proxyRes.statusCode,
      durationMs: Date.now() - upstreamStart,
      contentLength: proxyRes.headers['content-length'], mode,
    });
    // Override upstream Cache-Control: the proxy, not AEM, decides what the
    // browser should do with these responses. ETag / Last-Modified pass
    // through unchanged so browser conditional revalidation keeps working.
    const cacheControl = mode === 'stage' ? STAGE_CACHE_CONTROL : BYPASS_CACHE_CONTROL;
    const outHeaders = dropHeaders(stripResponseCookies(proxyRes.headers), [
      'cache-control', ...HOP_BY_HOP,
    ]);
    outHeaders['Cache-Control'] = cacheControl;
    res.writeHead(proxyRes.statusCode, outHeaders);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    log('error', 'upstream request error', { reqId, message: err.message });
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('Bad Gateway');
  });

  req.pipe(proxyReq);
}

function onHandlerError(reqId, res, err) {
  log('error', 'handler error', { reqId, message: err.message });
  if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
  res.end('Bad Gateway');
}

log('info', 'starting', {
  target: TARGET.origin, port: PORT, sslCert: SSL_CERT, sslKey: SSL_KEY,
  tokenEndpoint: TOKEN_ENDPOINT, logLevel: LOG_LEVEL,
  stageCacheControl: STAGE_CACHE_CONTROL, bypassCacheControl: BYPASS_CACHE_CONTROL,
});

try {
  await getToken();
} catch (err) {
  log('error', 'initial token mint failed, exiting', { message: err.message });
  process.exit(1);
}

const server = http2.createSecureServer({ ...tlsOptions, allowHTTP1: true }, (req, res) => {
  const reqId = randomBytes(4).toString('hex');
  const start = Date.now();

  if (req.url === '/favicon.ico') {
    log('debug', 'favicon short-circuit', { reqId });
    res.writeHead(204);
    res.end();
    return;
  }

  // Mode selection: stage callers opt in by sending Cache-Control: max-age>0
  // on the request. Anything else (including non-GET/HEAD) is authoring.
  const reqMaxAge = parseMaxAge(req.headers['cache-control']);
  const mode = (req.method === 'GET' || req.method === 'HEAD') && reqMaxAge > 0
    ? 'stage' : 'bypass';

  log('info', 'request', {
    reqId, method: req.method, url: req.url,
    remote: req.socket.remoteAddress, mode,
    headers: redactHeaders(req.headers),
  });

  res.on('finish', () => {
    log('info', 'response', {
      reqId, status: res.statusCode, durationMs: Date.now() - start,
    });
  });

  handleRequest(reqId, req, res, mode).catch((err) => onHandlerError(reqId, res, err));
});

server.listen(PORT, () => {
  log('info', 'listening', { port: PORT, target: TARGET.origin });
});
