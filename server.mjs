import fs from 'node:fs';
import https from 'node:https';
import { randomBytes } from 'node:crypto';

try { process.loadEnvFile(); } catch {}

const TARGET = new URL('https://preview-p22655-e59433.adobeaemcloud.com/');
const PORT = process.env.PORT || 3000;
const SSL_CERT = process.env.SSL_CERT;
const SSL_KEY = process.env.SSL_KEY;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
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
if (!ACCESS_TOKEN && (!CLIENT_ID || !CLIENT_SECRET || !SCOPES)) {
  console.error('Provide ACCESS_TOKEN, or CLIENT_ID + CLIENT_SECRET + SCOPES for OAuth mint');
  process.exit(1);
}

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const ACTIVE_LEVEL = LEVELS[LOG_LEVEL] ?? LEVELS.debug;

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

// Remove any upstream-provided values for headers we set ourselves,
// so we don't emit duplicates (e.g. AEM sends its own `x-cache`).
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

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host',
]);

// Headers from the incoming client request that must NOT be forwarded upstream.
// - `cookie` / `authorization`: scoped to this proxy's hostname; useless (and large) for AEM,
//   and we set our own Authorization below.
// - `sec-ch-*` / `sec-fetch-*` / `upgrade-insecure-requests` / `dnt` / `priority`:
//   browser fetch metadata irrelevant to AEM and contributing header bloat that causes 431.
// - `referer` / `origin`: reference this proxy, not upstream; safer to drop.
const DROP_FROM_UPSTREAM = new Set([
  'cookie', 'authorization',
  'referer', 'origin',
  'upgrade-insecure-requests', 'dnt', 'priority',
  'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-ch-ua-arch',
  'sec-ch-ua-bitness', 'sec-ch-ua-full-version', 'sec-ch-ua-full-version-list',
  'sec-ch-ua-model', 'sec-ch-ua-platform-version', 'sec-ch-ua-wow64',
  'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
]);

const MAX_ENTRIES = 500;
const MAX_TTL_SEC = 300;
const REFRESH_SKEW_MS = 5 * 60 * 1000;
const cache = new Map();

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
  if (ACCESS_TOKEN) return ACCESS_TOKEN;
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
  return Math.min(n, MAX_TTL_SEC);
}

async function buildUpstreamHeaders(req) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk) || DROP_FROM_UPSTREAM.has(lk)) continue;
    headers[k] = v;
  }
  headers['host'] = TARGET.host;
  headers['authorization'] = `Bearer ${await getToken()}`;
  return headers;
}

function sanitizeCachedHeaders(src) {
  const out = {};
  for (const [k, v] of Object.entries(src)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    if (lk === 'set-cookie' || lk === 'content-length') continue;
    out[k] = v;
  }
  return out;
}

function serveFromCache(res, entry) {
  const headers = { ...entry.headers, 'X-Cache': 'HIT', 'Content-Length': entry.body.length };
  res.writeHead(entry.status, headers);
  res.end(entry.body);
}

function storeInCache(key, entry) {
  if (cache.size >= MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) {
      cache.delete(oldest);
      log('debug', 'cache evict', { evicted: oldest, size: cache.size });
    }
  }
  cache.set(key, entry);
}

async function handleCacheable(reqId, req, res, ttlSec) {
  const key = `${req.method} ${req.url}`;
  const now = Date.now();
  const existing = cache.get(key);
  if (existing && existing.expiresAt > now) {
    const ageMs = now - (existing.expiresAt - ttlSec * 1000);
    log('info', 'cache hit', { reqId, key, ageMs, bytes: existing.body.length });
    serveFromCache(res, existing);
    return;
  }
  if (existing) {
    log('debug', 'cache expired', { reqId, key });
    cache.delete(key);
  } else {
    log('debug', 'cache miss', { reqId, key });
  }

  const headers = await buildUpstreamHeaders(req);
  const upstreamStart = Date.now();
  log('debug', 'upstream request', { reqId, method: req.method, path: req.url, cacheable: true });
  logCurl(reqId, req.method, req.url, headers);

  const proxyReq = https.request({
    hostname: TARGET.hostname,
    port: TARGET.port || 443,
    path: req.url,
    method: req.method,
    headers,
  }, (proxyRes) => {
    const status = proxyRes.statusCode;
    const hasSetCookie = Boolean(proxyRes.headers['set-cookie']);
    const cacheable = status >= 200 && status < 300;
    log('info', 'upstream response', {
      reqId, status, durationMs: Date.now() - upstreamStart,
      contentLength: proxyRes.headers['content-length'], cacheable, hasSetCookie,
    });

    if (!cacheable) {
      res.writeHead(status, { ...dropHeaders(stripResponseCookies(proxyRes.headers), ['x-cache']), 'X-Cache': 'MISS' });
      proxyRes.pipe(res);
      return;
    }

    const chunks = [];
    proxyRes.on('data', (chunk) => chunks.push(chunk));
    proxyRes.on('end', () => {
      const body = Buffer.concat(chunks);
      const cachedHeaders = dropHeaders(sanitizeCachedHeaders(proxyRes.headers), ['x-cache']);
      storeInCache(key, {
        expiresAt: Date.now() + ttlSec * 1000,
        status,
        headers: cachedHeaders,
        body,
      });
      log('info', 'cache store', { reqId, key, ttlSec, bytes: body.length, size: cache.size });
      res.writeHead(status, { ...cachedHeaders, 'X-Cache': 'MISS', 'Content-Length': body.length });
      res.end(body);
    });
    proxyRes.on('error', (err) => {
      log('error', 'upstream response error', { reqId, message: err.message });
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('Bad Gateway');
    });
  });

  proxyReq.on('error', (err) => {
    log('error', 'upstream request error', { reqId, message: err.message });
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('Bad Gateway');
  });

  req.pipe(proxyReq);
}

async function handleBypass(reqId, req, res) {
  const headers = await buildUpstreamHeaders(req);
  const upstreamStart = Date.now();
  log('debug', 'upstream request', { reqId, method: req.method, path: req.url, cacheable: false });
  logCurl(reqId, req.method, req.url, headers);

  const proxyReq = https.request({
    hostname: TARGET.hostname,
    port: TARGET.port || 443,
    path: req.url,
    method: req.method,
    headers,
  }, (proxyRes) => {
    log('info', 'upstream response', {
      reqId, status: proxyRes.statusCode, durationMs: Date.now() - upstreamStart,
      contentLength: proxyRes.headers['content-length'], cacheable: false,
    });
    res.writeHead(proxyRes.statusCode, { ...dropHeaders(stripResponseCookies(proxyRes.headers), ['x-cache']), 'X-Cache': 'BYPASS' });
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
  tokenMode: ACCESS_TOKEN ? 'static' : 'oauth',
  tokenEndpoint: ACCESS_TOKEN ? undefined : TOKEN_ENDPOINT,
  logLevel: LOG_LEVEL, maxCacheEntries: MAX_ENTRIES, maxTtlSec: MAX_TTL_SEC,
});

if (!ACCESS_TOKEN) {
  try {
    await getToken();
  } catch (err) {
    log('error', 'initial token mint failed, exiting', { message: err.message });
    process.exit(1);
  }
}

const server = https.createServer(tlsOptions, (req, res) => {
  const reqId = randomBytes(4).toString('hex');
  const start = Date.now();

  if (req.url === '/favicon.ico') {
    log('debug', 'favicon short-circuit', { reqId });
    res.writeHead(204, { 'X-Cache': 'STUB' });
    res.end();
    return;
  }

  const ttlSec = parseMaxAge(req.headers['cache-control']);
  const useCache = (req.method === 'GET' || req.method === 'HEAD') && ttlSec > 0;

  log('info', 'request', {
    reqId, method: req.method, url: req.url,
    remote: req.socket.remoteAddress, route: useCache ? 'cache' : 'bypass', ttlSec,
    headers: redactHeaders(req.headers),
  });

  res.on('finish', () => {
    log('info', 'response', {
      reqId, status: res.statusCode,
      xCache: res.getHeader('X-Cache'), durationMs: Date.now() - start,
    });
  });

  const promise = useCache ? handleCacheable(reqId, req, res, ttlSec) : handleBypass(reqId, req, res);
  promise.catch((err) => onHandlerError(reqId, res, err));
});

server.listen(PORT, () => {
  log('info', 'listening', { port: PORT, target: TARGET.origin });
});
