# mas-freyja-proxy

Minimal HTTPS reverse proxy that fronts the AEM Freyja preview environment
(`https://preview-p22655-e59433.adobeaemcloud.com/`) for MAS Studio and
injects an Adobe IMS bearer token server-side, so clients don't have to
handle IMS credentials.

Zero runtime dependencies — built on Node's stdlib (`node:http`, `node:https`,
`node:crypto`) and the built-in `.env` loader (`process.loadEnvFile()`).

## How it's used

Two consumer modes, selected per-request by the `Cache-Control` header the
caller sends. The proxy itself does not cache response bodies — it sets the
right `Cache-Control` downstream so the browser does the caching.

| Caller              | Sends                      | Proxy emits downstream |
| ------------------- | -------------------------- | ---------------------- |
| Authoring (default) | _no `Cache-Control`_       | `Cache-Control: no-store` |
| Stage / website     | `Cache-Control: max-age=N` | `Cache-Control: public, max-age=15, stale-while-revalidate=604800, stale-if-error=604800` |

The caller's `max-age=N` is a mode signal only — the proxy emits a fixed
policy (15 s fresh, 7 days stale-while-revalidate) regardless of `N`. The
browser becomes the real cache.

Bearer-token injection: the proxy mints tokens via Adobe IMS
Server-to-Server (`client_credentials` grant) and auto-refreshes before
expiry, with in-flight coalescing so concurrent requests share one mint.

## Configuration (`.env`)

| Var              | Required | Purpose                                                        |
| ---------------- | -------- | -------------------------------------------------------------- |
| `SSL_CERT`       | yes      | Path to PEM certificate (chain).                               |
| `SSL_KEY`        | yes      | Path to PEM private key.                                       |
| `CLIENT_ID`      | yes      | IMS S2S client ID.                                             |
| `CLIENT_SECRET`  | yes      | IMS S2S client secret.                                         |
| `SCOPES`         | yes      | IMS scopes, e.g. `AdobeID, openid`.                            |
| `PORT`           | no       | Listen port (default `3000`).                                  |
| `TOKEN_ENDPOINT` | no       | Override IMS token endpoint (default `ims-na1` prod).          |
| `LOG_LEVEL`      | no       | `error` \| `warn` \| `info` \| `debug` (default `debug`).      |
| `LOG_CURL`       | no       | Log a reproducible `curl` for every upstream call. Default on. |

## Running

Local:

```bash
node server.mjs
```

As a systemd service (production): see [`service.sh`](service.sh) and
[`deploy/mas-freyja-proxy.service`](deploy/mas-freyja-proxy.service).

```bash
./service.sh install   # template + enable + start
./service.sh status
./service.sh logs      # tails journald
./service.sh restart
./service.sh uninstall
```

## Caching strategy

The browser is the cache. The proxy is a thin token-injecting pass-through
that tells the browser how to cache via response headers.

### Stage mode — `Cache-Control: public, max-age=15, stale-while-revalidate=604800, stale-if-error=604800`

- **`max-age=15`** — browser serves straight from its own cache for 15 s.
  Zero round trip, zero proxy load.
- **`stale-while-revalidate=604800`** (7 days) — after those 15 s, for up
  to a week, the browser still serves the cached body immediately and
  refetches in the background. The user experiences memory latency; the
  revalidation happens off the critical path.
- **`stale-if-error=604800`** — if the background revalidation fails
  (upstream 5xx), the browser keeps serving stale for up to a week rather
  than surfacing the error.
- **ETag / Last-Modified pass through unchanged.** The browser attaches
  `If-None-Match` / `If-Modified-Since` on revalidation; upstream's `304
  Not Modified` flows straight back to the browser. Background refreshes
  are typically a few hundred bytes, not full bodies.

### Authoring / bypass mode — `Cache-Control: no-store`

Nothing caches. Every call reaches upstream fresh.

### Proxy-side optimizations kept

Only the ones the browser can't do for you.

- **Keep-alive connection pool** to upstream
  (`https.Agent({ keepAlive: true, maxSockets: 64 })`) — shared across
  every request. Critical: every browser SWR revalidation still traverses
  the proxy, and paying a TCP+TLS handshake per 304 would dominate.
- **IMS token mint + in-flight coalescing** — tokens are proxy-local
  secrets; concurrent requests share a single mint.
- **`/favicon.ico` → 204** short-circuit, never reaches upstream.
- **Header hygiene** (see below), still necessary regardless of caching.

### End-to-end latency matrix

| Caller state                               | Layer hit        | Latency          | Network                 |
| ------------------------------------------ | ---------------- | ---------------- | ----------------------- |
| Browser cache fresh (< 15 s)               | browser RAM/disk | sub-ms           | none                    |
| Browser cache stale (within SWR window)    | browser RAM/disk | sub-ms for user  | 1 background request, usually 304 |
| Browser cache cold (first visit)           | full chain       | 1 RTT to proxy + 1 to AEM | full body once |
| Authoring / bypass                         | full chain       | 1 RTT (warm sockets)      | full body      |

## Security / header hygiene

- Bearer token injected server-side; never trusted from the client.
- Client-scoped headers stripped before forwarding upstream: `cookie`,
  `authorization`, `cache-control`, `pragma`, `referer`, `origin`,
  `sec-ch-ua*`, `sec-fetch-*`, `upgrade-insecure-requests`, `dnt`,
  `priority`. Prevents HTTP 431 and avoids leaking caller identity or
  mode hints to AEM.
- `If-None-Match` / `If-Modified-Since` are intentionally forwarded so the
  browser's conditional revalidation reaches upstream unchanged.
- Hop-by-hop headers dropped per RFC 7230.
- `Set-Cookie` stripped from upstream responses. Cookies are never logged
  (fully omitted, not redacted).
- Upstream's `Cache-Control` is overridden — the proxy, not AEM, decides
  the browser-facing caching policy.

## Logging

Structured JSON-ish lines to stdout; routed to `journalctl -u mas-freyja-proxy`
when run under systemd. Every request gets a short `reqId` threaded through
all related log lines. Optional `LOG_CURL=true` emits a ready-to-run `curl`
command for each upstream call (useful for debugging, includes the real
bearer token — leave off in shared environments).
