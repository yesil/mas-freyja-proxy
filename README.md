# mas-freyja-proxy

Minimal HTTP/2 reverse proxy fronting the AEM Freyja preview environment
(`https://preview-p22655-e59433.adobeaemcloud.com/`) for MAS Studio. Injects
an Adobe IMS bearer token server-side so clients don't handle IMS credentials.

Zero runtime dependencies — Node stdlib only (`node:http2`, `node:https`,
`node:crypto`, `node:fs`) and the built-in `.env` loader.

## Modes

Selected per-request by the caller's `Cache-Control`. The proxy does not
cache bodies; it sets `Cache-Control` downstream so the browser caches.

| Caller              | Sends                      | Proxy emits (on 2xx)                                                          |
| ------------------- | -------------------------- | ----------------------------------------------------------------------------- |
| Authoring (default) | _no `Cache-Control`_       | `no-store`                                                                    |
| Stage / website     | `Cache-Control: max-age=N` | `public, max-age=15, stale-while-revalidate=604800, stale-if-error=604800`    |

`N` is a mode signal only; the emitted policy is fixed (15 s fresh, 7 d SWR).
Non-2xx responses always get `no-store` so transient upstream errors can't be
pinned in the browser cache.

## Features

- **HTTP/2** with HTTP/1.1 fallback (`http2.createSecureServer({ allowHTTP1: true })`).
- **IMS token injection** via `client_credentials` grant, auto-refresh with
  in-flight coalescing.
- **CORS always on** — preflight is answered directly by the proxy; every
  response carries `Access-Control-Allow-*` so upstream errors remain visible.
- **Keep-alive upstream pool** (`https.Agent({ keepAlive: true, maxSockets: 64 })`)
  — critical so browser SWR revalidations don't pay a TLS handshake per 304.
- **Header hygiene**: strips client-scoped request headers (`cookie`,
  `authorization`, `referer`, `origin`, `sec-ch-ua*`, `sec-fetch-*`, etc.) and
  hop-by-hop headers per RFC 7230. Drops `Set-Cookie` and upstream
  `Cache-Control` from responses. Forwards `If-None-Match` / `If-Modified-Since`
  so browser conditional revalidation works end-to-end.

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
| `LOG_CURL`       | no       | Log a reproducible `curl` per upstream call. Default on.       |

## Running

```bash
node server.mjs
```

Systemd (production): see [`service.sh`](service.sh) and
[`deploy/mas-freyja-proxy.service`](deploy/mas-freyja-proxy.service).

```bash
./service.sh install   # template + enable + start
./service.sh status
./service.sh logs      # tails journald
./service.sh restart
./service.sh uninstall
```

## Logging

Structured lines to stdout; `journalctl -u mas-freyja-proxy` under systemd.
Every request gets a short `reqId` threaded through its log lines. `LOG_CURL=true`
emits a ready-to-run `curl` per upstream call — includes the real bearer token,
leave off in shared environments.
