# Solver

Persistent Cloudflare UAM solver with a browser pool. Designed for use
from Go via HTTP on `127.0.0.1:9876` (loopback only, never expose).

## Setup

```bash
cd solver
npm install
```

`puppeteer-real-browser` requires a working Chromium and (on Linux) Xvfb
because it runs in non-headless mode. On a VPS:

```bash
sudo apt-get install -y xvfb chromium
```

## Two modes

### Server mode (recommended)

Starts a long-lived HTTP server with a browser pool. blaze auto-launches
this when you pass `--solve`.

```bash
SOLVER_POOL=5 node server.js https://your-site.com
```

Endpoints:

- `GET /healthz` — liveness check
- `GET /status` — pool health and per-slot stats
- `GET /cookie` — round-robin one cookie set from the pool
- `POST /invalidate` body `{slot, reason}` — schedule a slot for refresh
- `GET /fingerprint` — capture the solver browser's actual JA3/JA4 from
  tls.peet.ws so you can verify it lines up with what your Go client emits
- `POST /shutdown` — graceful exit

Environment variables:

| name | default | meaning |
| --- | --- | --- |
| `SOLVER_PORT` | `9876` | listen port |
| `SOLVER_HOST` | `127.0.0.1` | bind address |
| `SOLVER_POOL` | `5` | parallel browsers |
| `SOLVER_TARGET` | (cli arg) | target URL |
| `SOLVER_COOKIE_TTL_MS` | `1500000` (25 min) | refresh cookie at this age |
| `SOLVER_SOLVE_TIMEOUT_MS` | `90000` | per-slot first-solve timeout |
| `SOLVER_KEEPALIVE_MS` | `90000` | how often each slot pokes the target to refresh `__cf_bm` |
| `SOLVER_VERBOSE` | `0` | set to `1` for chatty logs |

### One-shot mode (legacy)

Single solve, prints JSON to stdout, exits. Kept for ad-hoc cookie
captures or scripting outside blaze.

```bash
node index.js https://your-site.com 45
```

## How the cookie stays alive longer

Each pool slot, after `cf_clearance` first appears, performs:

1. 1–2 s settle dwell
2. mouse move (smoothed) into the document
3. `window.scrollBy({ top: random(250..600) })`
4. another mouse move + smaller scroll
5. final 0.5–1 s dwell

This produces a higher "human signal" score on Cloudflare's side, so the
cookie does not get demoted to "weak" when blaze immediately starts
hammering it with the cached `cf_clearance`.

A keepalive loop (`SOLVER_KEEPALIVE_MS`) re-navigates each healthy slot
periodically to refresh the short-lived `__cf_bm` companion cookie.

## Fingerprint alignment

UAM binds `cf_clearance` to **(JA3/JA4, UA, IP)**. If the JA4 of your Go
client drifts from the JA4 of the solver browser, every request gets
mitigated even though the cookie itself is "valid". Use:

```bash
curl http://127.0.0.1:9876/fingerprint
```

…then compare with what your Go client produces from
`https://tls.peet.ws/api/all`. JA4 should match exactly. If it doesn't,
upgrade your local Chromium to match the version your gofire profile
emulates (currently Chrome 146).
