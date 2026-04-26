// Persistent solver server: HTTP API + browser pool.
//
// Design goals (Tier 1 Cloudflare UAM bypass):
//   - Pool of N parallel real-browser sessions, each holding its own
//     cf_clearance + __cf_bm pair so concentrated cookie abuse is avoided.
//   - Real human-like navigation (scroll, mouse, dwell time) between
//     receiving a challenge response and capturing the cookie, so the
//     issued clearance has a high "human signal" score and survives
//     longer under load.
//   - Persistent: 0 cold-start cost on refresh. blaze gets a cookie via
//     localhost HTTP in <2ms vs ~5-10s for a `node solver` exec.
//   - Self-healing: each slot tracks invalidations and auto-refreshes
//     before TTL expiry; blaze can also push 403s via /invalidate to
//     mark a slot dirty.
//   - Fingerprint visibility: /fingerprint endpoint queries tls.peet.ws
//     from inside one of the pool browsers so blaze can verify that
//     its own emulated JA4/UA align with the solver's real browser.
//
// API:
//   GET  /healthz                       -> 200 ok
//   GET  /status                        -> { slots: [...], target, ready }
//   GET  /cookie                        -> { slot, cookies, user_agent }
//   POST /invalidate { slot, reason }   -> 200 (slot scheduled for refresh)
//   GET  /fingerprint                   -> { ja4, ja3_hash, user_agent, ... }
//   POST /shutdown                      -> 200 (graceful exit)
//
// Bind: 127.0.0.1:9876 by default. Loopback only - never expose this.

import http from "node:http";
import { connect } from "puppeteer-real-browser";

// ----- Configuration (env overrides) -----
const PORT = parseInt(process.env.SOLVER_PORT || "9876", 10);
const HOST = process.env.SOLVER_HOST || "127.0.0.1";
const POOL_SIZE = parseInt(process.env.SOLVER_POOL || "5", 10);
const TARGET_URL = process.argv[2] || process.env.SOLVER_TARGET;
const COOKIE_TTL_MS = parseInt(process.env.SOLVER_COOKIE_TTL_MS || (25 * 60 * 1000), 10);
const SOLVE_TIMEOUT_MS = parseInt(process.env.SOLVER_SOLVE_TIMEOUT_MS || (90 * 1000), 10);
const REFRESH_KEEPALIVE_MS = parseInt(process.env.SOLVER_KEEPALIVE_MS || (90 * 1000), 10);
const VERBOSE = process.env.SOLVER_VERBOSE === "1";

if (!TARGET_URL) {
  console.error("usage: node server.js <target_url>");
  console.error("       or set SOLVER_TARGET env var");
  process.exit(1);
}

// ----- Logging -----
function log(...a) {
  console.log(`[solver ${new Date().toISOString()}]`, ...a);
}
function vlog(...a) {
  if (VERBOSE) log(...a);
}

// ----- One pool slot = one browser holding one cookie set -----
class PoolSlot {
  constructor(id) {
    this.id = id;
    this.browser = null;
    this.page = null;
    this.cookies = "";
    this.cookieList = [];
    this.userAgent = "";
    this.acquiredAt = 0;
    this.uses = 0;
    this.invalidations = 0;
    this.refreshing = false;
    this.dirty = true;
    this.lastError = null;
  }

  isHealthy() {
    if (this.dirty || !this.cookies) return false;
    const age = Date.now() - this.acquiredAt;
    return age < COOKIE_TTL_MS;
  }

  toStatus() {
    return {
      id: this.id,
      ready: this.isHealthy(),
      refreshing: this.refreshing,
      uses: this.uses,
      invalidations: this.invalidations,
      ageMs: this.acquiredAt ? Date.now() - this.acquiredAt : 0,
      lastError: this.lastError,
    };
  }

  async start() {
    return this.refresh();
  }

  async refresh() {
    if (this.refreshing) return;
    this.refreshing = true;
    this.dirty = true;

    // Fully tear down existing browser to avoid Chromium state bleed.
    if (this.browser) {
      try { await this.browser.close(); } catch {}
      this.browser = null;
      this.page = null;
    }

    try {
      const result = await connect({
        headless: false,
        turnstile: true,
        args: [
          "--no-sandbox",
          "--disable-setuid-sandbox",
          "--disable-dev-shm-usage",
          "--disable-gpu",
          "--disable-blink-features=AutomationControlled",
          "--no-first-run",
          "--no-default-browser-check",
          "--disable-features=IsolateOrigins,site-per-process",
          "--window-size=1920,1080",
        ],
        connectOption: {
          defaultViewport: null,
        },
        disableXvfb: false,
        ignoreAllFlags: false,
      });

      this.browser = result.browser;
      this.page = result.page;

      // Match blaze's emulated Chrome 146 UA exactly. UAM frequently binds
      // cf_clearance to UA, so any drift between the solver browser's UA
      // and the gofire client's UA invalidates the cookie immediately.
      const targetUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
      try { await this.page.setUserAgent(targetUA); } catch {}

      // Mild stealth boost on top of puppeteer-real-browser's existing patches.
      await this.page.evaluateOnNewDocument(() => {
        // navigator.webdriver -> undefined
        try { Object.defineProperty(navigator, "webdriver", { get: () => undefined }); } catch {}
        // languages: realistic
        try { Object.defineProperty(navigator, "languages", { get: () => ["en-US", "en"] }); } catch {}
        // plugins: at least 3 entries (real Chrome reports several)
        try {
          Object.defineProperty(navigator, "plugins", {
            get: () => ([
              { name: "PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
              { name: "Chrome PDF Viewer", filename: "internal-pdf-viewer", description: "" },
              { name: "Chromium PDF Viewer", filename: "internal-pdf-viewer", description: "" },
            ]),
          });
        } catch {}
      });

      log(`slot ${this.id}: navigating to ${TARGET_URL}`);
      await this.page.goto(TARGET_URL, { waitUntil: "domcontentloaded", timeout: SOLVE_TIMEOUT_MS });

      // Wait for cf_clearance to materialize (challenge solved).
      await this.waitForClearance(SOLVE_TIMEOUT_MS);

      // Real navigation: produce strong "human signal" score so the cookie
      // does not get invalidated as soon as we hammer it from the client.
      await this.simulateHumanBehavior();

      // Re-read cookies post-behavior; some sites issue stronger __cf_bm
      // values after interaction.
      const cookies = await this.browser.cookies(TARGET_URL);
      const ua = await this.page.evaluate(() => navigator.userAgent);

      this.cookieList = cookies;
      this.cookies = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
      this.userAgent = ua;
      this.acquiredAt = Date.now();
      this.dirty = false;
      this.lastError = null;
      log(`slot ${this.id}: ready (cookies=${cookies.length}, ua=${ua.split(" ").slice(-2).join(" ")})`);
    } catch (err) {
      this.lastError = err.message || String(err);
      this.cookies = "";
      this.cookieList = [];
      this.dirty = true;
      log(`slot ${this.id}: refresh failed: ${this.lastError}`);
    } finally {
      this.refreshing = false;
    }
  }

  async waitForClearance(timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const cookies = await this.browser.cookies(TARGET_URL).catch(() => []);
      const cf = cookies.find((c) => c.name === "cf_clearance");
      if (cf) return cf;

      // If the page already loaded without challenge, we're done.
      const title = await this.page.title().catch(() => "");
      if (
        title &&
        !/just a moment|attention required|checking your browser/i.test(title)
      ) {
        return null; // No challenge present.
      }

      await sleep(500);
    }
    throw new Error("cf_clearance did not appear before timeout");
  }

  async simulateHumanBehavior() {
    // 1-2s settle pause.
    await sleep(rand(1000, 2000));

    // Move mouse to a believable area (away from extreme corners).
    try { await this.page.mouse.move(rand(200, 1000), rand(150, 600), { steps: 10 }); } catch {}
    await sleep(rand(300, 700));

    // Scroll down a screen.
    try {
      await this.page.evaluate((y) => window.scrollBy({ top: y, behavior: "smooth" }), rand(250, 600));
    } catch {}
    await sleep(rand(800, 1400));

    // Move mouse again, scroll a bit more.
    try { await this.page.mouse.move(rand(400, 1500), rand(300, 800), { steps: 12 }); } catch {}
    try {
      await this.page.evaluate((y) => window.scrollBy({ top: y, behavior: "smooth" }), rand(150, 400));
    } catch {}
    await sleep(rand(600, 1200));

    // Final dwell — many WAFs sample beacon/RUM events for ~2s after first paint.
    await sleep(rand(500, 1100));
  }

  // Lightweight keepalive: load same URL in the same tab to refresh
  // __cf_bm without paying the full challenge cost. Skipped if dirty.
  async keepalive() {
    if (this.dirty || this.refreshing || !this.page) return;
    try {
      await this.page.goto(TARGET_URL, { waitUntil: "domcontentloaded", timeout: 15000 });
      const cookies = await this.browser.cookies(TARGET_URL);
      this.cookieList = cookies;
      this.cookies = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
      vlog(`slot ${this.id}: keepalive ok`);
    } catch (err) {
      vlog(`slot ${this.id}: keepalive failed: ${err.message}`);
      this.dirty = true;
    }
  }

  async stop() {
    if (this.browser) {
      try { await this.browser.close(); } catch {}
      this.browser = null;
      this.page = null;
    }
  }
}

class BrowserPool {
  constructor(size) {
    this.slots = Array.from({ length: size }, (_, i) => new PoolSlot(i));
    this.rotateIdx = 0;
  }

  async start() {
    log(`spinning up ${this.slots.length} slots in parallel`);
    await Promise.all(this.slots.map((s) => s.start().catch((e) => log(`slot ${s.id} init: ${e.message}`))));
    log(`pool ready: ${this.healthyCount()}/${this.slots.length} slots healthy`);

    // Background loops: keepalive ping + TTL refresh.
    setInterval(() => this.keepaliveLoop(), REFRESH_KEEPALIVE_MS);
    setInterval(() => this.refreshLoop(), 30 * 1000);
  }

  healthyCount() {
    return this.slots.filter((s) => s.isHealthy()).length;
  }

  // Round-robin pick of a healthy slot. Returns null if pool is empty.
  pick() {
    const n = this.slots.length;
    for (let attempt = 0; attempt < n; attempt++) {
      const slot = this.slots[this.rotateIdx % n];
      this.rotateIdx = (this.rotateIdx + 1) % n;
      if (slot.isHealthy()) {
        slot.uses++;
        return slot;
      }
    }
    return null;
  }

  async invalidate(slotId, reason) {
    const slot = this.slots[slotId];
    if (!slot) return;
    slot.invalidations++;
    slot.dirty = true;
    log(`slot ${slot.id}: invalidated (${reason || "no reason"})`);
    // Refresh asynchronously so the HTTP caller doesn't wait.
    slot.refresh().catch((e) => log(`slot ${slot.id} refresh err: ${e.message}`));
  }

  async refreshLoop() {
    for (const slot of this.slots) {
      if (slot.refreshing) continue;
      const age = Date.now() - slot.acquiredAt;
      if (slot.dirty || age > COOKIE_TTL_MS) {
        slot.refresh().catch((e) => log(`slot ${slot.id} ttl-refresh err: ${e.message}`));
      }
    }
  }

  async keepaliveLoop() {
    for (const slot of this.slots) {
      if (slot.refreshing || slot.dirty) continue;
      slot.keepalive().catch(() => {});
    }
  }

  async stop() {
    await Promise.all(this.slots.map((s) => s.stop()));
  }
}

// ----- Fingerprint capture -----
// Uses one slot's browser to query tls.peet.ws/api/all so blaze can verify
// JA4 alignment with what its emulated Chrome 146 produces.
async function captureFingerprint(pool) {
  const slot = pool.slots.find((s) => s.page && !s.refreshing);
  if (!slot) throw new Error("no available browser for fingerprint capture");
  const r = await slot.page.evaluate(async () => {
    const res = await fetch("https://tls.peet.ws/api/all", { credentials: "omit" });
    return await res.json();
  });
  return {
    ja3_hash: r?.tls?.ja3_hash,
    ja4: r?.tls?.ja4,
    akamai_h2_hash: r?.http2?.akamai_fingerprint_hash,
    user_agent: r?.user_agent,
  };
}

// ----- Helpers -----
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function rand(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

function send(res, code, obj) {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
}

// ----- Main -----
const pool = new BrowserPool(POOL_SIZE);

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/healthz") {
      return send(res, 200, { ok: true });
    }
    if (req.method === "GET" && req.url === "/status") {
      return send(res, 200, {
        target: TARGET_URL,
        pool_size: pool.slots.length,
        healthy: pool.healthyCount(),
        slots: pool.slots.map((s) => s.toStatus()),
      });
    }
    if (req.method === "GET" && req.url.startsWith("/cookie")) {
      const slot = pool.pick();
      if (!slot) return send(res, 503, { error: "no healthy slots" });
      return send(res, 200, {
        slot: slot.id,
        cookies: slot.cookies,
        cookie_list: slot.cookieList.map((c) => ({ name: c.name, value: c.value })),
        user_agent: slot.userAgent,
      });
    }
    if (req.method === "POST" && req.url === "/invalidate") {
      const body = await readBody(req);
      let parsed = {};
      try { parsed = JSON.parse(body); } catch {}
      await pool.invalidate(parsed.slot, parsed.reason);
      return send(res, 200, { ok: true });
    }
    if (req.method === "GET" && req.url === "/fingerprint") {
      try {
        const fp = await captureFingerprint(pool);
        return send(res, 200, fp);
      } catch (e) {
        return send(res, 500, { error: e.message });
      }
    }
    if (req.method === "POST" && req.url === "/shutdown") {
      send(res, 200, { ok: true });
      shutdown();
      return;
    }
    send(res, 404, { error: "not found" });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
});

let shuttingDown = false;
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  log("shutting down");
  await pool.stop().catch(() => {});
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

(async () => {
  log(`target=${TARGET_URL} pool=${POOL_SIZE} bind=${HOST}:${PORT}`);
  await pool.start();
  server.listen(PORT, HOST, () => {
    log(`listening on http://${HOST}:${PORT}`);
  });
})();
