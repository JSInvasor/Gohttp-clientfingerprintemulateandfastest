// Single-shot Cloudflare UAM solver.
//
// Usage:
//   node solver/index.js <url> [timeout_sec=75]
//
// Output (stdout, single JSON line):
//   { "status": "ok"|"no_clearance"|"error",
//     "url": "<final url>",
//     "user_agent": "<navigator.userAgent>",
//     "cookies": "name=val; name=val; ...",   // header-ready
//     "cookie_list": [{name, value, domain, expires}, ...],
//     "duration_ms": <int>,
//     "attempts": <int>,
//     "error": "<message>" }                  // only on error
//
// Design (one-shot, no server):
//   - puppeteer-real-browser launches a real Chromium with stealth patches.
//   - We pin the UA to Chrome 147 to match what the gofire client emulates.
//     UAM binds cf_clearance to (UA, JA3/JA4, IP); UA drift = instant 403.
//   - After cf_clearance appears we perform human-like behavior (mouse moves,
//     smoothed scroll, dwell time) BEFORE reading the cookie. CF assigns a
//     "human signal" score during the first few seconds after issuance; a
//     cookie captured immediately is weak and dies under load. After ~3-5 s
//     of believable activity the score plateaus and the cookie survives.
//   - Up to 2 attempts: if first try yields no clearance we tear the browser
//     down and retry once. Many CF protections rotate the challenge after a
//     soft-fail, so a fresh tab/session can succeed.

import { connect } from "puppeteer-real-browser";

const url = process.argv[2];
const timeoutSec = parseInt(process.argv[3] || "75", 10);
const TIMEOUT_MS = timeoutSec * 1000;
const MAX_ATTEMPTS = 2;

// Match blaze's emulated Chrome 147. Override via env if your VPS Chrome is
// a different major version - drift between solver UA and gofire UA causes
// "all mitigated" because cf_clearance is bound to UA + JA4.
const TARGET_UA =
  process.env.SOLVER_UA ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";

if (!url) {
  console.error(
    JSON.stringify({
      status: "error",
      error: "usage: node solver/index.js <url> [timeout_sec]",
    })
  );
  process.exit(1);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function rand(a, b) {
  return Math.floor(Math.random() * (b - a + 1)) + a;
}

// Launch a fresh real-browser session with stealth shims layered on top of
// puppeteer-real-browser's existing rebrowser-puppeteer-core patches.
async function launch() {
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
    connectOption: { defaultViewport: null },
    disableXvfb: false,
    ignoreAllFlags: false,
  });

  const { browser, page } = result;

  // Force the gofire-matching UA before any navigation.
  try {
    await page.setUserAgent(TARGET_UA);
  } catch {}

  // Stealth shims - applied to every new document so they survive navigations.
  await page.evaluateOnNewDocument(() => {
    // navigator.webdriver -> undefined (CF Bot Score signal)
    try {
      Object.defineProperty(navigator, "webdriver", { get: () => undefined });
    } catch {}
    // languages: realistic en-US fallback
    try {
      Object.defineProperty(navigator, "languages", {
        get: () => ["en-US", "en"],
      });
    } catch {}
    // plugins: real Chrome reports several PDF-related entries
    try {
      Object.defineProperty(navigator, "plugins", {
        get: () => [
          {
            name: "PDF Viewer",
            filename: "internal-pdf-viewer",
            description: "Portable Document Format",
          },
          {
            name: "Chrome PDF Viewer",
            filename: "internal-pdf-viewer",
            description: "",
          },
          {
            name: "Chromium PDF Viewer",
            filename: "internal-pdf-viewer",
            description: "",
          },
        ],
      });
    } catch {}
  });

  return { browser, page };
}

// Wait until cf_clearance appears in the cookie jar OR the page leaves the
// challenge state (title flips back to a normal one). Returns the cookie
// object on success, null if no challenge was present, throws on timeout.
async function waitForClearance(browser, page, deadline) {
  while (Date.now() < deadline) {
    const cookies = await browser.cookies(url).catch(() => []);
    const cf = cookies.find((c) => c.name === "cf_clearance");
    if (cf) return cf;

    const title = await page.title().catch(() => "");
    if (
      title &&
      !/just a moment|attention required|checking your browser|verify you are human/i.test(
        title
      )
    ) {
      // Page is past the challenge gate even without an explicit clearance
      // cookie (some sites use Bot Fight Mode without UAM).
      return null;
    }
    await sleep(500);
  }
  throw new Error("cf_clearance did not appear before timeout");
}

// Real-user behavior between challenge solve and cookie capture. CF samples
// mouse/scroll/dwell events for the first few seconds after issuance and
// uses them to score the cookie. A cookie captured cold dies under load
// within seconds; one captured after 3-5 s of believable activity holds up.
async function simulateHumanBehavior(page) {
  // Initial settle pause (RUM beacons fire here).
  await sleep(rand(900, 1600));

  // Mouse move into a believable region.
  try {
    await page.mouse.move(rand(220, 1100), rand(180, 600), { steps: 12 });
  } catch {}
  await sleep(rand(280, 600));

  // First scroll - slow, smooth.
  try {
    await page.evaluate(
      (y) => window.scrollBy({ top: y, behavior: "smooth" }),
      rand(280, 600)
    );
  } catch {}
  await sleep(rand(800, 1300));

  // Second mouse move + smaller scroll.
  try {
    await page.mouse.move(rand(400, 1500), rand(300, 800), { steps: 10 });
  } catch {}
  try {
    await page.evaluate(
      (y) => window.scrollBy({ top: y, behavior: "smooth" }),
      rand(150, 380)
    );
  } catch {}
  await sleep(rand(700, 1100));

  // Dispatch a focus/blur event, simulating tab switching back.
  try {
    await page.evaluate(() => {
      window.dispatchEvent(new Event("focus"));
      document.body && document.body.click();
    });
  } catch {}
  await sleep(rand(500, 900));

  // Final dwell - lets __cf_bm settle and any post-load JS finish.
  await sleep(rand(600, 1100));
}

// One full attempt: launch, navigate, wait for clearance, simulate behavior,
// capture cookies. Caller decides whether to retry on failure.
async function attempt(attemptNum) {
  const { browser, page } = await launch();
  try {
    const deadline = Date.now() + TIMEOUT_MS;

    await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: TIMEOUT_MS,
    });

    const cf = await waitForClearance(browser, page, deadline);
    if (!cf && attemptNum < MAX_ATTEMPTS) {
      // No clearance and we still have a retry left - signal caller.
      return { status: "no_clearance", browser };
    }

    // Whether clearance was present or not, harvest behavior data so even
    // bot-fight-mode-only sites get a strong __cf_bm.
    await simulateHumanBehavior(page);

    // Re-read cookies post-behavior (interaction can elevate __cf_bm).
    const cookies = await browser.cookies(url);
    const cfFinal = cookies.find((c) => c.name === "cf_clearance");
    const userAgent = await page.evaluate(() => navigator.userAgent);
    const finalUrl = page.url();

    return {
      status: cfFinal ? "ok" : "no_clearance",
      url: finalUrl,
      user_agent: userAgent,
      cookies: cookies.map((c) => `${c.name}=${c.value}`).join("; "),
      cookie_list: cookies.map((c) => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        expires: c.expires,
      })),
      browser,
    };
  } catch (err) {
    return { status: "error", error: err.message || String(err), browser };
  }
}

async function solve() {
  const startTs = Date.now();
  let lastResult = null;

  for (let i = 1; i <= MAX_ATTEMPTS; i++) {
    const r = await attempt(i);
    lastResult = r;

    // Always close the browser before deciding whether to retry. Keeping
    // the old session around can carry stale fingerprint state into the
    // next attempt.
    if (r.browser) {
      await r.browser.close().catch(() => {});
      r.browser = undefined;
    }

    if (r.status === "ok") {
      const out = {
        status: "ok",
        url: r.url,
        user_agent: r.user_agent,
        cookies: r.cookies,
        cookie_list: r.cookie_list,
        duration_ms: Date.now() - startTs,
        attempts: i,
      };
      console.log(JSON.stringify(out));
      return;
    }

    // Non-ok and we have another attempt: small jittered backoff so the
    // retry hits the edge with a clean PoP rotation.
    if (i < MAX_ATTEMPTS) {
      await sleep(rand(800, 1500));
    }
  }

  // All attempts exhausted.
  if (lastResult && lastResult.status === "no_clearance") {
    const out = {
      status: "no_clearance",
      url: lastResult.url || url,
      user_agent: lastResult.user_agent || TARGET_UA,
      cookies: lastResult.cookies || "",
      cookie_list: lastResult.cookie_list || [],
      duration_ms: Date.now() - startTs,
      attempts: MAX_ATTEMPTS,
    };
    console.log(JSON.stringify(out));
    return;
  }

  console.log(
    JSON.stringify({
      status: "error",
      error: (lastResult && lastResult.error) || "solve failed",
      duration_ms: Date.now() - startTs,
      attempts: MAX_ATTEMPTS,
    })
  );
}

solve().catch((err) => {
  console.log(
    JSON.stringify({
      status: "error",
      error: err.message || String(err),
    })
  );
  process.exit(1);
});
