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
//     "attempts": <int>,                      // attempts actually made
//     "chromium_version": "<browser.version()>",
//     "chromium_major": <int>,
//     "error": "<message>" }                  // only on error
//
// Design (one-shot, no server):
//   - puppeteer-real-browser launches a real Chromium with stealth patches.
//   - We pin the UA and its Client Hints (profile.js) to match what the gofire
//     client emulates. UAM binds cf_clearance to (UA, JA3/JA4, IP); UA drift =
//     instant 403. `fpcheck -via-chromium` verifies the pin against the Go
//     profile and against this box's actual Chromium, so the drift is caught
//     before a run rather than diagnosed from a wall of 403s.
//   - Cookies are read scoped to the target origin. A challenge run navigates
//     cross-origin and back, so the whole-profile jar ends up holding another
//     host's cf_clearance too — which is not proof the target was solved.
//   - After cf_clearance appears we perform human-like behavior (mouse moves,
//     smoothed scroll, dwell time) BEFORE reading the cookie. CF assigns a
//     "human signal" score during the first few seconds after issuance; a
//     cookie captured immediately is weak and dies under load. After ~3-5 s
//     of believable activity the score plateaus and the cookie survives.
//   - Up to 2 attempts: if first try yields no clearance we tear the browser
//     down and retry once. Many CF protections rotate the challenge after a
//     soft-fail, so a fresh tab/session can succeed.

import { connect } from "puppeteer-real-browser";
import {
  CONNECT_OPTIONS,
  TARGET_UA,
  userAgentMetadata,
  chromiumMajor as parseChromiumMajor,
} from "./profile.js";
import {
  cleanup,
  errorMessage,
  installExitHandlers,
  trackBrowser,
  untrackBrowser,
} from "./cleanup.js";
import { cookiesForUrl } from "./cookies.js";

const MAX_ATTEMPTS = 2;
const DEFAULT_TIMEOUT_SEC = 75;

// Everything below is written to the single-JSON-line contract in the header
// comment, so usage errors go to stdout in the same shape a caller parses.
function die(message, code = 1) {
  console.log(JSON.stringify({ status: "error", error: message }));
  process.exit(code);
}

const url = process.argv[2];
if (!url) {
  die("usage: node solver/index.js <url> [timeout_sec]");
}

// A non-numeric timeout used to survive all the way to setTimeout, where Node
// coerces NaN to 1ms: the watchdog fired a millisecond into the run and the
// solver reported "watchdog timeout" without ever opening a browser. NaN also
// poisoned the goto budget (Math.max(1000, NaN) is NaN) and the deadline
// comparison (Date.now() >= NaN is false).
function parseTimeoutSec(raw) {
  if (raw === undefined) return DEFAULT_TIMEOUT_SEC;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    die(`invalid timeout_sec ${JSON.stringify(raw)}: want a positive number of seconds`);
  }
  return n;
}

const TIMEOUT_MS = Math.round(parseTimeoutSec(process.argv[3]) * 1000);

// Client Hints are built once, up front: userAgentMetadata() throws when the
// pinned UA and sec-ch-ua disagree, and finding that out after a 75-second
// solve would be an expensive way to learn it.
let UA_METADATA;
try {
  UA_METADATA = userAgentMetadata();
} catch (err) {
  die(errorMessage(err));
}

// Kill the Chromium tree on every exit path — signals, exceptions, normal
// return. See cleanup.js for why this is not done with an env-var pkill sweep.
installExitHandlers({
  onFatal: (err) => {
    if (err) console.log(JSON.stringify({ status: "error", error: errorMessage(err) }));
  },
});

// Hard backstop: even if the run hangs forever, we self-terminate at
// (timeout + 30s) so we never become the zombie ourselves.
setTimeout(() => {
  try {
    console.log(
      JSON.stringify({ status: "error", error: "watchdog timeout" })
    );
  } catch {}
  cleanup();
  process.exit(2);
}, TIMEOUT_MS + 30_000).unref();

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function rand(a, b) {
  return Math.floor(Math.random() * (b - a + 1)) + a;
}

// Launch a fresh real-browser session with stealth shims layered on top of
// puppeteer-real-browser's existing rebrowser-puppeteer-core patches.
async function launch() {
  // Launch options live in profile.js so fingerprint.js measures the same
  // browser configuration this solves with. A launch flag can move the TLS
  // layer, and measuring a differently-flagged browser answers the wrong
  // question.
  const result = await connect(CONNECT_OPTIONS);

  const { browser, page } = result;

  // Track the handle and the chromium PID so cleanup() can kill the whole tree
  // even if browser.close() never runs (timeout, kill -9 from blaze, etc.).
  trackBrowser(browser);

  // Read the actual Chromium build so the caller can compare it to the emulated
  // Chrome major. cf_clearance is bound to the JA4 of the session that issued
  // it — if this Chromium is 147 but gofire replays as 151, the cookie dies
  // under load. `fpcheck -via-chromium` measures that difference directly.
  let chromiumVersion = "";
  let chromiumMajorVersion = 0;
  try {
    chromiumVersion = await browser.version(); // e.g. "HeadlessChrome/151.0.7204.50"
    chromiumMajorVersion = parseChromiumMajor(chromiumVersion);
  } catch {}

  // Force the gofire-matching identity before any navigation.
  //
  // The metadata argument is not optional in practice: setUserAgent(ua) alone
  // clears the Client Hints rather than leaving them alone, so the session ends
  // up claiming Chrome 151 in User-Agent while sending no sec-ch-ua at all —
  // a combination no real Chrome emits, on the very request that earns
  // cf_clearance. See profile.js for the measurement.
  await page.setUserAgent(TARGET_UA, UA_METADATA);

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

  return { browser, page, chromiumVersion, chromiumMajor: chromiumMajorVersion };
}

// Wait until cf_clearance appears for the target origin, or until the page
// leaves the challenge state. Returns:
//
//   {cleared: true,  cookie}                 clearance issued
//   {cleared: false, challenged: false}      no challenge was ever presented
//   {cleared: false, challenged: true}       still challenged at the deadline
//
// The challenged flag is what tells the caller whether a retry has anything to
// retry: a site with no challenge at all has already given us everything it is
// going to, and relaunching the browser for it only costs another cold start.
async function waitForClearance(browser, page, deadline) {
  while (Date.now() < deadline) {
    const cookies = await cookiesForUrl(browser, page, url);
    const cf = cookies.find((c) => c.name === "cf_clearance");
    if (cf) return { cleared: true, cookie: cf };

    const title = await page.title().catch(() => "");
    if (
      title &&
      !/just a moment|attention required|checking your browser|verify you are human/i.test(
        title
      )
    ) {
      // Page is past the challenge gate even without an explicit clearance
      // cookie (some sites use Bot Fight Mode without UAM).
      return { cleared: false, challenged: false };
    }
    await sleep(500);
  }
  return { cleared: false, challenged: true };
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
//
// attemptDeadline is a wall-clock timestamp (ms); page.goto and waitForClearance
// both honor it, and solve() sizes it so an attempt cannot consume the budget
// its own retry needs.
//
// Two structural notes, both of which were bugs:
//
//   - launch() is inside the try. A failed connect() (no Xvfb, missing Chromium,
//     a port race) used to escape attempt() entirely and abort the run from
//     solve()'s outermost catch, so the retry documented at the top of this file
//     never covered the one failure a retry helps most with.
//   - the browser is closed in finally rather than handed back for the caller to
//     close. The caller then had to clear the module-level handle too, and the
//     check that did so compared against a field it had already set to undefined
//     — so it never fired, and cleanup's "graceful close" always ran against a
//     dead handle.
async function attempt(attemptNum, attemptDeadline) {
  let browser = null;
  let chromiumVersion = "";
  let chromiumMajor = 0;

  try {
    const launched = await launch();
    browser = launched.browser;
    chromiumVersion = launched.chromiumVersion;
    chromiumMajor = launched.chromiumMajor;
    const page = launched.page;

    const budgetMs = Math.max(1000, attemptDeadline - Date.now());

    await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: budgetMs,
    });

    const outcome = await waitForClearance(browser, page, attemptDeadline);
    if (!outcome.cleared && outcome.challenged && attemptNum < MAX_ATTEMPTS) {
      // Still sitting on a challenge with a retry left. A fresh tab often gets
      // a different challenge variant, so signal the caller rather than
      // harvesting a jar we know has no clearance in it.
      return { status: "no_clearance", chromiumVersion, chromiumMajor };
    }

    // Whether clearance was present or not, harvest behavior data so even
    // bot-fight-mode-only sites get a strong __cf_bm.
    await simulateHumanBehavior(page);

    // Re-read cookies post-behavior (interaction can elevate __cf_bm).
    const cookies = await cookiesForUrl(browser, page, url);
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
      chromiumVersion,
      chromiumMajor,
    };
  } catch (err) {
    return {
      status: "error",
      error: errorMessage(err),
      chromiumVersion,
      chromiumMajor,
    };
  } finally {
    // Always tear the session down before the caller decides whether to retry:
    // a reused session carries stale fingerprint state into the next attempt.
    if (browser) {
      try {
        await browser.close();
      } catch {}
      untrackBrowser(browser);
    }
  }
}

async function solve() {
  const startTs = Date.now();
  // Single overall deadline shared by every attempt, so the solver cannot
  // overshoot the parent's (blaze's) outer timeout. The per-attempt split below
  // is what keeps a slow first attempt from leaving the second with no time.
  const overallDeadline = startTs + TIMEOUT_MS;
  let lastResult = null;
  let attemptsMade = 0;

  for (let i = 1; i <= MAX_ATTEMPTS; i++) {
    // Stop early if we've already overshot the global deadline.
    if (Date.now() >= overallDeadline) break;

    // Give a non-final attempt only part of what is left, so a first attempt
    // that sits on a challenge until the deadline cannot leave the retry with
    // no time to run in. The last attempt gets everything that remains.
    const remaining = overallDeadline - Date.now();
    const attemptDeadline =
      i < MAX_ATTEMPTS
        ? Date.now() + Math.round(remaining * 0.6)
        : overallDeadline;

    const r = await attempt(i, attemptDeadline);
    lastResult = r;
    attemptsMade = i;

    if (r.status === "ok") {
      const out = {
        status: "ok",
        url: r.url,
        user_agent: r.user_agent,
        cookies: r.cookies,
        cookie_list: r.cookie_list,
        duration_ms: Date.now() - startTs,
        attempts: i,
        chromium_version: r.chromiumVersion || "",
        chromium_major: r.chromiumMajor || 0,
      };
      console.log(JSON.stringify(out));
      return;
    }

    // Non-ok and we have another attempt: small jittered backoff so the
    // retry hits the edge with a clean PoP rotation, but only if we still
    // have meaningful time left.
    if (i < MAX_ATTEMPTS && overallDeadline - Date.now() > 3_000) {
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
      attempts: attemptsMade,
      chromium_version: lastResult.chromiumVersion || "",
      chromium_major: lastResult.chromiumMajor || 0,
    };
    console.log(JSON.stringify(out));
    return;
  }

  console.log(
    JSON.stringify({
      status: "error",
      error: (lastResult && lastResult.error) || "solve failed",
      duration_ms: Date.now() - startTs,
      attempts: attemptsMade,
      chromium_version: (lastResult && lastResult.chromiumVersion) || "",
      chromium_major: (lastResult && lastResult.chromiumMajor) || 0,
    })
  );
}

solve().catch((err) => {
  console.log(
    JSON.stringify({ status: "error", error: errorMessage(err) })
  );
  process.exit(1);
});
