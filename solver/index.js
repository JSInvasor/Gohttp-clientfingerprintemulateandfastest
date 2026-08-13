// Single-shot Cloudflare UAM solver.
//
// Usage:
//   node solver/index.js <url> [timeout_sec=150]
//
// Environment:
//   SOLVER_PROXY   scheme://[user:pass@]host:port — solve through this proxy.
//                  cf_clearance is bound to the issuing IP, so a cookie earned
//                  here and replayed from a different exit is dead on arrival.
//   SOLVER_LANG    the Accept-Language to solve with, e.g. "en-US,en;q=0.9".
//                  `send` passes whatever the run will replay with. Left unset
//                  the browser used the box's locale, which on a localised image
//                  is a language the replay never asks for — and which the
//                  navigator.languages shim below then contradicted.
//   SOLVER_UA, SOLVER_SEC_CH_UA, SOLVER_PLATFORM
//                  re-pin the identity when solving from a box whose OS or
//                  Chrome major differs; see profile.js.
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
//     "proxy": "<host:port>",                 // "" when solved direct
//     "launch_ms": <int>,                     // browser startup, out of the budget
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
  TARGET_LANG,
  TARGET_UA,
  connectOptions,
  languageList,
  parseProxyURL,
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
import { detectChallengeInPage, isChallengeTitle } from "./challenge.js";
import { withDeadline } from "./deadline.js";

const MAX_ATTEMPTS = 2;
// 75 was too small on a real box. Chromium under Xvfb takes ~20s to come up,
// the budget is split across two attempts, and the launch is charged against
// each — so a 75s budget left one attempt 25s of solving and the other 9s, and
// a managed challenge with a Turnstile widget needs 15-30s. Measured against a
// live UAM: 75s failed with no cookie at all, 180s solved on the first attempt
// in 71s. The default is the value that works unattended; a fast machine simply
// finishes early, since the budget is a ceiling and not a wait.
const DEFAULT_TIMEOUT_SEC = 150;

// Exactly one result line is ever printed. Every exit path goes through
// finish(), and this guard is what keeps a late watchdog or a stray rejection
// from appending a second line after the answer is already out.
let finished = false;

// Everything below is written to the single-JSON-line contract in the header
// comment, so usage errors go to stdout in the same shape a caller parses.
function die(message, code = 1) {
  finish({ status: "error", error: message }, code);
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

// SOLVER_PROXY routes the solve through the same exit the replay will use.
// Parsed up front for the same reason as the hints: a malformed proxy URL
// should not cost a browser launch to discover.
let CONNECT_OPTS;
let PROXY_LABEL = "";
try {
  CONNECT_OPTS = connectOptions({ proxy: process.env.SOLVER_PROXY });
  const parsed = parseProxyURL(process.env.SOLVER_PROXY);
  if (parsed) PROXY_LABEL = `${parsed.host}:${parsed.port}`; // credentials stay out of the output
} catch (err) {
  die(errorMessage(err));
}

// Kill the Chromium tree on every exit path — signals, exceptions, normal
// return. See cleanup.js for why this is not done with an env-var pkill sweep.
installExitHandlers({
  onFatal: (err) => {
    if (!err || finished) return;
    finished = true;
    try {
      process.stdout.write(JSON.stringify({ status: "error", error: errorMessage(err) }) + "\n");
    } catch {}
  },
});

// Hard backstop: even if the run hangs forever, we self-terminate at
// (timeout + 30s) so we never become the zombie ourselves.
setTimeout(() => {
  finish({ status: "error", error: "watchdog timeout" }, 2);
}, TIMEOUT_MS + 30_000).unref();

// finish prints the one result line and ends the process.
//
// Returning from solve() and letting the event loop drain was not enough:
// puppeteer-real-browser leaves handles behind — an Xvfb session, a
// chrome-launcher child — that keep node alive after the answer is known. A run
// that had already printed its error at 1.1s sat there until the watchdog fired
// and printed a *second* JSON line, and a caller reading the last line saw
// "watchdog timeout" instead of the real cause.
//
// The write callback is what makes this safe: process.exit() truncates pending
// stdout on a pipe, which is exactly how this is invoked.
function finish(result, code = 0) {
  if (finished) return;
  finished = true;
  const line = JSON.stringify(result) + "\n";
  try {
    process.stdout.write(line, () => {
      cleanup();
      process.exit(code);
    });
  } catch {
    cleanup();
    process.exit(code);
  }
  // Backstop for a stdout that never drains (a closed pipe, a full buffer).
  setTimeout(() => {
    cleanup();
    process.exit(code);
  }, 2000).unref();
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
  // Launch options live in profile.js so fingerprint.js measures the same
  // browser configuration this solves with. A launch flag can move the TLS
  // layer, and measuring a differently-flagged browser answers the wrong
  // question.
  const result = await connect(CONNECT_OPTS);

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
  //
  // The metadata is rebuilt here rather than reused from startup so the
  // high-entropy hints can carry this browser's real build. UA_METADATA was
  // still worth building up front: it fails on a bad pin before a browser is
  // launched, which is the expensive way to find out.
  await page.setUserAgent(
    TARGET_UA,
    userAgentMetadata(undefined, undefined, undefined, undefined, chromiumVersion)
  );

  // Stealth shim, singular.
  //
  // This used to also overwrite navigator.webdriver and navigator.plugins.
  // Measured against this browser with the shims on and off, both were making
  // the fingerprint worse than leaving it alone:
  //
  //                              shimmed              untouched
  //   navigator.webdriver        undefined            false
  //   own property on navigator  true                 false
  //   plugins.length             3                    5
  //   toString(plugins)          [object Array]       [object PluginArray]
  //   typeof plugins.item        undefined            function
  //   toString(plugins[0])       [object Object]      [object Plugin]
  //
  // puppeteer-real-browser's rebrowser patches already report webdriver as
  // false, which is what a real Chrome reports — undefined is not a stealthier
  // false, it is a value no browser produces, and defining it on the instance
  // leaves an own property that Navigator.prototype never has. The plugins
  // override replaced a genuine PluginArray of five Plugin objects with a plain
  // Array of three plain objects: three separate tells in one property, plus a
  // plugins/mimeTypes pair (3 and 2) that no Chrome ever emits.
  //
  // languages is the one that earns its place. Chrome sends the full
  // Accept-Language list — en-US,en;q=0.9 — while navigator.languages reports
  // only the primary tag, and a header advertising a language the page object
  // does not list is the kind of contradiction the rest of this repo exists to
  // avoid. Restoring the remaining entries makes the two agree.
  //
  // The list comes from TARGET_LANG rather than a literal. It used to be a
  // hardcoded ["en-US", "en"], which was correct only for as long as the box's
  // locale happened to be en-US: on any other image the shim asserted a language
  // the browser was not asking for, manufacturing the very contradiction it was
  // written to remove. Now --accept-lang, --lang and this all read one value.
  await page.evaluateOnNewDocument((languages) => {
    try {
      Object.defineProperty(navigator, "languages", {
        get: () => languages,
      });
    } catch {}
  }, languageList(TARGET_LANG));

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

    // Structure first, wording second. The markers are language-independent, so
    // a localised or reworded interstitial keeps its budget instead of being
    // read as "this site never challenged us" — see challenge.js. A probe that
    // cannot run (an execution context torn down mid-navigation) answers null
    // and leaves the decision to the title exactly as before.
    const challenged = await page.evaluate(detectChallengeInPage).catch(() => null);
    if (challenged !== true) {
      const title = await page.title().catch(() => "");
      if (title && !isChallengeTitle(title)) {
        // Page is past the challenge gate even without an explicit clearance
        // cookie (some sites use Bot Fight Mode without UAM).
        return { cleared: false, challenged: false };
      }
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

// harvest reads the session's cookies for the target and shapes the result the
// caller prints. Status is decided by the cookie that matters: everything else
// in the jar is context.
async function harvest(browser, page) {
  const cookies = await cookiesForUrl(browser, page, url);
  const userAgent = await page.evaluate(() => navigator.userAgent).catch(() => TARGET_UA);
  const finalUrl = (() => {
    try {
      return page.url();
    } catch {
      return url;
    }
  })();

  return {
    status: cookies.some((c) => c.name === "cf_clearance") ? "ok" : "no_clearance",
    url: finalUrl,
    user_agent: userAgent,
    cookies: cookies.map((c) => `${c.name}=${c.value}`).join("; "),
    cookie_list: cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      expires: c.expires,
    })),
  };
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
  let page = null;
  let chromiumVersion = "";
  let chromiumMajor = 0;
  let launchMs = 0;

  try {
    // connect() is unbounded on its own, and on a slow box it is the longest
    // step in the attempt: a 90-second budget produced a 111-second run because
    // two launches happened outside it. Racing it against the deadline keeps
    // the budget meaning what it says, and a launch that loses the race is a
    // real failure — the alternative is a browser nobody is waiting for.
    const launchStart = Date.now();
    const launched = await withDeadline(
      launch(),
      attemptDeadline,
      "browser launch did not finish before the attempt deadline",
      // A launch that lost the race still comes up. Closing it here is what
      // keeps the retry from running beside a full Chromium nobody owns —
      // cleanup() would only collect it at process exit, which on the box this
      // is tuned for is the difference between one browser and two.
      (late) => {
        if (!late || !late.browser) return;
        untrackBrowser(late.browser);
        return late.browser.close();
      }
    );
    launchMs = Date.now() - launchStart;
    browser = launched.browser;
    chromiumVersion = launched.chromiumVersion;
    chromiumMajor = launched.chromiumMajor;
    page = launched.page;

    const budgetMs = Math.max(1000, attemptDeadline - Date.now());

    await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: budgetMs,
    });

    const outcome = await waitForClearance(browser, page, attemptDeadline);
    if (!outcome.cleared && outcome.challenged && attemptNum < MAX_ATTEMPTS) {
      // Still sitting on a challenge with a retry left. A fresh tab often gets
      // a different challenge variant, so skip the behavior simulation and let
      // the caller start over — but read the jar first. __cf_bm is set by the
      // challenge page itself, and abandoning the attempt used to throw it away,
      // so a run whose retry also failed reported nothing at all when it had in
      // fact collected something usable.
      return { ...(await harvest(browser, page)), chromiumVersion, chromiumMajor, launchMs };
    }

    // Whether clearance was present or not, harvest behavior data so even
    // bot-fight-mode-only sites get a strong __cf_bm.
    await simulateHumanBehavior(page);

    // Re-read cookies post-behavior (interaction can elevate __cf_bm).
    return { ...(await harvest(browser, page)), chromiumVersion, chromiumMajor, launchMs };
  } catch (err) {
    // Harvest before giving up. A navigation timeout or a deadline hit is not a
    // reason to throw away cookies the challenge page already set — a run whose
    // goto timed out reported nothing at all, when the jar held the challenge's
    // own cookies. The error is still what the status reports; the cookies ride
    // along so the caller and solve()'s best-attempt pick can use them.
    const salvaged = browser
      ? await harvest(browser, page).catch(() => null)
      : null;
    return {
      ...(salvaged || {}),
      status: "error",
      error: errorMessage(err),
      chromiumVersion,
      chromiumMajor,
      launchMs,
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

// betterResult ranks two attempts: a clearance beats anything, then more
// cookies, then anything at all over an error. It exists so the retry is a
// second chance rather than a replacement.
function rankResult(r) {
  if (!r) return -1;
  if (r.status === "ok") return 1_000_000;
  return (r.cookie_list || []).length;
}

function betterResult(a, b) {
  return rankResult(b) > rankResult(a) ? b : a || b;
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
    attemptsMade = i;
    // Keep the best attempt, not the most recent one. A retry that fails to
    // launch, or lands on a harder challenge variant, must not erase cookies
    // the earlier attempt already collected.
    lastResult = betterResult(lastResult, r);

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
        proxy: PROXY_LABEL,
        launch_ms: r.launchMs || 0,
      };
      return finish(out);
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
      proxy: PROXY_LABEL,
      launch_ms: lastResult.launchMs || 0,
    };
    return finish(out);
  }

  return finish({
    status: "error",
    error: (lastResult && lastResult.error) || "solve failed",
    duration_ms: Date.now() - startTs,
    attempts: attemptsMade,
    chromium_version: (lastResult && lastResult.chromiumVersion) || "",
    chromium_major: (lastResult && lastResult.chromiumMajor) || 0,
    proxy: PROXY_LABEL,
    launch_ms: (lastResult && lastResult.launchMs) || 0,
  }, 1);
}

solve().catch((err) => finish({ status: "error", error: errorMessage(err) }, 1));
