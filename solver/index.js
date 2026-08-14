// Cloudflare UAM solver: one exit, or a list of them through one browser.
//
// Usage:
//   node solver/index.js <url> [timeout_sec=150]
//   node solver/index.js <url> [timeout_sec=150] --batch   < jobs.json
//
// --batch reads the exits from stdin (see jobs.js) and works them through a
// single Chromium, one BrowserContext each, printing one result line per exit as
// it finishes. The launch is what makes this worth doing: it costs ~20s on a
// small VPS and a browser per exit spent that on every one of them — half an
// hour of pure startup for a hundred exits, against once for the batch.
//
// Environment:
//   SOLVER_PROXY   scheme://[user:pass@]host:port — solve through this proxy.
//                  cf_clearance is bound to the issuing IP, so a cookie earned
//                  here and replayed from a different exit is dead on arrival.
//   SOLVER_LANG    the Accept-Language to solve with, e.g. "en-US,en;q=0.9".
//                  `send` passes whatever the run will replay with. Left unset
//                  the browser used the box's locale, which on a localised image
//                  is a language the replay never asks for. It reaches the
//                  header through --accept-lang and navigator.languages through
//                  preparePage's pinLanguage; both are needed, and only the
//                  second one is detectable from inside the page.
//   SOLVER_UA, SOLVER_SEC_CH_UA, SOLVER_PLATFORM
//                  re-pin the identity when solving from a box whose OS or
//                  Chrome major differs; see profile.js.
//
// Output (stdout, one JSON line; in --batch one line per exit, each carrying an
// extra "exit" field echoing the id it was given):
//   { "status": "ok"|"no_clearance"|"error",
//     "url": "<final url>",
//     "user_agent": "<navigator.userAgent>",
//     "accept_language": "<what the browser actually sent, not what was asked>",
//     "page_languages": ["en-US", "en"],       // navigator.languages, to check
//                                              // against accept_language
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
  parseProxyURL,
  preferenceList,
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
import { parseJobs, readAll } from "./jobs.js";

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

// Flags are pulled out before the positionals are read, or --batch would land
// in the timeout slot and be rejected as a non-number.
const ARGV = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const BATCH = process.argv.slice(2).includes("--batch");

const url = ARGV[0];
if (!url) {
  die("usage: node solver/index.js <url> [timeout_sec] [--batch]");
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

const TIMEOUT_MS = Math.round(parseTimeoutSec(ARGV[1]) * 1000);

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

// Hard backstop: even if the run hangs forever, we self-terminate so we never
// become the zombie ourselves.
//
// A batch is sized in rounds rather than in exits: exits run parallel at a time,
// so the wall clock is ceil(exits/parallel) budgets, not one. Arming it for a
// single budget would have killed every batch of more than `parallel` exits at
// the first round boundary — and it would have looked like the target timing
// out. The batch arms this itself once the job list has been read, because
// until then the number of rounds is not known.
let watchdog = null;
function armWatchdog(budgetMs) {
  if (watchdog) clearTimeout(watchdog);
  watchdog = setTimeout(() => {
    finish({ status: "error", error: "watchdog timeout" }, 2);
  }, budgetMs + 30_000);
  watchdog.unref();
}
armWatchdog(TIMEOUT_MS);

// emit writes one NDJSON result line, for a batch where there are many.
//
// Separate from finish() because the invariants are opposite: finish() prints
// the last line and ends the process, and is guarded so a late watchdog cannot
// append a second. A batch prints one line per exit as it completes and keeps
// going. The guard is still honoured — once something has ended the run, no
// further results are claimed.
function emit(result) {
  if (finished) return;
  try {
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch {}
}

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

  await preparePage(page, chromiumVersion);

  return { browser, page, chromiumVersion, chromiumMajor: chromiumMajorVersion };
}

// preparePage puts the gofire-matching identity on a page before it navigates.
//
// Every page a solve drives goes through this, whether it is the one connect()
// handed back or one opened in a context of its own. A page that missed it
// would carry the browser's own identity into the request that earns the
// cookie, which is the mismatch this whole file exists to prevent — and in
// batch mode there are as many pages as there are exits.
async function preparePage(page, chromiumVersion) {
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
  const metadata = userAgentMetadata(
    undefined,
    undefined,
    undefined,
    undefined,
    chromiumVersion
  );
  await page.setUserAgent(TARGET_UA, metadata);

  // And the language, in the same override, because puppeteer's setUserAgent
  // does not carry it. See pinLanguage: this is the half that moves
  // navigator.languages.
  await pinLanguage(page, metadata);

  // No stealth shims at all, and each one was removed for the same reason: it
  // asserted something no real Chrome reports, through a mechanism a page can
  // see.
  //
  // webdriver and plugins went first. Measured against this browser with the
  // shims on and off:
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
  // Array of three plain objects.
  //
  // languages was the last one, and removing it was half right — right about the
  // mechanism, wrong about the value, and the wrong half was the expensive one.
  //
  // Right about the mechanism. Object.defineProperty(navigator, "languages")
  // leaves an own property on the instance where Navigator.prototype is the only
  // place one belongs, and an accessor that stringifies as an arrow function
  // where every native one reads [native code]:
  //
  //                              shimmed              untouched
  //   own property on navigator  true                 false
  //   getter toString            () => languages      [native code]
  //
  // Both are one probe away on the request that earns cf_clearance, and no value
  // is worth asserting that way.
  //
  // Wrong about the value. The claim that replaced the shim was that ["en-US"]
  // beside a header of en-US,en;q=0.9 is "what Chrome does". It is what a
  // *bare-profile Chromium* does. Measured here on 141, one row per launch, a
  // local server reading the header and the page reporting its own object:
  //
  //   --accept-lang=      header sent      navigator.languages
  //   (unset)             en-US,en;q=0.9   ["en-US"]
  //   en-US               en-US,en;q=0.9   ["en-US"]
  //   en-US,en            en-US,en;q=0.9   ["en-US"]
  //
  // Three configurations, one page object, and in every one of them the header
  // advertises an "en" that navigator.languages does not list. An ordinary
  // Chrome install carries the pref "en-US,en" and reports ["en-US", "en"];
  // this is a fresh --user-data-dir with no locale state, and it collapses. So
  // the contradiction was real, the shim had been covering it, and removing the
  // shim without replacing it put it back on the wire.
  //
  // Replaced where it is not a shim at all. Emulation.setUserAgentOverride takes
  // an acceptLanguage, and Chromium applies it to the header and to the page
  // object together — from inside, so there is nothing on navigator to find.
  // Same probe, same browser, through pinLanguage:
  //
  //   navigator.languages        ["en-US", "en"]
  //   own property on navigator  false
  //   getter toString            function get languages() { [native code] }
  //
  // See pinLanguage for why the value handed to it must be the preference list
  // and not a finished header.
  watchAcceptLanguage(page);
}

// pinLanguage puts the run's language on the header and on navigator.languages
// in one call, natively.
//
// puppeteer's setUserAgent sends Emulation.setUserAgentOverride but exposes only
// userAgent and userAgentMetadata; the protocol's third field, acceptLanguage,
// is the one that moves the page object. So this re-sends the same override with
// all three, which is why it takes the metadata: the call replaces its
// predecessor wholesale rather than merging, and leaving the Client Hints out
// here would clear the ones setUserAgent had just set.
//
// The value is the preference list — "en-US,en" — not the header. Handing it
// TARGET_LANG verbatim is measured to corrupt both halves at once:
//
//   acceptLanguage       header sent           navigator.languages
//   en-US,en             en-US,en;q=0.9        ["en-US", "en"]
//   en-US,en;q=0.9       en-US,en;q=0.9;q=0.9  ["en-US", "en;q=0.9"]
//
// A doubled quality parameter and a q-value inside a language tag, neither of
// which any browser emits.
//
// Best effort, deliberately. A CDP session is the one part of preparePage that
// can fail for reasons that have nothing to do with the identity — a puppeteer
// build without page.createCDPSession, a target that went away mid-launch — and
// the fallback is the behaviour of the previous release rather than a dead
// solve. The UA and the hints are already pinned by the caller either way.
async function pinLanguage(page, metadata) {
  const acceptLanguage = preferenceList(TARGET_LANG);
  if (!acceptLanguage) return;
  try {
    // Kept for the life of the page: an emulation override belongs to the
    // session that set it, and detaching would hand the language back to the
    // browser default at the first navigation. The page outlives nothing here —
    // attempt() closes it — so there is no session to leak.
    const client = await cdpSession(page);
    await client.send("Emulation.setUserAgentOverride", {
      userAgent: TARGET_UA,
      acceptLanguage,
      userAgentMetadata: metadata,
    });
    cdpSessions.set(page, client);
  } catch (err) {
    // Worth a line: the run continues with the header pinned by --accept-lang
    // and navigator.languages left where the browser had it, which is the
    // mismatch described above rather than a broken solve.
    process.stderr.write(
      `solver: could not pin navigator.languages (${errorMessage(err)}); ` +
        `continuing with the launch flag only\n`
    );
  }
}

// The CDP sessions pinLanguage opened, held so the override outlives the call
// and dropped when the page is collected.
const cdpSessions = new WeakMap();

// cdpSession opens a raw protocol session on a page across the two spellings
// puppeteer has had for it. page.createCDPSession is the current one;
// page.target().createCDPSession is what everything before it exposed, and
// puppeteer-real-browser pins its own fork rather than a version this file can
// assume.
function cdpSession(page) {
  if (typeof page.createCDPSession === "function") return page.createCDPSession();
  return page.target().createCDPSession();
}

// What the browser actually sent, per page.
//
// Asked for one thing, Chromium sends another: it regenerates the header from
// the first tag of --accept-lang and drops the rest, so a run started with
// -lang "tr-TR,tr;q=0.9,en;q=0.8" solves under "tr-TR,tr;q=0.9". Replaying with
// the value that was asked for would advertise a language the session that
// earned the cookie never did — the same class of handover mismatch as a stale
// UA, and just as quiet.
//
// Reported rather than predicted. The transform above is what this Chromium
// does; a different build is free to do something else, and a rule derived from
// one measurement would then be wrong in the one place nobody looks.
const observedAcceptLanguage = new WeakMap();

function watchAcceptLanguage(page) {
  page.on("request", (request) => {
    try {
      if (!request.isNavigationRequest()) return;
      if (request.frame() !== page.mainFrame()) return;
      const value = request.headers()["accept-language"];
      if (value) observedAcceptLanguage.set(page, value);
    } catch {}
  });
}

// acceptLanguageOf returns what was seen on this page's document request, or
// the value that was asked for when nothing was observed — an empty string here
// would read as "the solve sent no Accept-Language", which is a stronger claim
// than "it was not watched".
function acceptLanguageOf(page) {
  return observedAcceptLanguage.get(page) || TARGET_LANG;
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
async function waitForClearance(jar, page, deadline) {
  while (Date.now() < deadline) {
    const cookies = await cookiesForUrl(jar, page, url);
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
async function harvest(jar, page) {
  const cookies = await cookiesForUrl(jar, page, url);

  // The UA and the languages come back in one round trip, from the page rather
  // than from what was asked for.
  //
  // navigator.languages is here because it is the half of the language that the
  // wire cannot show. The header is observed by watchAcceptLanguage; this is the
  // page object beside it, and a solve where the two disagree is the bug this
  // pair was added to make impossible to ship again — a browser advertising
  // "en" it does not list is not a browser any ordinary Chrome install
  // produces. send compares them and says so.
  const identity = await page
    .evaluate(() => ({ userAgent: navigator.userAgent, languages: navigator.languages }))
    .catch(() => null);
  const userAgent = (identity && identity.userAgent) || TARGET_UA;
  const pageLanguages = (identity && identity.languages) || [];

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
    accept_language: acceptLanguageOf(page),
    page_languages: pageLanguages,
    cookies: cookies.map((c) => `${c.name}=${c.value}`).join("; "),
    cookie_list: cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      expires: c.expires,
    })),
  };
}

// A session is one isolated place to solve in: a page to drive, the jar its
// cookies come from, and the teardown that ends it.
//
// There are two ways to get one, and the difference between them is the whole
// point of batch mode:
//
//   ownBrowserSession    a fresh Chromium per attempt. On a small VPS that is
//                        ~20s of every attempt — the honest price of a clean
//                        profile when there is one exit, and 33 minutes of pure
//                        startup when there are a hundred.
//   sharedContextSession a fresh BrowserContext in a browser that is already
//                        up. Own cookie jar, own storage, and its own proxy:
//                        Chrome takes one per context through
//                        Target.createBrowserContext, not only on the command
//                        line. It costs milliseconds.
//
// Both hand back the same shape and everything below is written against it, so
// the solving logic cannot drift between the one-exit path and the list.
//
// What a context is not is a whole new profile. It is Chrome's incognito
// primitive: same process, same BoringSSL, so the JA3/JA4 the cookie is bound
// to is identical either way — which is the property that matters here. What it
// does share is the browser's own state (its build, its command-line flags), and
// that is shared deliberately. -solve-isolate goes back to a browser per exit
// for anyone who measures a reason to.
function ownBrowserSession() {
  return async (deadline) => {
    // connect() is unbounded on its own, and on a slow box it is the longest
    // step in the attempt: a 90-second budget produced a 111-second run because
    // two launches happened outside it. Racing it against the deadline keeps
    // the budget meaning what it says, and a launch that loses the race is a
    // real failure — the alternative is a browser nobody is waiting for.
    const launchStart = Date.now();
    const launched = await withDeadline(
      launch(),
      deadline,
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
    return {
      page: launched.page,
      jar: launched.browser,
      chromiumVersion: launched.chromiumVersion,
      chromiumMajor: launched.chromiumMajor,
      launchMs: Date.now() - launchStart,
      close: async () => {
        try {
          await launched.browser.close();
        } catch {}
        untrackBrowser(launched.browser);
      },
    };
  };
}

function sharedContextSession(shared, proxy) {
  const parsed = parseProxyURL(proxy);
  return async (deadline) => {
    const start = Date.now();
    const open = (async () => {
      const context = await shared.browser.createBrowserContext(
        parsed ? { proxyServer: `${parsed.host}:${parsed.port}` } : {}
      );
      try {
        const page = await context.newPage();

        // Credentials are applied here rather than left to
        // puppeteer-real-browser. Its pageController authenticates every new
        // page with the single proxy connect() was given — which in a batch is
        // no proxy at all, and would be the wrong one even if it were set, since
        // each exit brings its own.
        if (parsed && (parsed.username || parsed.password)) {
          await page.authenticate({ username: parsed.username, password: parsed.password });
        }
        await preparePage(page, shared.chromiumVersion);
        return { context, page };
      } catch (err) {
        await context.close().catch(() => {});
        throw err;
      }
    })();

    const { context, page } = await withDeadline(
      open,
      deadline,
      "opening a context did not finish before the attempt deadline",
      (late) => late && late.context && late.context.close()
    );

    return {
      page,
      // The jar is the context, never the browser. A shared browser's jar holds
      // every exit's cookies at once, so reading it would hand one exit the
      // cf_clearance another one earned — the exact mispairing the Go side
      // spends its effort preventing.
      jar: context,
      chromiumVersion: shared.chromiumVersion,
      chromiumMajor: shared.chromiumMajor,
      launchMs: Date.now() - start,
      close: () => context.close().catch(() => {}),
    };
  };
}

// One full attempt: open a session, navigate, wait for clearance, simulate
// behavior, capture cookies. Caller decides whether to retry on failure.
//
// attemptDeadline is a wall-clock timestamp (ms); page.goto and waitForClearance
// both honor it, and solveExit() sizes it so an attempt cannot consume the
// budget its own retry needs.
//
// Two structural notes, both of which were bugs:
//
//   - opening the session is inside the try. A failed connect() (no Xvfb,
//     missing Chromium, a port race) used to escape attempt() entirely and abort
//     the run from the outermost catch, so the retry documented at the top of
//     this file never covered the one failure a retry helps most with.
//   - the session is closed in finally rather than handed back for the caller to
//     close. The caller then had to clear the module-level handle too, and the
//     check that did so compared against a field it had already set to undefined
//     — so it never fired, and cleanup's "graceful close" always ran against a
//     dead handle.
async function attempt(newSession, attemptNum, attemptDeadline) {
  let session = null;
  let chromiumVersion = "";
  let chromiumMajor = 0;
  let launchMs = 0;

  try {
    session = await newSession(attemptDeadline);
    chromiumVersion = session.chromiumVersion;
    chromiumMajor = session.chromiumMajor;
    launchMs = session.launchMs;

    const { page, jar } = session;
    const budgetMs = Math.max(1000, attemptDeadline - Date.now());

    await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: budgetMs,
    });

    const outcome = await waitForClearance(jar, page, attemptDeadline);
    if (!outcome.cleared && outcome.challenged && attemptNum < MAX_ATTEMPTS) {
      // Still sitting on a challenge with a retry left. A fresh tab often gets
      // a different challenge variant, so skip the behavior simulation and let
      // the caller start over — but read the jar first. __cf_bm is set by the
      // challenge page itself, and abandoning the attempt used to throw it away,
      // so a run whose retry also failed reported nothing at all when it had in
      // fact collected something usable.
      return { ...(await harvest(jar, page)), chromiumVersion, chromiumMajor, launchMs };
    }

    // Whether clearance was present or not, harvest behavior data so even
    // bot-fight-mode-only sites get a strong __cf_bm.
    await simulateHumanBehavior(page);

    // Re-read cookies post-behavior (interaction can elevate __cf_bm).
    return { ...(await harvest(jar, page)), chromiumVersion, chromiumMajor, launchMs };
  } catch (err) {
    // Harvest before giving up. A navigation timeout or a deadline hit is not a
    // reason to throw away cookies the challenge page already set — a run whose
    // goto timed out reported nothing at all, when the jar held the challenge's
    // own cookies. The error is still what the status reports; the cookies ride
    // along so the caller and solveExit()'s best-attempt pick can use them.
    const salvaged = session
      ? await harvest(session.jar, session.page).catch(() => null)
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
    if (session) {
      try {
        await session.close();
      } catch {}
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

// solveExit works one exit to a conclusion and returns the result object.
//
// budgetMs is this exit's whole share of the clock. In single mode that is the
// run's timeout; in a batch every exit gets the same share, and the rounds they
// run in are what the caller's watchdog is sized against.
async function solveExit(newSession, budgetMs, proxyLabel) {
  const startTs = Date.now();
  // Single overall deadline shared by every attempt, so an exit cannot overshoot
  // the budget the caller sized its watchdog against. The per-attempt split
  // below is what keeps a slow first attempt from leaving the second with none.
  const overallDeadline = startTs + budgetMs;
  let lastResult = null;
  let attemptsMade = 0;

  for (let i = 1; i <= MAX_ATTEMPTS; i++) {
    // Stop early if we've already overshot the deadline.
    if (Date.now() >= overallDeadline) break;

    // Give a non-final attempt only part of what is left, so a first attempt
    // that sits on a challenge until the deadline cannot leave the retry with
    // no time to run in. The last attempt gets everything that remains.
    const remaining = overallDeadline - Date.now();
    const attemptDeadline =
      i < MAX_ATTEMPTS
        ? Date.now() + Math.round(remaining * 0.6)
        : overallDeadline;

    const r = await attempt(newSession, i, attemptDeadline);
    attemptsMade = i;
    // Keep the best attempt, not the most recent one. A retry that fails to
    // launch, or lands on a harder challenge variant, must not erase cookies
    // the earlier attempt already collected.
    lastResult = betterResult(lastResult, r);

    if (r.status === "ok") {
      return {
        status: "ok",
        url: r.url,
        user_agent: r.user_agent,
        accept_language: r.accept_language || TARGET_LANG,
        page_languages: r.page_languages || [],
        cookies: r.cookies,
        cookie_list: r.cookie_list,
        duration_ms: Date.now() - startTs,
        attempts: i,
        chromium_version: r.chromiumVersion || "",
        chromium_major: r.chromiumMajor || 0,
        proxy: proxyLabel,
        launch_ms: r.launchMs || 0,
      };
    }

    // Non-ok and we have another attempt: small jittered backoff so the
    // retry hits the edge with a clean PoP rotation, but only if we still
    // have meaningful time left.
    if (i < MAX_ATTEMPTS && overallDeadline - Date.now() > 3_000) {
      await sleep(rand(800, 1500));
    }
  }

  // All attempts exhausted.
  const base = {
    duration_ms: Date.now() - startTs,
    attempts: attemptsMade,
    chromium_version: (lastResult && lastResult.chromiumVersion) || "",
    chromium_major: (lastResult && lastResult.chromiumMajor) || 0,
    proxy: proxyLabel,
    launch_ms: (lastResult && lastResult.launchMs) || 0,
  };
  if (lastResult && lastResult.status === "no_clearance") {
    return {
      status: "no_clearance",
      url: lastResult.url || url,
      user_agent: lastResult.user_agent || TARGET_UA,
      accept_language: lastResult.accept_language || TARGET_LANG,
      page_languages: lastResult.page_languages || [],
      cookies: lastResult.cookies || "",
      cookie_list: lastResult.cookie_list || [],
      ...base,
    };
  }
  return {
    status: "error",
    error: (lastResult && lastResult.error) || "solve failed",
    ...base,
  };
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

// solveSingle is the original contract: one exit from SOLVER_PROXY, one browser,
// one JSON line. Unchanged on purpose — one exit does not need a shared browser,
// and leaving this path exactly as it was is what keeps the common case off the
// newer machinery.
async function solveSingle() {
  const out = await solveExit(ownBrowserSession(), TIMEOUT_MS, PROXY_LABEL);
  return finish(out, out.status === "error" ? 1 : 0);
}

// solveBatch works a list of exits through one browser.
//
// The launch is paid once instead of once per exit, which is the entire saving:
// on a small VPS Chromium takes ~20s to come up, so a hundred exits spent over
// half an hour doing nothing but starting browsers. Contexts cost milliseconds.
//
// Results stream out as NDJSON, one line per exit as it finishes, rather than a
// single object at the end. A batch runs for minutes and the caller can act on
// the exits that are ready — and if the process dies halfway, the exits that
// did solve have already been reported rather than lost with it.
async function solveBatch(job) {
  // Rounds, not exits: `parallel` of them run at a time, so the wall clock is
  // ceil(exits/parallel) budgets. The caller sizes its own timeout the same way.
  const rounds = Math.ceil(job.exits.length / job.parallel);
  armWatchdog(rounds * TIMEOUT_MS);

  const shared = await withDeadline(
    launch(),
    Date.now() + TIMEOUT_MS,
    "browser launch did not finish before the batch deadline",
    (late) => {
      if (!late || !late.browser) return;
      untrackBrowser(late.browser);
      return late.browser.close();
    }
  );

  const queue = job.exits.slice();
  const runner = async () => {
    for (;;) {
      const exit = queue.shift();
      if (!exit) return;
      let out;
      try {
        out = await solveExit(
          sharedContextSession(shared, exit.proxy),
          TIMEOUT_MS,
          proxyLabel(exit.proxy)
        );
      } catch (err) {
        // solveExit is written not to throw; this is the backstop that keeps one
        // exit's surprise from taking the whole batch and every result with it.
        out = { status: "error", error: errorMessage(err), proxy: proxyLabel(exit.proxy) };
      }
      emit({ exit: exit.id, ...out });
    }
  };

  await Promise.all(Array.from({ length: job.parallel }, runner));

  try {
    await shared.browser.close();
  } catch {}
  untrackBrowser(shared.browser);

  cleanup();
  process.exit(0);
}

// proxyLabel names an exit without its credentials, the same way the Go side
// redacts them: this goes to stdout and from there into logs.
function proxyLabel(proxy) {
  try {
    const parsed = parseProxyURL(proxy);
    return parsed ? `${parsed.host}:${parsed.port}` : "";
  } catch {
    return "";
  }
}

async function main() {
  if (!BATCH) return solveSingle();

  let job;
  try {
    job = parseJobs(await readAll(process.stdin));
  } catch (err) {
    die(errorMessage(err));
    return;
  }
  // Every proxy is parsed before the browser starts, for the same reason the
  // Client Hints are: finding out about a malformed one after a launch is an
  // expensive way to learn it, and in a batch it would strand the exits behind
  // it too.
  for (const exit of job.exits) {
    try {
      parseProxyURL(exit.proxy);
    } catch (err) {
      die(`exit ${exit.id}: ${errorMessage(err)}`);
      return;
    }
  }
  return solveBatch(job);
}

main().catch((err) => finish({ status: "error", error: errorMessage(err) }, 1));
