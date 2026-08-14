// Measures the real fingerprint of the Chromium this repo drives.
//
// Usage:
//   node solver/fingerprint.js <url> [timeout_sec=60]
//
// Output (stdout, single JSON line):
//   { "status": "ok",
//     "chromium_version": "HeadlessChrome/151.0.7204.50",
//     "chromium_major": 151,
//     "native_user_agent": "<what this Chromium reports for itself>",
//     "solver_user_agent": "<the UA index.js pins, from profile.js>",
//     "solver_sec_ch_ua": "<the Client Hints index.js pins alongside it>",
//     "capture": { ... the fingerprint endpoint's JSON ... } }
//   { "status": "error", "error": "<message>" }
//
// Why this exists: the solver earns cf_clearance with a real browser and gofire
// replays it with an emulated ClientHello. Cloudflare binds the cookie to the
// issuing session's fingerprint, so those two have to be the same browser. That
// was previously an assumption maintained by hand — index.js pinned a UA in a
// comment and nothing checked it. This makes it measurable:
// `fpcheck -via-chromium` runs this, then diffs the result against what the Go
// client emits.
//
// Deliberately does NOT call page.setUserAgent. index.js overrides the UA so
// the solved session matches gofire; here we want the browser's own identity,
// because the question being answered is "what browser is actually installed
// on this box". The pinned UA and its Client Hints are reported alongside as
// solver_user_agent and solver_sec_ch_ua so the caller can check both.
//
// The TLS and HTTP/2 layers are unaffected by any of that either way: they come
// from BoringSSL and Chromium's own HTTP/2 stack, which no page-level override
// can reach. That is precisely what makes them worth measuring.

import { connect } from "puppeteer-real-browser";
import {
  TARGET_SEC_CH_UA,
  TARGET_UA,
  chromiumMajor,
  connectOptions,
  pinProcessLocale,
} from "./profile.js";
import {
  cleanup,
  errorMessage,
  installExitHandlers,
  trackBrowser,
  untrackBrowser,
} from "./cleanup.js";

function fail(message) {
  console.log(JSON.stringify({ status: "error", error: message }));
  process.exit(1);
}

const url = process.argv[2];
if (!url) {
  fail("usage: node solver/fingerprint.js <url> [timeout_sec]");
}

// Same locale pin the solve runs under. This file's whole contract is that it
// measures the browser index.js drives, and the locale reaches Intl and the
// Accept-Language header — both of which a fingerprint endpoint reports.
pinProcessLocale();

// A NaN here would reach setTimeout, which coerces it to 1ms and fires the hard
// stop immediately; a zero would reach page.goto, where it means "no timeout at
// all". fpcheck passes int(timeout.Seconds()), so a sub-second -timeout arrives
// as 0 — clamped rather than rejected, since that is a legitimate way to ask
// for "as little as possible".
const DEFAULT_TIMEOUT_SEC = 60;
const rawTimeout = process.argv[3];
let timeoutSec = DEFAULT_TIMEOUT_SEC;
if (rawTimeout !== undefined) {
  const n = Number(rawTimeout);
  if (!Number.isFinite(n) || n < 0) {
    fail(`invalid timeout_sec ${JSON.stringify(rawTimeout)}: want a non-negative number of seconds`);
  }
  timeoutSec = Math.max(1, n);
}

// Kill the Chromium tree on every exit path. The previous hard stop called
// process.exit() directly, which skips the finally that closes the browser — so
// the timeout path leaked exactly the tree this comment promised to prevent,
// and there were no signal handlers at all.
installExitHandlers();

const hardStop = setTimeout(() => {
  try {
    console.log(
      JSON.stringify({
        status: "error",
        error: `timed out after ${timeoutSec}s`,
      })
    );
  } catch {}
  cleanup();
  process.exit(2);
}, timeoutSec * 1000 + 15_000);
hardStop.unref();

async function main() {
  let browser;
  try {
    // SOLVER_PROXY is honoured here too, so the browser being measured is the
    // one the solve actually runs — a proxy can change the egress path and the
    // TLS the far end sees.
    const result = await connect(connectOptions({ proxy: process.env.SOLVER_PROXY }));
    browser = result.browser;
    trackBrowser(browser);
    const page = result.page;

    let version = "";
    try {
      version = await browser.version();
    } catch {}

    let nativeUA = "";
    try {
      nativeUA = await page.evaluate(() => navigator.userAgent);
    } catch {}

    // A real navigation, not fetch(): the header order and Sec-Fetch-* values
    // this is meant to capture are the ones a document load produces, which is
    // also what the Go client's default profile emits.
    const response = await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: timeoutSec * 1000,
    });
    if (!response) {
      throw new Error(`no response from ${url}`);
    }
    if (!response.ok()) {
      throw new Error(`HTTP ${response.status()} from ${url}`);
    }

    // Read the raw HTTP body rather than scraping the rendered DOM: Chrome's
    // JSON viewer wraps the response in markup, and on a large body it
    // truncates the visible text.
    const body = await response.text();

    let capture;
    try {
      capture = JSON.parse(body);
    } catch (err) {
      throw new Error(
        `${url} did not return JSON (is it a fingerprint API?): ${err.message}`
      );
    }

    console.log(
      JSON.stringify({
        status: "ok",
        chromium_version: version,
        chromium_major: chromiumMajor(version),
        native_user_agent: nativeUA,
        solver_user_agent: TARGET_UA,
        solver_sec_ch_ua: TARGET_SEC_CH_UA,
        capture,
      })
    );
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {}
      untrackBrowser(browser);
    }
  }
}

main().catch((err) => {
  fail(errorMessage(err));
});
