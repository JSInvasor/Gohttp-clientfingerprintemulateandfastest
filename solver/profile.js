// Shared browser identity for everything in solver/.
//
// This file exists because the solver and the Go client have to agree on which
// browser they are. Cloudflare binds cf_clearance to the (UA, JA3/JA4, IP) of
// the session that was issued it. The solver drives a real Chromium to earn the
// cookie; gofire then replays that cookie with its own emulated ClientHello. If
// the two are not the same browser, the cookie is issued to one identity and
// presented by another, and it dies — usually within seconds under load, and
// with no diagnostic beyond a wall of 403s.
//
// Keeping the UA and the launch flags in one module means index.js (which
// solves) and fingerprint.js (which measures) cannot drift apart, and
// `fpcheck -via-chromium` measures the browser the solver actually launches
// rather than a differently-configured one.

// TARGET_UA must match gofire's Chrome151UserAgent in headers.go.
//
// `fpcheck -via-chromium` checks this for you and fails when it drifts; that
// check is the reason this constant is worth pinning rather than leaving to
// whatever Chromium happens to report. Override with SOLVER_UA when your box
// runs a different Chrome major and you have re-pinned the Go profile to match.
export const TARGET_UA =
  process.env.SOLVER_UA ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";

// LAUNCH_ARGS and CONNECT_OPTIONS are shared so the fingerprint probe measures
// the same browser configuration the solver runs. Launch flags can move the
// TLS layer — a --disable-features that switches off post-quantum key agreement
// would change the ClientHello and therefore the JA4 — so measuring a
// differently-flagged browser would answer the wrong question.
export const LAUNCH_ARGS = [
  "--no-sandbox",
  "--disable-setuid-sandbox",
  "--disable-dev-shm-usage",
  "--disable-gpu",
  "--disable-blink-features=AutomationControlled",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-features=IsolateOrigins,site-per-process",
  "--window-size=1920,1080",
];

export const CONNECT_OPTIONS = {
  headless: false,
  turnstile: true,
  args: LAUNCH_ARGS,
  connectOption: { defaultViewport: null },
  disableXvfb: false,
  ignoreAllFlags: false,
};

// chromiumMajor extracts the major version from a browser.version() string
// such as "HeadlessChrome/151.0.7204.50". Returns 0 when it cannot be parsed.
export function chromiumMajor(version) {
  const m = String(version || "").match(/(\d+)\.\d+\.\d+\.\d+/);
  return m ? parseInt(m[1], 10) : 0;
}
