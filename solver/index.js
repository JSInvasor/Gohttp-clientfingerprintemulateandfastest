// Single-shot Cloudflare UAM solver.
//
// Usage:
//   node solver/index.js <url> [timeout_sec=75]
//
// Output (stdout, single JSON line):
//   { "status": "ok"|"no_clearance"|"error",
//     "url": "<final url>",
//     "user_agent": "<navigator.userAgent>",
//     "cookies": "name=val; name=val; ...",
//     "cookie_list": [{name, value, domain, expires}, ...],
//     "fingerprint": { ja3, ja3_hash, ja4, akamai, ua_seen } | null,
//     "error": "<message>" }
//
// Design: keep it bare. puppeteer-real-browser already ships stealth
// patches (rebrowser-puppeteer-core + turnstile auto-click). Layering
// our own evaluateOnNewDocument shims on top *broke* bypass on
// previously-working targets because our overrides clashed with theirs
// (double-defined props become a fingerprint instead of hiding one).
// Only thing we do beyond connect() is pin the UA to match blaze's
// emulated Chrome 147 — UAM binds cf_clearance to UA + JA4.

import { connect } from "puppeteer-real-browser";
import { execSync } from "node:child_process";

const url = process.argv[2];
const timeoutSec = parseInt(process.argv[3] || "75", 10);
const TIMEOUT_MS = timeoutSec * 1000;

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

function log(stage, extra) {
  const line = extra ? `[solver] ${stage}: ${extra}` : `[solver] ${stage}`;
  try {
    process.stderr.write(line + "\n");
  } catch {}
}

// ---- Process tracking + hard cleanup ----------------------------------------
//
// puppeteer-real-browser launches Chromium plus an Xvfb wrapper plus
// renderer/GPU children. browser.close() is best-effort: if node is killed
// (blaze timeout, SIGKILL) the chromium tree is orphaned and keeps eating
// CPU/RAM. Track every PID we know about and kill the whole tree on every
// exit path.

const SESSION_MARK = `BLAZE_SOLVER_SESSION=${process.pid}-${Date.now()}`;
process.env.BLAZE_SOLVER_SESSION = SESSION_MARK.split("=")[1];

const trackedPids = new Set();
let cleanedUp = false;
let currentBrowser = null;

function trackPid(pid) {
  if (pid && Number.isInteger(pid)) trackedPids.add(pid);
}

function killProcessTree(pid, signal) {
  try {
    process.kill(-pid, signal);
  } catch {}
  try {
    process.kill(pid, signal);
  } catch {}
}

function cleanup() {
  if (cleanedUp) return;
  cleanedUp = true;

  if (currentBrowser) {
    try {
      currentBrowser.close();
    } catch {}
    currentBrowser = null;
  }

  for (const pid of trackedPids) killProcessTree(pid, "SIGTERM");
  setTimeout(() => {
    for (const pid of trackedPids) killProcessTree(pid, "SIGKILL");
  }, 500).unref();

  if (process.platform === "linux") {
    try {
      execSync(
        `pgrep -af "BLAZE_SOLVER_SESSION=${process.env.BLAZE_SOLVER_SESSION}" | awk '{print $1}' | xargs -r kill -9`,
        { stdio: "ignore", timeout: 2000 }
      );
    } catch {}
  }
}

process.on("SIGINT", () => {
  cleanup();
  process.exit(130);
});
process.on("SIGTERM", () => {
  cleanup();
  process.exit(143);
});
process.on("SIGHUP", () => {
  cleanup();
  process.exit(129);
});
process.on("uncaughtException", (e) => {
  try {
    console.log(
      JSON.stringify({ status: "error", error: e?.message || String(e) })
    );
  } catch {}
  cleanup();
  process.exit(1);
});
process.on("unhandledRejection", (e) => {
  try {
    console.log(
      JSON.stringify({
        status: "error",
        error: (e && e.message) || String(e),
      })
    );
  } catch {}
  cleanup();
  process.exit(1);
});
process.on("exit", cleanup);

// Watchdog backstop — fires before blaze's 90s SIGKILL.
setTimeout(() => {
  log("watchdog timeout - aborting");
  try {
    console.log(
      JSON.stringify({ status: "error", error: "watchdog timeout" })
    );
  } catch {}
  cleanup();
  process.exit(2);
}, TIMEOUT_MS + 10_000).unref();

async function solve() {
  log(`start url=${url} timeout=${timeoutSec}s`);
  let browser;
  try {
    log("launching chromium");

    const launchArgs = [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--start-maximized",
    ];

    // Optional residential proxy for the chromium itself. Datacenter VPS
    // IPs sometimes get persistent UAM regardless of fingerprint quality;
    // a clean IP at the chromium level is the workaround.
    const proxyURL = process.env.SOLVER_PROXY;
    if (proxyURL) {
      launchArgs.push(`--proxy-server=${proxyURL}`);
      log("using proxy", proxyURL);
    }

    const result = await connect({
      headless: false,
      turnstile: true,
      args: launchArgs,
      connectOption: { defaultViewport: null },
      disableXvfb: false,
    });

    browser = result.browser;
    currentBrowser = browser;
    const page = result.page;

    try {
      const proc = browser.process && browser.process();
      if (proc && proc.pid) trackPid(proc.pid);
    } catch {}

    // Optional proxy auth via CDP (--proxy-server doesn't accept user:pass).
    const proxyUser = process.env.SOLVER_PROXY_USER;
    const proxyPass = process.env.SOLVER_PROXY_PASS;
    if (proxyURL && proxyUser) {
      try {
        await page.authenticate({ username: proxyUser, password: proxyPass || "" });
        log("proxy auth registered");
      } catch (err) {
        log("proxy auth setup failed", err.message || String(err));
      }
    }

    // Pin UA to match blaze's Chrome 147 emulation.
    await page.setUserAgent(TARGET_UA);

    log("chromium ready");
    log("navigating", url);
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: TIMEOUT_MS });
    log("navigation done");

    // Wait for cf_clearance — or for the page to leave the challenge state.
    const startTime = Date.now();
    let cookies = [];
    let cfClearance = null;
    let lastTitle = "";
    let polls = 0;

    while (Date.now() - startTime < TIMEOUT_MS) {
      cookies = await browser.cookies(url).catch(() => []);
      cfClearance = cookies.find((c) => c.name === "cf_clearance");
      if (cfClearance) {
        log("cf_clearance acquired");
        break;
      }

      const title = await page.title().catch(() => "");
      if (title && title !== lastTitle) {
        log("title", title);
        lastTitle = title;
      }
      if (
        title &&
        !title.includes("Just a moment") &&
        !title.includes("Attention Required") &&
        !title.includes("Checking")
      ) {
        cookies = await browser.cookies(url).catch(() => []);
        cfClearance = cookies.find((c) => c.name === "cf_clearance");
        log("past challenge");
        break;
      }

      polls++;
      if (polls % 10 === 0) {
        const remaining = Math.max(
          0,
          Math.round((TIMEOUT_MS - (Date.now() - startTime)) / 1000)
        );
        log(`waiting for clearance (${remaining}s left)`);
      }
      await new Promise((r) => setTimeout(r, 1000));
    }

    if (!cfClearance) {
      cookies = await browser.cookies(url).catch(() => []);
    }

    const userAgent = await page.evaluate(() => navigator.userAgent);
    const finalUrl = page.url();
    const cookieHeader = cookies
      .map((c) => `${c.name}=${c.value}`)
      .join("; ");

    // Fingerprint diagnostic. cf_clearance is bound to the REAL Chromium's
    // JA3/JA4 + UA; blaze replays the cookie with its *emulated* fingerprint,
    // so the two must match or Cloudflare re-challenges at load. Read what this
    // browser actually presents so blaze can be aligned to it. Best-effort: a
    // failure here never costs us the clearance we just earned.
    let fingerprint = null;
    const fpURL = process.env.SOLVER_FP_URL || "https://tls.peet.ws/api/all";
    try {
      const fpPage = await browser.newPage();
      await fpPage.setUserAgent(TARGET_UA);
      const fpResp = await fpPage.goto(fpURL, {
        waitUntil: "domcontentloaded",
        timeout: 20_000,
      });
      const data = JSON.parse(await fpResp.text());
      fingerprint = {
        ja3: data?.tls?.ja3 ?? null,
        ja3_hash: data?.tls?.ja3_hash ?? null,
        ja4: data?.tls?.ja4 ?? null,
        akamai: data?.http2?.akamai_fingerprint ?? null,
        ua_seen: data?.user_agent ?? null,
      };
      await fpPage.close().catch(() => {});
      log(
        "fingerprint",
        `ja4=${fingerprint.ja4} ja3_hash=${fingerprint.ja3_hash} h2=${fingerprint.akamai} ua=${fingerprint.ua_seen}`
      );
    } catch (err) {
      log("fingerprint probe failed", err.message || String(err));
    }

    const output = {
      status: cfClearance ? "ok" : "no_clearance",
      url: finalUrl,
      user_agent: userAgent,
      cookies: cookieHeader,
      fingerprint,
      cookie_list: cookies.map((c) => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        expires: c.expires,
      })),
    };

    log(cfClearance ? "result: ok" : "result: no_clearance");
    console.log(JSON.stringify(output));
  } catch (err) {
    log("error", err.message || String(err));
    console.log(
      JSON.stringify({
        status: "error",
        error: err.message || String(err),
      })
    );
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
    currentBrowser = null;
  }
}

solve();
