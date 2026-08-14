// Does the cookie work in the browser that earned it?
//
// Usage:
//   node solver/replay.js <url> [cache_dir]
//
// Output (stdout, single JSON line):
//   { "status": "ok", "http_status": 200, "challenged": false, ... }
//   { "status": "error", "error": "<message>" }
//
// This exists to answer one question, and it is the question that decides where
// to look when a solve succeeds and the run that follows it gets 403.
//
// Two very different things produce that symptom:
//
//   1. the client replaying the cookie does not look enough like the browser
//      that earned it, so the edge rejects a cookie that is otherwise fine; or
//   2. the clearance is not replayable at all — the zone re-scores every
//      request, the address is on a datacenter range, or the challenge bound
//      the cookie to the session that solved it.
//
// From outside they are identical: a fresh interstitial either way. And they
// have opposite answers — the first is fingerprint work in this repo, the
// second is not work at all, it is a proxy.
//
// So: load the cookies the solve already stored, put them in a *fresh* browser
// context, and navigate. Same browser, same address, same everything the solve
// had — except that the challenge is not being solved again, only its cookie
// presented. If that comes back 200, the cookie is replayable and the gap is in
// whatever else is replaying it. If it comes back challenged, no amount of
// fingerprint work in the Go client would have helped, because the browser
// itself could not do it.

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { connect } from "puppeteer-real-browser";
import { connectOptions } from "./profile.js";
import {
  cleanup,
  errorMessage,
  installExitHandlers,
  trackBrowser,
  untrackBrowser,
} from "./cleanup.js";

function out(o) {
  console.log(JSON.stringify(o));
}

function fail(message) {
  out({ status: "error", error: message });
  process.exit(1);
}

const url = process.argv[2];
if (!url) fail("usage: node solver/replay.js <url> [cache_dir]");

// The same directory defaultSolveCachePath() in cmd/send/solvecache.go writes
// to: os.UserCacheDir()/gofire/solve-cache, which on Linux honours XDG_CACHE_HOME
// and falls back to ~/.cache.
const cacheDir =
  process.argv[3] ||
  process.env.SEND_SOLVE_CACHE ||
  path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "gofire", "solve-cache");

// The cache is keyed by a hash this file does not compute, so rather than
// reproduce that keying, every entry is read and the one for this host is
// taken. There are only ever a handful.
function cookiesFromCache(target) {
  let host;
  try {
    host = new URL(target).hostname;
  } catch {
    fail(`invalid url ${JSON.stringify(target)}`);
  }
  let entries;
  try {
    entries = fs.readdirSync(cacheDir).filter((f) => f.endsWith(".json"));
  } catch (err) {
    fail(`cannot read the solve cache at ${cacheDir}: ${err.message}. Run a -solve first, or pass the directory as the second argument.`);
  }

  let newest = null;
  for (const file of entries) {
    let entry;
    try {
      entry = JSON.parse(fs.readFileSync(path.join(cacheDir, file), "utf8"));
    } catch {
      continue;
    }
    if (entry.host !== host || !Array.isArray(entry.cookies)) continue;
    if (!newest || new Date(entry.solved_at) > new Date(newest.solved_at)) {
      newest = entry;
    }
  }
  if (!newest) {
    fail(`no cached solve for ${host} in ${cacheDir} — run \`send -solve ${target}\` first`);
  }
  return newest;
}

installExitHandlers();

const entry = cookiesFromCache(url);

async function main() {
  let browser;
  try {
    const result = await connect(connectOptions({ proxy: process.env.SOLVER_PROXY }));
    browser = result.browser;
    trackBrowser(browser);

    // A context of its own, so the only thing this session has is the cookies
    // being tested. Reusing the default context would carry whatever the
    // browser picked up on startup and prove nothing.
    const context = await browser.createBrowserContext();
    const page = await context.newPage();

    const origin = new URL(url).origin;
    await context.setCookie(
      ...entry.cookies.map((c) => ({
        name: c.name,
        value: c.value,
        domain: c.domain || new URL(url).hostname,
        path: "/",
        secure: true,
      }))
    );

    const response = await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: 45_000,
    });

    // Give the page a moment: a challenge that is going to appear appears
    // immediately, and one that resolves itself does so in well under this.
    await new Promise((r) => setTimeout(r, 3_000));

    const httpStatus = response ? response.status() : 0;
    const title = await page.title().catch(() => "");
    const challenged = await page
      .evaluate(() => typeof window._cf_chl_opt === "object" && window._cf_chl_opt !== null)
      .catch(() => false);

    const after = await context.cookies(origin).catch(() => []);
    const clearance = after.find((c) => c.name === "cf_clearance");

    out({
      status: "ok",
      url: page.url(),
      http_status: httpStatus,
      title,
      challenged,
      // A clearance that came back different is the edge replacing the one that
      // was presented, which is its way of saying the presented one was not
      // accepted.
      clearance_replaced:
        !!clearance &&
        !!entry.cookies.find((c) => c.name === "cf_clearance") &&
        clearance.value !== entry.cookies.find((c) => c.name === "cf_clearance").value,
      cookies_presented: entry.cookies.map((c) => c.name),
      solved_at: entry.solved_at,
      chromium_version: await browser.version().catch(() => ""),
    });
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {}
      untrackBrowser(browser);
    }
    cleanup();
  }
}

main().catch((err) => fail(errorMessage(err)));
