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
// to: os.UserCacheDir()/gofire/solve-cache.
//
// Which is a different place on each platform, and reproducing only the Linux
// one meant this looked in ~/.cache on Windows while send wrote to
// %LocalAppData% — a "no cached solve" error pointing at a directory that was
// never going to have one, on the platform least likely to guess why.
function userCacheDir() {
  switch (process.platform) {
    case "win32":
      return process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
    case "darwin":
      return path.join(os.homedir(), "Library", "Caches");
    default:
      return process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache");
  }
}

const cacheDir =
  process.argv[3] ||
  process.env.SEND_SOLVE_CACHE ||
  path.join(userCacheDir(), "gofire", "solve-cache");

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

// Cookies a passing browser keeps, as opposed to the working state a challenge
// leaves behind.
//
// cf_clearance is the credential. cf_chl_* are the challenge's own bookkeeping —
// rc is a retry counter, and the rest are stage markers — and a browser that has
// finished has no reason to keep presenting them. Handing them back says "I am
// part-way through a challenge", which is a different claim from "I finished
// one", and the edge is entitled to act on it.
//
// Worth testing rather than assuming, which is what attempt() below is for: the
// solver captures every cookie it can see, and if the bookkeeping is what breaks
// the replay then the fix is in this repo rather than in somebody's proxy list.
function isChallengeState(name) {
  return name.startsWith("cf_chl_") || name.startsWith("_cf_chl");
}

async function attempt(browser, cookies, label) {
  // A context of its own, so the only thing this session has is the cookies
  // being tested. Reusing one would carry whatever the last attempt left.
  const context = await browser.createBrowserContext();
  const page = await context.newPage();

  // What actually went out, rather than what was asked for.
  //
  // This is the assumption the whole file rests on: "the cookie was presented
  // and refused" and "the cookie was never sent" look identical from the
  // response, and a setCookie that fails quietly produces the second while
  // reading as the first.
  //
  // It has to come from Network.requestWillBeSentExtraInfo rather than from
  // request.headers(). Puppeteer's headers are the ones Chrome has at the
  // interception point, and the network stack adds Cookie after that — so
  // request.headers() reports no Cookie on a request that carries one, which is
  // a false "never sent" on every attempt. Measured against a local HTTPS
  // server that recorded what it received:
  //
  //   server actually received : "cf_clearance=abc123"
  //   request.headers().cookie : (absent)
  //   extraInfo headers.Cookie : "cf_clearance=abc123"
  let cookieSent = null;
  try {
    const cdp = await page.createCDPSession();
    await cdp.send("Network.enable");
    cdp.on("Network.requestWillBeSentExtraInfo", (e) => {
      if (cookieSent !== null) return; // the first request, not the redirects
      const h = e.headers || {};
      cookieSent = h.Cookie ?? h.cookie ?? "";
    });
  } catch {
    // Without the event there is no honest answer, and "" would read as
    // "nothing was sent". Left null, which reports as unknown below.
  }

  if (cookies.length > 0) {
    await context.setCookie(
      ...cookies.map((c) => ({
        name: c.name,
        value: c.value,
        domain: c.domain || new URL(url).hostname,
        path: "/",
        secure: true,
      }))
    );
  }

  const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45_000 })
    .catch(() => null);
  await new Promise((r) => setTimeout(r, 3_000));

  const challenged = await page
    .evaluate(() => typeof window._cf_chl_opt === "object" && window._cf_chl_opt !== null)
    .catch(() => true);

  const wanted = cookies.map((c) => c.name);
  const sentNames =
    cookieSent === null
      ? null
      : cookieSent
          .split(";")
          .map((p) => p.split("=")[0].trim())
          .filter(Boolean);

  const out = {
    presented: wanted,
    // The names that were actually on the wire, and what is missing from them.
    // A non-empty `not_sent` invalidates the attempt rather than answering it;
    // null means the wire could not be observed, which is not the same as
    // nothing having been on it.
    sent: sentNames,
    not_sent: sentNames === null ? null : wanted.filter((n) => !sentNames.includes(n)),
    http_status: response ? response.status() : 0,
    challenged,
    title: await page.title().catch(() => ""),
    url: page.url(),
  };
  await context.close().catch(() => {});
  return { label, ...out };
}

async function main() {
  let browser;
  try {
    const result = await connect(connectOptions({ proxy: process.env.SOLVER_PROXY }));
    browser = result.browser;
    trackBrowser(browser);

    // The carried-in cookie, in a context of its own. attempt() reports what
    // went out on the wire as well as what came back, so a cookie that was
    // never sent cannot be read as one that was refused.
    const carried = await attempt(browser, entry.cookies, "carried in");

    // Only worth asking once that has answered no: is the clearance unusable,
    // or is the zone challenging everything?
    //
    // Let a challenge run to completion in a context of its own — a browser
    // solves it and proceeds, which is the whole difference between it and a
    // client — then navigate again with whatever that left behind. If that
    // passes, a clearance does work here and simply does not travel. If it is
    // challenged too, the zone re-challenges every request and there is nothing
    // for -solve to earn that would ever be reusable.
    let inSession = null;
    if (carried.challenged) {
      const context = await browser.createBrowserContext();
      const page = await context.newPage();
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45_000 }).catch(() => null);

      const deadline = Date.now() + 90_000;
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 2_000));
        const stillOn = await page
          .evaluate(() => typeof window._cf_chl_opt === "object" && window._cf_chl_opt !== null)
          .catch(() => true);
        if (!stillOn) break;
      }
      const second = await page
        .goto(url, { waitUntil: "domcontentloaded", timeout: 45_000 })
        .catch(() => null);
      await new Promise((r) => setTimeout(r, 2_000));
      inSession = {
        http_status: second ? second.status() : 0,
        challenged: await page
          .evaluate(() => typeof window._cf_chl_opt === "object" && window._cf_chl_opt !== null)
          .catch(() => true),
        title: await page.title().catch(() => ""),
      };
      await context.close().catch(() => {});
    }

    // The solver captures every cookie the origin set, challenge bookkeeping
    // included. If presenting that bookkeeping is what breaks the replay, the
    // same cookies without it will pass — and the fix is in this repo.
    let clearanceOnly = null;
    if (carried.challenged) {
      const kept = entry.cookies.filter((c) => !isChallengeState(c.name));
      if (kept.length !== entry.cookies.length) {
        clearanceOnly = await attempt(browser, kept, "clearance only");
      }
    }

    out({
      status: "ok",
      ...carried,
      // null when the carried cookie already passed, so there was nothing to
      // distinguish. Otherwise: does a clearance earned *here* work here?
      same_session_after_solving: inSession,
      // null when nothing was dropped, or when the carried attempt passed.
      without_challenge_state: clearanceOnly,
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
