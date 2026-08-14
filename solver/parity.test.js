// What the solver does to a page, against the version that actually passes.
//
// workingBrowsers/ is the solver as it stood before the rewrite. On a datacenter
// VPS address it earns a cf_clearance and replays it for 113 requests without a
// challenge; the rewritten one, same box and same target, gets a managed
// challenge. Every difference between them was individually argued to be safe —
// a stealth shim removed because it left an own property on navigator, launch
// flags added to pin a language, a structural challenge probe added because
// Cloudflare localises its interstitial — and the arguments were good. The
// result was a solver that does not work.
//
// So the page-facing surface is pinned to the working version rather than to an
// argument. Anything a page or the edge could observe has to match; anything
// that cannot be seen from outside the browser is free to differ, which is where
// batch mode and the proxy list live.
//
// This is not a claim about which difference mattered. Nobody knows, and the
// only instrument that could have said was itself broken twice over. It is the
// weaker and more useful claim: stop introducing them, and if one has to be
// introduced, introduce it alone so a live A/B can attribute it.

import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const here = import.meta.dirname;
const read = (...p) => fs.readFileSync(path.join(here, ...p), "utf8");

// The reference used to be read out of workingBrowsers/, which is no longer in
// the tree. Reading a deleted directory is not a weaker check, it is no check:
// this test failed with ENOENT on every run, which is the same as not having
// been written.
//
// So the reference is transcribed here instead. This is the complete set of
// page-facing calls in workingBrowsers/index.js at 29f044c^, the last commit
// that carried it; `git show 29f044c^:workingBrowsers/index.js` is the original
// if it ever needs re-deriving.
const WORKING_VERSION_PAGE_CALLS = new Set([
  "page.setUserAgent",
  "page.evaluateOnNewDocument",
  "page.title",
  "page.goto",
  "page.evaluate",
  "page.url",
]);

// Comments are prose about page APIs — this file's own subject — so they have to
// go before anything counts calls.
function code(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "")
    .replace(/([^:])\/\/.*$/gm, "$1");
}

// Everything that reaches the browser: page.* and the raw protocol.
function pageCalls(text) {
  const calls = new Set();
  for (const m of code(text).matchAll(/\bpage\.([a-zA-Z]+)\s*\(/g)) calls.add(`page.${m[1]}`);
  for (const m of code(text).matchAll(/\b(createCDPSession|setUserAgentOverride|setRequestInterception|setExtraHTTPHeaders|setBypassCSP|setJavaScriptEnabled|emulate[A-Za-z]*)\s*\(/g)) {
    calls.add(m[1]);
  }
  return calls;
}

// Calls the rewrite is allowed to have that the working version does not, with
// the reason each is invisible to a single-exit solve.
const ALLOWED_EXTRA = new Map([
  // Batch mode only: one BrowserContext per exit, each with its own proxy, and
  // puppeteer-real-browser authenticates every page with the single proxy
  // connect() was given — which in a batch is the wrong one. solveSingle, the
  // path the working version is, never reaches it.
  ["page.authenticate", "batch mode, per-exit proxy credentials"],
]);

test("the solve presents nothing to the page that the working version does not", () => {
  const theirs = WORKING_VERSION_PAGE_CALLS;
  const ours = new Set([
    ...pageCalls(read("index.js")),
    ...pageCalls(read("identity.js")),
    ...pageCalls(read("behavior.js")),
  ]);

  const extra = [...ours].filter((c) => !theirs.has(c) && !ALLOWED_EXTRA.has(c));
  assert.deepEqual(
    extra,
    [],
    `\nthe rewrite reaches the page in ways the working version does not:\n` +
      extra.map((c) => `  ${c}`).join("\n") +
      `\n\nEither drop it, or add it to ALLOWED_EXTRA with the reason a solve cannot ` +
      `see it.\n`
  );
});

// The shim is back, and this says so out loud so nobody removes it again on the
// strength of the argument that removed it the first time. That argument is
// correct — defineProperty on the instance leaves an own property, and the
// getter stringifies as an arrow function — and the version carrying it is the
// version that passes.
test("navigator.languages is still shimmed, deliberately", () => {
  const identity = code(read("identity.js"));
  assert.match(identity, /evaluateOnNewDocument/);
  assert.match(identity, /Object\.defineProperty\(navigator, "languages"/);

  // And the mechanism that replaced it is gone. It is better by every argument
  // available and it did not pass; see identity.js.
  assert.ok(
    !/setUserAgentOverride/.test(identity),
    "the CDP language override is back — it is a better mechanism that did not work"
  );
});

// The challenge probe may stay, but not on the polling path: the working version
// does one page.title() per pass and nothing else while a challenge is running.
test("the challenge probe runs only when the title says the challenge is over", () => {
  const waitFor = code(read("index.js")).match(
    /async function waitForClearance[\s\S]*?\n}/
  );
  assert.ok(waitFor, "waitForClearance not found");
  const body = waitFor[0];

  const titleAt = body.indexOf("page.title(");
  const probeAt = body.indexOf("page.evaluate(detectChallengeInPage)");
  assert.ok(titleAt > 0, "the title check is gone");
  assert.ok(probeAt > 0, "the structural probe is gone — a localised interstitial needs it");
  assert.ok(
    titleAt < probeAt,
    "the structural probe runs before the title check, so it runs on every poll — " +
      "which is a page.evaluate twice a second for the whole challenge, and the " +
      "working version does not do it"
  );
});
