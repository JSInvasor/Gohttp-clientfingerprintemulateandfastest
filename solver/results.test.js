// The two decisions that used to throw away a solved cookie.
//
// Both were invisible from outside: the solver printed a plausible line, send
// reported a plausible failure, and the cf_clearance that had already been
// earned was never in it. Neither had a test, which is how they survived.

import assert from "node:assert/strict";
import test from "node:test";

import {
  betterResult,
  exhaustedResult,
  rankResult,
  statusAfterThrow,
} from "./results.js";

const cookie = (name) => ({ name, value: "v", domain: ".example.com", expires: 0 });

test("a clearance outranks any number of other cookies", () => {
  const solved = { status: "ok", cookie_list: [cookie("cf_clearance")] };
  const busy = { status: "no_clearance", cookie_list: [cookie("a"), cookie("b"), cookie("c")] };

  assert.ok(rankResult(solved) > rankResult(busy));
  assert.equal(betterResult(busy, solved), solved);
  assert.equal(betterResult(solved, busy), solved);
});

test("the retry is a second chance, not a replacement", () => {
  const first = { status: "no_clearance", cookie_list: [cookie("__cf_bm")] };
  const failedRetry = { status: "error", error: "browser launch did not finish", cookie_list: [] };

  assert.equal(betterResult(first, failedRetry), first);
  assert.equal(betterResult(null, failedRetry), failedRetry);
  assert.equal(rankResult(null), -1);
});

// The bug: page.goto throws when the challenge navigates the frame out from
// under it, which happens *after* cf_clearance is set. Pinning the status to
// "error" there reported a solve that worked as a solve that failed, and send
// aborted the run over it.
test("an attempt that threw with a clearance in the jar is a solve", () => {
  assert.equal(statusAfterThrow({ status: "ok", cookie_list: [cookie("cf_clearance")] }), "ok");
  assert.equal(statusAfterThrow({ status: "no_clearance", cookie_list: [cookie("__cf_bm")] }), "error");
  assert.equal(statusAfterThrow(null), "error");
});

const defaults = {
  url: "https://example.com/",
  userAgent: "Mozilla/5.0 pinned",
  acceptLanguage: "en-US,en;q=0.9",
};

// The other half of the same bug: even when an attempt reported its cookies, the
// tail forwarded them only if the status happened to be "no_clearance". An
// attempt that threw was reported as a bare error and the jar went with it.
test("cookies survive an attempt that ended in an error", () => {
  const threw = {
    status: "error",
    error: "net::ERR_ABORTED",
    url: "https://example.com/x",
    user_agent: "Mozilla/5.0 pinned",
    accept_language: "en-US,en;q=0.9",
    page_languages: ["en-US", "en"],
    cookies: "__cf_bm=abc",
    cookie_list: [cookie("__cf_bm")],
  };

  const out = exhaustedResult(threw, defaults);
  assert.equal(out.status, "no_clearance");
  assert.deepEqual(out.cookie_list, [cookie("__cf_bm")]);
  assert.equal(out.cookies, "__cf_bm=abc");
  // The reason the attempt ended is kept beside the cookies, not instead of them.
  assert.equal(out.error, "net::ERR_ABORTED");
  assert.equal(out.url, "https://example.com/x");
});

test("an attempt that collected nothing is still an error", () => {
  const out = exhaustedResult({ status: "error", error: "watchdog timeout", cookie_list: [] }, defaults);
  assert.deepEqual(out, { status: "error", error: "watchdog timeout" });

  // Nothing at all — no attempt ever completed.
  assert.deepEqual(exhaustedResult(null, defaults), { status: "error", error: "solve failed" });
});

// A run that failed before it reached a page has no url, UA or language of its
// own, and the line still has to carry the ones the run was configured with —
// send reads them whatever the status says.
test("what a failed attempt never reached falls back to what was configured", () => {
  const out = exhaustedResult({ status: "no_clearance", cookie_list: [cookie("__cf_bm")] }, defaults);
  assert.equal(out.url, "https://example.com/");
  assert.equal(out.user_agent, "Mozilla/5.0 pinned");
  assert.equal(out.accept_language, "en-US,en;q=0.9");
  assert.deepEqual(out.page_languages, []);
  assert.equal(out.error, "");
});
