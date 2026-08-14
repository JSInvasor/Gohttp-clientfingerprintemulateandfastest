// What an attempt is worth, and what a run reports when the attempts are spent.
//
// These are pure decisions about an object, and they live here because index.js
// cannot be imported by a test — it pulls in puppeteer-real-browser at module
// load and a test run has no browser. That is the same reason challenge.js,
// cookies.js and verdict.js exist, and it is not academic: both of the bugs
// below were in this logic, both were silent, and both threw away a cookie that
// had already been earned and paid for.

// rankResult orders two attempts: a clearance beats anything, then more cookies,
// then anything at all over nothing. It is what makes the retry a second chance
// rather than a replacement — a retry that fails to launch, or lands on a harder
// challenge variant, must not erase what the first attempt collected.
export function rankResult(r) {
  if (!r) return -1;
  if (r.status === "ok") return 1_000_000;
  return (r.cookie_list || []).length;
}

export function betterResult(a, b) {
  return rankResult(b) > rankResult(a) ? b : a || b;
}

// statusAfterThrow decides what an attempt that threw should report, given
// whatever its jar still held.
//
// The status used to be pinned to "error" regardless, and that made the one case
// the salvage exists for the one case it could not report. page.goto is what
// throws here, and the throw is ordinary rather than exotic: a challenge that
// clears navigates the frame out from under it, surfacing as net::ERR_ABORTED or
// a detached frame — after cf_clearance has been set. So the jar held the cookie,
// the line said "error", and send turned a successful solve into an aborted run.
export function statusAfterThrow(salvaged) {
  return salvaged && salvaged.status === "ok" ? "ok" : "error";
}

// exhaustedResult shapes the line a run prints once every attempt is spent.
//
// It reports whatever the best attempt collected, whichever way that attempt
// ended. The previous version keyed on status alone — only a "no_clearance"
// result had its cookies forwarded — so an attempt that threw was reported as a
// bare error with the jar discarded. rankResult exists to rank attempts by how
// many cookies they collected, and that was work done for nothing: the winner's
// cookies were dropped one function later unless its status happened to be the
// right one. On a zone with no UAM the __cf_bm the challenge page set is the
// whole of what a solve can produce, and a goto that timed out after it arrived
// turned that into "solver: navigation timeout" and no cookie at all.
//
// The error message rides along rather than being replaced by the cookies. send
// only reads it on an "error" line, and it is the only record of why the attempt
// ended where it did.
//
// defaults supply what the caller knows and a failed attempt may not have
// reached: the target url, the pinned UA, and the Accept-Language the browser
// was launched to send.
export function exhaustedResult(lastResult, defaults) {
  const collected = (lastResult && lastResult.cookie_list) || [];
  if (collected.length === 0) {
    return {
      status: "error",
      error: (lastResult && lastResult.error) || "solve failed",
    };
  }
  return {
    status: "no_clearance",
    url: (lastResult && lastResult.url) || defaults.url,
    user_agent: (lastResult && lastResult.user_agent) || defaults.userAgent,
    accept_language: (lastResult && lastResult.accept_language) || defaults.acceptLanguage,
    page_languages: (lastResult && lastResult.page_languages) || [],
    cookies: (lastResult && lastResult.cookies) || "",
    cookie_list: collected,
    error: (lastResult && lastResult.error) || "",
  };
}
