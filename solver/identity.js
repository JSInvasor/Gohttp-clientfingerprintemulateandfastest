// The identity every page a solve or a replay drives has to present.
//
// This file is deliberately a copy of what workingBrowsers/index.js does, and
// deviating from it is what this repo has spent a branch paying for. That
// version — the solver as it stood before the rewrite — earns a cf_clearance
// from a datacenter VPS address and replays it for 113 requests without a
// challenge. The rewritten one, from the same box against the same target, gets
// a managed challenge. Three separate theories about why each individual change
// was safe turned out to be wrong, so the rule here is now: what the page and
// the edge can see matches the version that works, and anything that cannot be
// observed from outside the browser is free to differ.
//
// Shared as a module because replay.js — whose entire job is to present the
// resulting cookie and report whether the edge accepts it — was opening its
// contexts and pinning nothing at all. cf_clearance is bound to the User-Agent
// it was issued to, and the two differ in a way that is easy to miss: the solve
// claims Chrome's frozen build, "Chrome/151.0.0.0", while an unpinned page
// reports the browser's real one, "Chrome/151.0.7922.108". Different string,
// same browser, refused cookie. So replay.js answered "the edge refused this
// clearance" on every run it ever made, including the ones written up as a
// finding. One module means there is no second place to forget it.

import {
  TARGET_LANG,
  TARGET_UA,
  expectedAcceptLanguage,
  languageList,
  userAgentMetadata,
} from "./profile.js";

// The one language value everything on this side is built from: the header the
// browser will actually put on the wire, given the --accept-lang in LAUNCH_ARGS.
//
// The shim below and acceptLanguageOf() both read it, so the page object, the
// wire and the seed gofire replays with cannot disagree with each other. They
// used to: the header came from the box's locale and the other two came from
// SOLVER_LANG.
const SENT_LANG = expectedAcceptLanguage(TARGET_LANG);

// preparePage puts the gofire-matching identity on a page before it navigates.
//
// Every page a solve drives goes through this, whether it is the one connect()
// handed back or one opened in a context of its own. A page that missed it
// would carry the browser's own identity into the request that earns the
// cookie, which is the mismatch this whole file exists to prevent — and in
// batch mode there are as many pages as there are exits.
export async function preparePage(page, chromiumVersion) {
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

  // Stealth shim, singular — and it is here because the version that works has
  // it, not because the argument for it survived scrutiny.
  //
  // It does not. Object.defineProperty(navigator, "languages") leaves an own
  // property on the instance where Navigator.prototype is the only place one
  // belongs, and an accessor that stringifies as an arrow function where every
  // native one reads [native code]:
  //
  //                              shimmed              untouched
  //   own property on navigator  true                 false
  //   getter toString            () => languages      [native code]
  //
  // Both are one probe away on the request that earns cf_clearance. That
  // reasoning is why the shim was removed, and removing it is part of what
  // produced a solver that no longer passes.
  //
  // It was replaced, for a while, with Emulation.setUserAgentOverride's
  // acceptLanguage — which sets the header and navigator.languages together
  // from inside the browser, leaving no own property and a native getter.
  // Measured on Chromium 141 that is exactly what it does, and it is a strictly
  // better mechanism by every argument available. It also still got a managed
  // challenge on the box that matters.
  //
  // So the measurement that decides is not the probe, it is the target: this is
  // what the working version does, character for character, and it is what
  // ships until there is a live A/B saying otherwise. A better mechanism that
  // does not pass is not better.
  //
  // The one liberty taken is reading the list from the header the browser will
  // send instead of the literal ["en-US", "en"]. On the default SOLVER_LANG the
  // two are the same array, so nothing observable changes.
  //
  // It is derived from the *sent* header rather than from SOLVER_LANG, and that
  // is the fix rather than a detail. SOLVER_LANG is what was asked for;
  // everything past the first tag of it is discarded by the browser, so a shim
  // built from it advertises languages the header does not carry. Measured on
  // Chromium 141: --accept-lang=tr-TR,en-US,en sends `tr-TR,tr;q=0.9`, and a
  // page claiming ["tr-TR","en-US","en"] beside it is a contradiction of the
  // same kind this shim exists to remove.
  await page.evaluateOnNewDocument((languages) => {
    try {
      Object.defineProperty(navigator, "languages", {
        get: () => languages,
      });
    } catch {}
  }, languageList(SENT_LANG));
}

// acceptLanguageOf reports the language this solve advertised, for the seed the
// Go side replays with.
//
// It is derived rather than observed, because observing it means a
// page.on("request") listener and the working version does not have one. What
// changed is what it derives from. It used to return TARGET_LANG — the value
// that was *asked for* — and that made it wrong twice over:
//
//   - with no --accept-lang the browser sent the box's locale, so on any image
//     that is not en_US the reported header was simply not the one sent, and the
//     cookie was replayed under a language its own session never advertised.
//   - send's reportLanguageDrift and reportLanguageSplit are the checks for
//     exactly that, and both were being handed the asked-for value. They
//     compared it against itself and agreed every time. The instrument that
//     would have caught this was blind by construction.
//
// Now the flag pins the header and this reports what the flag produces, so the
// two are the same thing for a real reason rather than by luck of the locale.
export function acceptLanguageOf(_page) {
  return SENT_LANG;
}
