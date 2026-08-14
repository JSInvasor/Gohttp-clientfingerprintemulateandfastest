// The identity every page a solve or a replay drives has to present.
//
// Shared because it has to be the same in both, and was not. index.js pinned the
// User-Agent, the Client Hints and the language on every page it opened;
// replay.js — whose entire job is to present the resulting cookie and report
// whether the edge accepts it — opened its contexts and pinned nothing at all.
//
// That is not a cosmetic difference. cf_clearance is bound to the User-Agent it
// was issued to, and the two differ in a way that is easy to miss: the solve
// claims Chrome's frozen build, "Chrome/151.0.0.0", while an unpinned page
// reports the browser's real one, "Chrome/151.0.7922.108". Different string,
// same browser, refused cookie. So replay.js answered "the edge refused this
// clearance" on every run it has ever made, including the ones written up as a
// finding about clearances not travelling — a result its own method guaranteed
// before the request went out.
//
// Living in one module is the fix that keeps: there is no longer a second place
// for the identity to be set, or forgotten.

import { TARGET_LANG, TARGET_UA, preferenceList, userAgentMetadata } from "./profile.js";
import { errorMessage } from "./cleanup.js";

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
export function acceptLanguageOf(page) {
  return observedAcceptLanguage.get(page) || TARGET_LANG;
}
