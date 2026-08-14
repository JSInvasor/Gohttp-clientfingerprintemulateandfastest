import assert from "node:assert/strict";
import test from "node:test";

import {
  LAUNCH_ARGS,
  TARGET_LANG,
  languageList,
  parseProxyURL,
  preferenceList,
  primaryLanguage,
} from "./profile.js";
import { CHALLENGE_TITLE_RE, detectChallengeInPage, isChallengeTitle } from "./challenge.js";
import { explain, verdict } from "./verdict.js";

test("languageList drops quality values and keeps the order", () => {
  assert.deepEqual(languageList("en-US,en;q=0.9"), ["en-US", "en"]);
  assert.deepEqual(languageList("tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"), [
    "tr-TR",
    "tr",
    "en-US",
    "en",
  ]);
  // Order is a fingerprint of its own, so a duplicate is dropped where it
  // repeats rather than resorted.
  assert.deepEqual(languageList("en,en-US,en"), ["en", "en-US"]);
  assert.deepEqual(languageList(""), []);
  assert.deepEqual(languageList(undefined), []);
});

test("primaryLanguage is what --lang takes", () => {
  assert.equal(primaryLanguage("en-US,en;q=0.9"), "en-US");
  assert.equal(primaryLanguage("de-DE"), "de-DE");
  assert.equal(primaryLanguage(""), "");
});

// The header and the UI locale both have to come from one value, in the form
// each flag actually takes.
//
// This used to assert --accept-lang=${TARGET_LANG} — the finished header, passed
// straight through — and that is the bug it was pinning in place. The flag takes
// a preference list, and Chrome 151 handed a header instead emitted
// "en-US,en;q=0.9,en;q=0.9;q=0.8" on the request that earns cf_clearance.
test("the launch flags carry the pinned language in the form each takes", () => {
  assert.ok(
    LAUNCH_ARGS.includes(`--accept-lang=${preferenceList(TARGET_LANG)}`),
    `--accept-lang missing from ${LAUNCH_ARGS.join(" ")}`
  );
  assert.ok(
    LAUNCH_ARGS.includes(`--lang=${primaryLanguage(TARGET_LANG)}`),
    `--lang missing from ${LAUNCH_ARGS.join(" ")}`
  );

  // The property that matters more than either exact value: no quality value
  // ever reaches --accept-lang, whatever TARGET_LANG is set to.
  const acceptLang = LAUNCH_ARGS.find((a) => a.startsWith("--accept-lang="));
  assert.ok(
    !acceptLang.includes(";"),
    `${acceptLang} passes a quality value to a flag that takes a preference list`
  );
});

test("parseProxyURL keeps a scheme Chrome would otherwise assume away", () => {
  assert.deepEqual(parseProxyURL("http://1.2.3.4:8080"), {
    host: "1.2.3.4",
    port: "8080",
    username: "",
    password: "",
  });
  // Chrome only assumes HTTP for a bare host:port, so anything else has to keep
  // its scheme or a SOCKS proxy is silently dialled as HTTP.
  assert.equal(parseProxyURL("socks5://1.2.3.4:1080").host, "socks5://1.2.3.4");
  assert.equal(parseProxyURL(""), null);
  assert.equal(parseProxyURL(undefined), null);
});

test("parseProxyURL rejects what it cannot dial", () => {
  assert.throws(() => parseProxyURL("not a url"), /invalid proxy URL/);
  assert.throws(() => parseProxyURL("http://1.2.3.4"), /has no port/);
});

test("proxy credentials survive the URL round trip", () => {
  const escaped = parseProxyURL("http://us%40er:p%40ss@1.2.3.4:8080");
  assert.equal(escaped.username, "us@er");
  assert.equal(escaped.password, "p@ss");

  // A lone '%' is a legal password character. The URL parser stores it verbatim
  // rather than escaping it, so decoding throws — and rejecting a working proxy
  // over that is worse than handing the password back unchanged.
  const literal = parseProxyURL("http://user:pa%ss@1.2.3.4:8080");
  assert.equal(literal.password, "pa%ss");
});

test("the challenge title check is not English-only", () => {
  for (const title of [
    "Just a moment...",
    "Attention Required! | Cloudflare",
    "Bir dakika lütfen",
    "Un momento…",
    "Einen Moment",
    "请稍候…",
  ]) {
    assert.ok(isChallengeTitle(title), `${title} was not recognised as a challenge`);
  }
  for (const title of ["Example Domain", "Shop | Home", ""]) {
    assert.equal(isChallengeTitle(title), false, `${title} was read as a challenge`);
  }
  // Global flags carry lastIndex between calls; this regex must not.
  assert.ok(!CHALLENGE_TITLE_RE.global);
});

// detectChallengeInPage runs in the browser, so it is exercised here against a
// stand-in document rather than a real one: it only ever calls
// document.querySelector and reads window._cf_chl_opt, and both are supplied.
//
// The case that matters is the negative one. Cloudflare puts its JS-detection
// script on ordinary 200 responses, so a selector matching the whole of
// /cdn-cgi/challenge-platform/ reads a cleared page as a challenged one — and
// the caller's response to "still challenged" is to wait until its deadline and
// then retry the whole solve.
test("the challenge markers do not fire on a cleared Cloudflare page", () => {
  const doc = (present) => ({
    querySelector(selector) {
      return present.some((s) => matches(s, selector)) ? {} : null;
    },
  });

  // Enough of a matcher for the selectors this file uses: an id, or a
  // tag[attr*="needle"] with an optional :not([attr*="needle"]).
  const matches = (element, selector) => {
    if (selector.startsWith("#")) return element === selector;
    const tag = selector.match(/^[a-z]+/)[0];
    const want = [...selector.matchAll(/\[src\*="([^"]+)"\]/g)].map((m) => m[1]);
    const not = selector.includes(":not(") ? want.pop() : null;
    if (!element.startsWith(tag + ":")) return false;
    const src = element.slice(tag.length + 1);
    if (!want.every((w) => src.includes(w))) return false;
    return !(not && src.includes(not));
  };

  const withDoc = (present, chlOpt) => {
    const priorDoc = globalThis.document;
    const priorOpt = globalThis.window;
    globalThis.document = doc(present);
    globalThis.window = chlOpt ? { _cf_chl_opt: chlOpt } : {};
    try {
      return detectChallengeInPage();
    } finally {
      globalThis.document = priorDoc;
      globalThis.window = priorOpt;
    }
  };

  // A page that cleared. The jsd script is what Cloudflare injects into ordinary
  // responses on a zone with bot management on — it is in the body of the last
  // successful solve recorded in this repo.
  assert.equal(
    withDoc(["script:/cdn-cgi/challenge-platform/scripts/jsd/main.js"], null),
    false,
    "the JS-detection script on a cleared page was read as a challenge"
  );

  // A page that did not.
  assert.equal(withDoc(["#challenge-form"], null), true);
  assert.equal(withDoc(["#challenge-stage"], null), true);
  assert.equal(withDoc(["iframe:https://challenges.cloudflare.com/turnstile/v0"], null), true);
  assert.equal(
    withDoc(["script:/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=1"], null),
    true
  );
  // The bootstrap object, which is there before any of the markup is.
  assert.equal(withDoc([], { cType: "managed" }), true);

  // Nothing at all.
  assert.equal(withDoc([], null), false);
});

test("preferenceList gives the preference list it takes, not a header", () => {
  // The bug this exists for: handed a finished header, Chrome 151 treated the
  // quality values as part of the language codes and emitted
  // "en-US,en;q=0.9,en;q=0.9;q=0.8" on the request that earns cf_clearance.
  assert.equal(preferenceList("en-US,en;q=0.9"), "en-US,en");
  assert.equal(preferenceList("tr-TR,tr;q=0.9"), "tr-TR,tr");
  assert.equal(preferenceList("en-GB,en-US;q=0.9,en;q=0.8"), "en-GB,en-US,en");

  // The base tag stays. It used to be dropped, on the reasoning that Chromium
  // re-adds it when it builds the header — which it does, so the header looked
  // right and navigator.languages did not. Measured on 141 through
  // Emulation.setUserAgentOverride, the two inputs are not interchangeable:
  //
  //   en-US      -> header en-US,en;q=0.9   navigator.languages ["en-US"]
  //   en-US,en   -> header en-US,en;q=0.9   navigator.languages ["en-US","en"]
  //
  // and only the second is a client whose page object agrees with its own
  // header. Dropping it is what put the contradiction back on the wire.
  assert.equal(preferenceList("en-US,en"), "en-US,en");
  assert.equal(preferenceList("de-DE,de;q=0.9"), "de-DE,de");

  // A duplicate is still a duplicate: the list is what the browser reports back
  // as navigator.languages, and no browser lists a tag twice.
  assert.equal(preferenceList("en-US,en,en;q=0.8"), "en-US,en");

  // A genuine second language is not implied by the first, and keeps its place.
  assert.equal(preferenceList("en-US,fr;q=0.9"), "en-US,fr");
  assert.equal(preferenceList("en-US,fr;q=0.9,de;q=0.8"), "en-US,fr,de");

  // Nothing to strip.
  assert.equal(preferenceList("en"), "en");
  assert.equal(preferenceList(""), "");

  // No quality value survives, whatever went in — that is the single property
  // the whole function is for. A q-value reaching the flag mangles the header;
  // one reaching setUserAgentOverride lands inside a language tag, and
  // navigator.languages reports ["en-US", "en;q=0.9"].
  for (const input of [
    "en-US,en;q=0.9",
    "tr-TR,tr;q=0.9,en;q=0.8",
    "en-GB,en-US;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9",
  ]) {
    assert.ok(!preferenceList(input).includes(";"), `${input} leaked a q-value into the pref list`);
  }
});

// The header the run replays with and the page object the challenge reads have
// to name the same languages. This is the invariant the two halves of that share
// — the list the browser is given is exactly the tags of TARGET_LANG, in order.
test("the pinned language survives the trip through the preference list", () => {
  assert.deepEqual(preferenceList(TARGET_LANG).split(","), languageList(TARGET_LANG));

  // The default is the one that matters, since almost every run uses it: a
  // Chrome asking for en-US,en;q=0.9 reports ["en-US", "en"].
  assert.equal(preferenceList("en-US,en;q=0.9"), "en-US,en");
});

// The verdict is the answer replay.js exists to produce, and getting it
// backwards would send someone to rewrite a fingerprint that was never the
// problem. The zone_challenges row is a real run, recorded verbatim: the
// carried cookie challenged, the clearance alone challenged, and a clearance
// the browser earned itself — in the context it earned it in — challenged too.
test("the replay verdict names the case the three attempts describe", () => {
  const challenged = { challenged: true };
  const passed = { challenged: false };

  assert.equal(verdict(passed, null, null), "travels");
  const solved = (o) => ({ ...o, solved_here: true });
  assert.equal(verdict(challenged, solved(challenged), challenged), "zone_challenges");
  assert.equal(verdict(challenged, solved(challenged), null), "zone_challenges");
  assert.equal(verdict(challenged, solved(passed), null), "does_not_travel");

  // A follow-up that never earned a clearance of its own proves nothing about
  // the zone — the challenge may simply not have finished. Reporting it as
  // zone_challenges is how a timeout becomes a finding about Cloudflare.
  assert.equal(verdict(challenged, { challenged: true, solved_here: false }, null), "inconclusive");
  // The bookkeeping being replayed alongside it is the one case that is fixable
  // in this repo, so it is checked before the two that are not.
  assert.equal(verdict(challenged, solved(challenged), passed), "challenge_state");
  assert.equal(verdict(challenged, null, null), "inconclusive");

  // Every verdict says something, and the one that means "stop working on the
  // client" says so in those terms.
  for (const v of ["travels", "zone_challenges", "does_not_travel", "challenge_state", "inconclusive"]) {
    assert.ok(explain(v).length > 40, `${v} explains nothing`);
  }
  assert.match(explain("zone_challenges"), /different exit|-proxy/);
  assert.match(explain("challenge_state"), /solve-all-cookies/);
});
