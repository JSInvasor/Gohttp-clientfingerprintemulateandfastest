import assert from "node:assert/strict";
import test from "node:test";

import {
  LAUNCH_ARGS,
  TARGET_LANG,
  expectedAcceptLanguage,
  languageList,
  localeEnv,
  parseProxyURL,
  pinProcessLocale,
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

// The launch list is what the solver that passes a live zone launches with, plus
// exactly one flag whose absence was a bug.
//
// It used to be read out of workingBrowsers/profile.js, which is no longer in the
// tree — so the assertion had been failing with ENOENT rather than checking
// anything. The reference is transcribed here instead; `git show
// 29f044c^:workingBrowsers/profile.js` is the original.
const WORKING_VERSION_LAUNCH_ARGS = [
  "--no-sandbox",
  "--disable-setuid-sandbox",
  "--disable-dev-shm-usage",
  "--disable-blink-features=AutomationControlled",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-features=IsolateOrigins,site-per-process",
  "--window-size=1920,1080",
  "--use-gl=angle",
  "--use-angle=swiftshader",
];

test("the launch flags match the solver that passes a live zone", () => {
  // Everything the working version has, in its order, unchanged.
  assert.deepEqual(
    LAUNCH_ARGS.filter((a) => !a.startsWith("--accept-lang=")),
    WORKING_VERSION_LAUNCH_ARGS
  );

  // --lang stays out. Measured on Chromium 141.0.7390.37 from a tr_TR box it
  // moves neither the Accept-Language header nor Intl's resolved locale, so it
  // is a difference from the working version that buys nothing.
  assert.ok(
    !LAUNCH_ARGS.some((a) => a.startsWith("--lang=")),
    "--lang is back in the launch list; it changes nothing the page can see"
  );
});

// --accept-lang is the one addition, and this pins both halves of why it is safe.
//
// On the configuration the working version was validated on — an en_US box, the
// default SOLVER_LANG — it is a measured no-op: header en-US,en;q=0.9,
// navigator.languages ["en-US"], Intl en-US, with the flag and without it. Off
// that configuration it is what stops the header following the box's locale while
// the shim asserts something else.
//
// It carries the primary tag only, because everything after the first tag is
// discarded by the browser; passing more promises a header that is not sent.
test("--accept-lang carries the primary tag of the language being solved with", () => {
  const flag = LAUNCH_ARGS.find((a) => a.startsWith("--accept-lang="));
  assert.ok(flag, "--accept-lang is missing; the header follows the box's locale without it");
  assert.equal(flag, `--accept-lang=${primaryLanguage(TARGET_LANG)}`);
  assert.equal(flag, "--accept-lang=en-US", "the default pin moved");
  assert.ok(
    !/;q=/.test(flag),
    "--accept-lang was handed a header rather than a preference list; " +
      "Chrome 151 answered that with `en-US,en;q=0.9,en;q=0.9;q=0.8`"
  );
});

// The header the browser derives from that flag, which is the value the shim and
// the report are both built from. Measured on Chromium 141.0.7390.37, one run per
// row, with LANG/LC_ALL varied to prove the flag rather than the locale decides:
//
//   --accept-lang        header sent        navigator.languages
//   en-US                en-US,en;q=0.9     ["en-US"]
//   en-US,en             en-US,en;q=0.9     ["en-US"]
//   en-US,en,de          en-US,en;q=0.9     ["en-US"]
//   tr-TR,en-US,en       tr-TR,tr;q=0.9     ["tr-TR"]
//   de,en                de                 ["de"]
//   pt-BR                pt-BR,pt;q=0.9     ["pt-BR"]
//   es-419               es-419,es;q=0.9    ["es-419"]
//   tr                   tr                 ["tr"]
test("expectedAcceptLanguage is the header the browser derives, not the one asked for", () => {
  assert.equal(expectedAcceptLanguage("en-US,en;q=0.9"), "en-US,en;q=0.9");
  assert.equal(expectedAcceptLanguage("pt-BR"), "pt-BR,pt;q=0.9");
  assert.equal(expectedAcceptLanguage("es-419"), "es-419,es;q=0.9");
  assert.equal(expectedAcceptLanguage("tr"), "tr");
  assert.equal(expectedAcceptLanguage("de,en"), "de");
  // Everything past the first tag is discarded by the browser, so it must be
  // discarded here too — reporting it would promise a header that is not sent,
  // and the shim built from it would list languages the header does not carry.
  assert.equal(expectedAcceptLanguage("tr-TR,en-US;q=0.8,en;q=0.7"), "tr-TR,tr;q=0.9");
  assert.equal(expectedAcceptLanguage(""), "");
});

// The three places the language shows have to agree, because a browser that
// advertises one language on the wire and lists another in the page object is not
// a browser that exists — and it was doing it on the request that earns
// cf_clearance.
test("the header, the page object and the seed all come from one value", () => {
  const sent = expectedAcceptLanguage(TARGET_LANG);
  assert.equal(sent, "en-US,en;q=0.9");
  // What the shim hands navigator.languages. The browser natively reports only
  // the first tag (["en-US"], measured above), which is the contradiction the
  // shim is there to remove: the header advertises "en" at q=0.9.
  // Which on the default is byte-identical to the working version's hardcoded
  // ["en-US", "en"], so nothing observable changed on the configuration that
  // passes a live zone.
  assert.deepEqual(languageList(sent), ["en-US", "en"]);
});

// Intl is the half no launch flag reaches: it answers from ICU, which reads
// LC_ALL. Measured on a tr_TR box, --accept-lang=en-US set throughout —
//
//   env untouched            header en-US,en;q=0.9   Intl tr
//   LC_ALL=en_US.UTF-8       header en-US,en;q=0.9   Intl en-US
//
// and it works on an image with no generated locales at all (`locale -a` lists
// only C, C.utf8, POSIX): ICU carries its own data and reads the variable.
test("the process locale is pinned to the language being solved with", () => {
  assert.deepEqual(localeEnv("en-US,en;q=0.9"), {
    LANG: "en_US.UTF-8",
    LC_ALL: "en_US.UTF-8",
    LANGUAGE: "en_US:en",
  });
  assert.deepEqual(localeEnv("tr-TR,tr;q=0.9"), {
    LANG: "tr_TR.UTF-8",
    LC_ALL: "tr_TR.UTF-8",
    LANGUAGE: "tr_TR:tr",
  });
  assert.equal(localeEnv(""), null);

  const env = { LANG: "tr_TR.UTF-8", LC_ALL: "tr_TR.UTF-8" };
  pinProcessLocale(env);
  assert.equal(env.LC_ALL, "en_US.UTF-8");

  // The opt-out leaves the box alone rather than half-pinning it.
  const untouched = { LANG: "tr_TR.UTF-8", LC_ALL: "tr_TR.UTF-8", SOLVER_PIN_LOCALE: "0" };
  assert.equal(pinProcessLocale(untouched), null);
  assert.equal(untouched.LC_ALL, "tr_TR.UTF-8");
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

  // The base tag stays, and this is now the only thing preferenceList is for:
  // nothing in the solver builds a flag from it any more.
  //
  // The reason it was kept — that `en-US,en` makes navigator.languages report
  // ["en-US","en"] where `en-US` alone reports ["en-US"] — was measured through
  // Emulation.setUserAgentOverride, which the solver no longer uses. Through the
  // launch flag it does not hold. Measured on Chromium 141.0.7390.37:
  //
  //   --accept-lang=en-US      header en-US,en;q=0.9   navigator.languages ["en-US"]
  //   --accept-lang=en-US,en   header en-US,en;q=0.9   navigator.languages ["en-US"]
  //
  // Identical, and neither lists the "en" the header advertises — which is
  // precisely why the shim in identity.js earns its place rather than the flag
  // being able to do the job alone. expectedAcceptLanguage is what the flag is
  // built from now; this is kept for the shape, and for the Chrome 151
  // measurement above that says a header must never be handed to the flag.
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
