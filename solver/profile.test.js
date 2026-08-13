import assert from "node:assert/strict";
import test from "node:test";

import {
  LAUNCH_ARGS,
  TARGET_LANG,
  languageList,
  parseProxyURL,
  primaryLanguage,
} from "./profile.js";
import { CHALLENGE_TITLE_RE, isChallengeTitle } from "./challenge.js";

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

// The header, the UI locale and navigator.languages all have to come from one
// value, or the browser asks for one language and reports another.
test("the launch flags carry the pinned language", () => {
  assert.ok(
    LAUNCH_ARGS.includes(`--accept-lang=${TARGET_LANG}`),
    `--accept-lang missing from ${LAUNCH_ARGS.join(" ")}`
  );
  assert.ok(
    LAUNCH_ARGS.includes(`--lang=${primaryLanguage(TARGET_LANG)}`),
    `--lang missing from ${LAUNCH_ARGS.join(" ")}`
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
