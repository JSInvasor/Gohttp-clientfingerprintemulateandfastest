// Run with: npm test --prefix solver   (or: node --test solver/*.test.js)
//
// Not `node --test solver/`: an explicit directory makes the runner execute
// every .js under it, index.js included, which is a CLI and not a test.
//
// Covers the fallback matcher in cookies.js. The primary path (page.cookies)
// is the browser's own matching and needs a browser to exercise; this is the
// code that runs when that method is unavailable, and a mistake here sends a
// cookie to a host it was never issued to.

import test from "node:test";
import assert from "node:assert/strict";
import { cookieInScope, cookiesForUrl, targetScope } from "./cookies.js";

const scope = (url) => targetScope(url);

test("host-only cookies match their exact host", () => {
  const s = scope("https://example.com/");
  assert.ok(cookieInScope({ domain: "example.com", path: "/" }, s));
  assert.ok(!cookieInScope({ domain: "other.com", path: "/" }, s));
});

test("domain cookies cover subdomains, in either spelling", () => {
  const s = scope("https://www.example.com/");
  assert.ok(cookieInScope({ domain: ".example.com", path: "/" }, s));
  assert.ok(cookieInScope({ domain: "example.com", path: "/" }, s));
  assert.ok(cookieInScope({ domain: "www.example.com", path: "/" }, s));
});

test("a subdomain's cookie does not leak to the parent", () => {
  const s = scope("https://example.com/");
  assert.ok(!cookieInScope({ domain: "www.example.com", path: "/" }, s));
});

test("suffix matching stops at the dot boundary", () => {
  // The bug this guards: endsWith("example.com") alone would hand
  // example.com's cf_clearance to notexample.com and vice versa.
  const s = scope("https://notexample.com/");
  assert.ok(!cookieInScope({ domain: "example.com", path: "/" }, s));
  assert.ok(!cookieInScope({ domain: "notexample.com", path: "/" }, scope("https://example.com/")));
});

test("the challenge iframe's origin is out of scope", () => {
  const s = scope("https://shop.example.com/checkout");
  assert.ok(!cookieInScope({ domain: "challenges.cloudflare.com", path: "/" }, s));
});

test("domain matching ignores case", () => {
  const s = scope("https://WWW.Example.COM/");
  assert.ok(cookieInScope({ domain: "Example.com", path: "/" }, s));
});

test("path matching respects segment boundaries", () => {
  const s = scope("https://example.com/admin/users");
  assert.ok(cookieInScope({ domain: "example.com", path: "/" }, s));
  assert.ok(cookieInScope({ domain: "example.com", path: "/admin" }, s));
  assert.ok(cookieInScope({ domain: "example.com", path: "/admin/" }, s));
  assert.ok(cookieInScope({ domain: "example.com", path: "/admin/users" }, s));
  assert.ok(!cookieInScope({ domain: "example.com", path: "/administrator" }, s));
  assert.ok(!cookieInScope({ domain: "example.com", path: "/other" }, s));
});

test("a cookie with no domain is never in scope", () => {
  assert.ok(!cookieInScope({ path: "/" }, scope("https://example.com/")));
  assert.ok(!cookieInScope({ domain: "", path: "/" }, scope("https://example.com/")));
});

test("cookiesForUrl reads the profile jar and filters it", async () => {
  // The jar carries a cf_clearance for another origin, and the unfiltered list
  // would have handed that back as the solve.
  const browser = {
    cookies: async () => [
      { name: "cf_clearance", value: "third-party", domain: "challenges.cloudflare.com", path: "/" },
      { name: "junk", value: "1", domain: "cdn.other.net", path: "/" },
      { name: "cf_clearance", value: "target", domain: "example.com", path: "/" },
    ],
  };
  const got = await cookiesForUrl(browser, {}, "https://example.com/");
  assert.equal(got.length, 1);
  assert.equal(got[0].value, "target");
});

// The regression this pins: page.cookies was the primary read, and it returns
// an empty list — not an error — when the page handle is no longer attached to
// the target that did the solving, which is what puppeteer-real-browser's
// targetcreated rewrapping produces. A live run reported "cookie_list":[] for a
// site that had just issued a cf_clearance.
test("an empty page read does not mask the profile jar", async () => {
  const page = { cookies: async () => [] };
  const browser = {
    cookies: async () => [
      { name: "cf_clearance", value: "target", domain: "example.com", path: "/" },
      { name: "__cf_bm", value: "bm", domain: "example.com", path: "/" },
    ],
  };
  const got = await cookiesForUrl(browser, page, "https://example.com/");
  assert.equal(got.length, 2, "the profile jar was not consulted");
  assert.ok(got.some((c) => c.name === "cf_clearance"));
});

test("cookiesForUrl falls back to the page when the browser has no jar API", async () => {
  // puppeteer below 23.7 has no Browser.cookies at all.
  const seen = [];
  const page = {
    cookies: async (...urls) => {
      seen.push(urls);
      return [{ name: "sess", value: "1", domain: "example.com", path: "/" }];
    },
  };
  const got = await cookiesForUrl({}, page, "https://example.com/");
  assert.deepEqual(seen, [["https://example.com/"]], "the target url was not passed through");
  assert.equal(got[0].name, "sess");
});

test("cookiesForUrl falls back to the page when the jar read throws", async () => {
  const browser = {
    cookies: async () => {
      throw new Error("protocol error");
    },
  };
  const page = {
    cookies: async () => [{ name: "sess", value: "1", domain: "example.com", path: "/" }],
  };
  const got = await cookiesForUrl(browser, page, "https://example.com/");
  assert.equal(got[0].name, "sess");
});

test("cookiesForUrl yields nothing rather than throwing on a bad url", async () => {
  const browser = { cookies: async () => [{ name: "a", value: "1", domain: "example.com" }] };
  assert.deepEqual(await cookiesForUrl(browser, {}, "not a url"), []);
});
