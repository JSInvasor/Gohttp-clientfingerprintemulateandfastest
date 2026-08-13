// Cookie scoping for the solved session.
//
// browser.cookies() takes no arguments: it returns every cookie in the profile,
// for every origin the session touched. The URL that used to be passed to it was
// silently ignored, which broke two things at once.
//
//   - A challenge run navigates cross-origin and back, and the challenge host
//     sets its own cf_clearance on the way through. The clearance check
//     therefore accepted another domain's cookie as proof that the target had
//     been solved.
//   - The `cookies` string handed back is meant to be pasted into a Cookie:
//     header for the target. Built from every origin, it sends foreign cookies
//     to the target, and duplicate names collapse in an order nothing controls.
//
// Both measured against Chromium 141. browser.cookies() and browser.cookies(url)
// return byte-identical lists, and a solve driven through a cross-origin
// redirect chain produced this before the fix:
//
//   cookies:  cf_clearance=THIRD_PARTY; tp_junk=1; cf_clearance=REAL; __cf_bm=bm1
//   reported: cf_clearance=THIRD_PARTY
//
// — two clearance cookies in one header, the wrong one first, and the wrong one
// reported as the solve.
//
// page.cookies(url) applies real domain and path matching in the browser, which
// is exactly the question being asked, so it is the primary path. The matcher
// below is the fallback for puppeteer builds where the page-level method is
// gone, and it deliberately errs toward excluding a cookie: sending one cookie
// too few costs a retry, sending one too many leaks it to the wrong host.

// targetScope reduces a URL to what cookie matching needs. Throws on a URL that
// does not parse, which is a caller bug rather than a cookie mismatch.
export function targetScope(target) {
  const u = new URL(target);
  return { host: u.hostname.toLowerCase(), path: u.pathname || "/" };
}

// cookieInScope implements the domain-match and path-match rules from RFC 6265
// §5.1.3-5.1.4, minus the public-suffix check the browser does for us on the
// primary path.
//
// A leading dot on the domain attribute is legacy syntax for "and subdomains",
// which is also what a bare host-matching cookie means to a subdomain, so both
// are treated the same: exact host, or a dot-boundary suffix of it. Matching on
// a bare suffix would let "evil-example.com" collect "example.com" cookies.
export function cookieInScope(cookie, scope) {
  const domain = String(cookie.domain || "")
    .replace(/^\./, "")
    .toLowerCase();
  if (!domain) return false;
  if (scope.host !== domain && !scope.host.endsWith("." + domain)) return false;

  const cookiePath = cookie.path || "/";
  if (cookiePath === "/") return true;
  if (scope.path === cookiePath) return true;
  // "/admin" covers "/admin/x" but not "/administrator".
  return scope.path.startsWith(
    cookiePath.endsWith("/") ? cookiePath : cookiePath + "/"
  );
}

// cookiesForUrl returns only the cookies that belong on a request to target.
//
// The whole-profile jar is the read, and the filter above is what makes it
// correct. page.cookies(url) does the matching in the browser and was the
// primary path here, which was a mistake: puppeteer-real-browser re-wraps pages
// on targetcreated to drive the challenge widget, so the page handle this code
// holds is not always attached to the target that did the solving. When it is
// not, page.cookies returns an empty list — and an empty list is not an error,
// so it was taken as the answer and a solved session reported no cookies at all.
// Against a live Cloudflare challenge that produced `"cookie_list":[]` for a
// site that had just issued a cf_clearance.
//
// browser.cookies() reads the profile rather than a page, so it does not depend
// on which handle is live. It only became usable in puppeteer 23.7; the page
// read stays as the fallback for older trees, where it is the only option.
export async function cookiesForUrl(browser, page, target) {
  let scope;
  try {
    scope = targetScope(target);
  } catch {
    return [];
  }

  if (browser && typeof browser.cookies === "function") {
    const all = await browser.cookies().catch(() => null);
    if (all) return all.filter((c) => cookieInScope(c, scope));
  }
  if (page && typeof page.cookies === "function") {
    try {
      return await page.cookies(target);
    } catch {}
  }
  return [];
}
