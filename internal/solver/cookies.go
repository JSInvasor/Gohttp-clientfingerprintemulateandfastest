package solver

import (
	"net/url"
	"strings"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/cdp"
)

// Cookie scoping for the solved session.
//
// The jar read is the whole context's, and the filter here is what makes it
// correct. Two things go wrong without it, and both did:
//
//   - A challenge run navigates cross-origin and back, and the challenge host
//     sets its own cf_clearance on the way through. The clearance check then
//     accepts another domain's cookie as proof that the target was solved.
//   - The header-ready string is meant to be pasted into a Cookie: header for
//     the target. Built from every origin it sends foreign cookies to the
//     target, and duplicate names collapse in an order nothing controls.
//
// Measured against Chromium 141, a solve driven through a cross-origin redirect
// chain produced this before the fix:
//
//	cookies:  cf_clearance=THIRD_PARTY; tp_junk=1; cf_clearance=REAL; __cf_bm=bm1
//	reported: cf_clearance=THIRD_PARTY
//
// — two clearance cookies in one header, the wrong one first, and the wrong one
// reported as the solve.

// Scope is what cookie matching needs from a URL.
type Scope struct {
	Host string
	Path string
}

// TargetScope reduces a URL to a Scope. It reports whether the URL parsed; a URL
// that does not is a caller bug rather than a cookie mismatch.
func TargetScope(target string) (Scope, bool) {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return Scope{}, false
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return Scope{Host: strings.ToLower(u.Hostname()), Path: path}, true
}

// CookieInScope implements the domain-match and path-match rules from RFC 6265
// §5.1.3-5.1.4, minus the public-suffix check.
//
// A leading dot on the domain attribute is legacy syntax for "and subdomains",
// which is also what a bare host-matching cookie means to a subdomain, so both
// are treated the same: exact host, or a dot-boundary suffix of it. Matching on
// a bare suffix would let "evil-example.com" collect "example.com" cookies.
//
// It deliberately errs toward excluding a cookie: sending one too few costs a
// retry, sending one too many leaks it to the wrong host.
func CookieInScope(c cdp.Cookie, scope Scope) bool {
	domain := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
	if domain == "" {
		return false
	}
	if scope.Host != domain && !strings.HasSuffix(scope.Host, "."+domain) {
		return false
	}

	path := c.Path
	if path == "" || path == "/" {
		return true
	}
	if scope.Path == path {
		return true
	}
	// "/admin" covers "/admin/x" but not "/administrator".
	prefix := path
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return strings.HasPrefix(scope.Path, prefix)
}

// CookiesForURL returns only the cookies that belong on a request to target.
func CookiesForURL(all []cdp.Cookie, target string) []cdp.Cookie {
	scope, ok := TargetScope(target)
	if !ok {
		return nil
	}
	out := make([]cdp.Cookie, 0, len(all))
	for _, c := range all {
		if CookieInScope(c, scope) {
			out = append(out, c)
		}
	}
	return out
}

// CookieHeader renders cookies the way a Cookie: header carries them.
func CookieHeader(cookies []cdp.Cookie) string {
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// HasClearance reports whether this list carries the cookie that decides a
// solve. Everything else in the jar is context.
func HasClearance(cookies []cdp.Cookie) bool {
	for _, c := range cookies {
		if c.Name == "cf_clearance" {
			return true
		}
	}
	return false
}
