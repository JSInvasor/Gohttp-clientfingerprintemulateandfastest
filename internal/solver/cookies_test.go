package solver

import (
	"testing"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/cdp"
)

func TestTargetScope(t *testing.T) {
	cases := []struct {
		url  string
		host string
		path string
		ok   bool
	}{
		{"https://Example.COM/a/b", "example.com", "/a/b", true},
		{"https://example.com", "example.com", "/", true},
		{"http://sub.example.com:8443/x", "sub.example.com", "/x", true},
		{"not a url", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		scope, ok := TargetScope(tc.url)
		if ok != tc.ok {
			t.Errorf("TargetScope(%q) ok = %v, want %v", tc.url, ok, tc.ok)
			continue
		}
		if ok && (scope.Host != tc.host || scope.Path != tc.path) {
			t.Errorf("TargetScope(%q) = %+v, want %s %s", tc.url, scope, tc.host, tc.path)
		}
	}
}

// The rules that keep one host's cf_clearance from being reported as another's.
func TestCookieInScope(t *testing.T) {
	scope, _ := TargetScope("https://shop.example.com/admin")

	cases := []struct {
		name   string
		cookie cdp.Cookie
		want   bool
	}{
		{"exact host", cdp.Cookie{Domain: "shop.example.com", Path: "/"}, true},
		{"parent domain", cdp.Cookie{Domain: "example.com", Path: "/"}, true},
		{"leading dot is the same thing", cdp.Cookie{Domain: ".example.com", Path: "/"}, true},
		{"case is not significant", cdp.Cookie{Domain: "Example.COM", Path: "/"}, true},
		// The one that matters: a bare suffix match would let this collect the
		// target's cookies.
		{"suffix that is not a dot boundary", cdp.Cookie{Domain: "evil-example.com", Path: "/"}, false},
		{"unrelated host", cdp.Cookie{Domain: "other.com", Path: "/"}, false},
		{"a subdomain is not a parent", cdp.Cookie{Domain: "deep.shop.example.com", Path: "/"}, false},
		{"empty domain", cdp.Cookie{Domain: "", Path: "/"}, false},

		{"matching path", cdp.Cookie{Domain: "shop.example.com", Path: "/admin"}, true},
		{"empty path is root", cdp.Cookie{Domain: "shop.example.com", Path: ""}, true},
		{"a longer path does not match", cdp.Cookie{Domain: "shop.example.com", Path: "/admin/deep"}, false},
		// "/admin" covers "/admin/x" but not "/administrator".
		{"prefix that is not a path boundary", cdp.Cookie{Domain: "shop.example.com", Path: "/ad"}, false},
	}
	for _, tc := range cases {
		if got := CookieInScope(tc.cookie, scope); got != tc.want {
			t.Errorf("%s: CookieInScope(%+v) = %v, want %v", tc.name, tc.cookie, got, tc.want)
		}
	}

	deeper, _ := TargetScope("https://shop.example.com/admin/users")
	if !CookieInScope(cdp.Cookie{Domain: "shop.example.com", Path: "/admin"}, deeper) {
		t.Error(`"/admin" should cover "/admin/users"`)
	}
	if CookieInScope(cdp.Cookie{Domain: "shop.example.com", Path: "/administrator"}, deeper) {
		t.Error(`"/administrator" must not cover "/admin/users"`)
	}
}

// The failure this whole file exists to prevent, end to end: a challenge run
// navigates cross-origin and back, the challenge host sets its own cf_clearance
// on the way through, and the unfiltered jar reports the wrong one as the solve.
func TestCookiesForURLDropsAnotherHostsClearance(t *testing.T) {
	jar := []cdp.Cookie{
		{Name: "cf_clearance", Value: "THIRD_PARTY", Domain: "challenges.cloudflare.com", Path: "/"},
		{Name: "tp_junk", Value: "1", Domain: "tracker.example.net", Path: "/"},
		{Name: "cf_clearance", Value: "REAL", Domain: "target.example", Path: "/"},
		{Name: "__cf_bm", Value: "bm1", Domain: ".target.example", Path: "/"},
	}

	got := CookiesForURL(jar, "https://target.example/")
	if len(got) != 2 {
		t.Fatalf("kept %d cookies, want 2: %+v", len(got), got)
	}
	for _, c := range got {
		if c.Name == "cf_clearance" && c.Value != "REAL" {
			t.Fatalf("reported %q as the clearance; the third party's cookie survived the filter", c.Value)
		}
	}

	header := CookieHeader(got)
	if header != "cf_clearance=REAL; __cf_bm=bm1" {
		t.Errorf("CookieHeader = %q", header)
	}
	if !HasClearance(got) {
		t.Error("HasClearance did not see the target's own clearance")
	}
	if HasClearance(CookiesForURL(jar, "https://unrelated.example/")) {
		t.Error("a host with no cookies of its own was reported as cleared")
	}
}

func TestCookiesForURLRejectsAnUnparseableTarget(t *testing.T) {
	jar := []cdp.Cookie{{Name: "a", Domain: "example.com", Path: "/"}}
	if got := CookiesForURL(jar, "not a url"); len(got) != 0 {
		t.Errorf("CookiesForURL(garbage) = %+v, want nothing", got)
	}
}
