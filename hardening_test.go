package gofire

import (
	"net/http"
	"net/url"
	"testing"
)

// TestRefererOriginTrimsEverythingPastTheOrigin covers the Sec-Fetch-Site cache
// key. computeSecFetchSite reads only the referer's scheme, host and port, so
// keying the cache on the full referer made one permanent entry per page a
// crawler visited.
func TestRefererOriginTrimsEverythingPastTheOrigin(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://a.com/path/to/page?q=1#frag", "https://a.com"},
		{"https://a.com", "https://a.com"},
		{"https://a.com/", "https://a.com"},
		{"https://a.com:8443/x", "https://a.com:8443"},
		{"https://a.com?q=1", "https://a.com"},
		{"https://a.com#frag", "https://a.com"},
		{"http://user@a.com/x", "http://user@a.com"},
		{"not-a-url", "not-a-url"},
	} {
		if got := refererOrigin(tc.in); got != tc.want {
			t.Errorf("refererOrigin(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSecFetchSiteCacheKeyIsBounded pins that per-request referers that differ
// only past the origin all collapse onto one cache entry.
func TestSecFetchSiteCacheKeyIsBounded(t *testing.T) {
	before := secFetchSiteCacheSize.Load()

	for i := 0; i < 500; i++ {
		u, _ := url.Parse("https://target.example/page")
		req := &http.Request{Method: "GET", URL: u, Header: http.Header{}}
		// A crawler walking a site sets a fresh Referer every request.
		req.Header.Set("Referer", "https://target.example/listing?page="+string(rune('a'+i%26))+itoa(i))
		if got := secFetchSiteFor(req); got != "same-origin" {
			t.Fatalf("iteration %d: Sec-Fetch-Site = %q, want same-origin", i, got)
		}
	}

	if grew := secFetchSiteCacheSize.Load() - before; grew > 1 {
		t.Fatalf("500 distinct referers added %d cache entries, want at most 1", grew)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestSecFetchSiteStillDistinguishesOrigins guards the cache-key change against
// over-collapsing: different referer origins must still produce different
// answers.
func TestSecFetchSiteStillDistinguishesOrigins(t *testing.T) {
	for _, tc := range []struct{ target, referer, want string }{
		{"https://a.example/p", "https://a.example/other", "same-origin"},
		{"https://a.example/p", "https://sub.a.example/x", "same-site"},
		{"https://a.example/p", "https://b.example/x", "cross-site"},
		// Scheme and port break same-origin but not same-site: same-site is
		// decided on the registrable domain alone.
		{"https://a.example/p", "http://a.example/x", "same-site"},
		{"https://a.example/p", "https://a.example:8443/x", "same-site"},
	} {
		u, err := url.Parse(tc.target)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.target, err)
		}
		req := &http.Request{Method: "GET", URL: u, Header: http.Header{}}
		req.Header.Set("Referer", tc.referer)
		if got := secFetchSiteFor(req); got != tc.want {
			t.Errorf("target=%s referer=%s: got %q, want %q", tc.target, tc.referer, got, tc.want)
		}
	}
}

// TestDefaultResponseBodyLimitIsFinite pins the decompression-bomb guard.
// Bytes() decodes Content-Encoding itself and the client advertises br and
// zstd, so an unlimited io.ReadAll over a decoder is an OOM waiting for a
// hostile endpoint.
func TestDefaultResponseBodyLimitIsFinite(t *testing.T) {
	if n := defaultClientConfig().maxResponseBody; n <= 0 {
		t.Fatalf("default maxResponseBody = %d, want a finite positive cap", n)
	}

	// Opting out explicitly must still work.
	cfg := defaultClientConfig()
	WithMaxResponseBodySize(0)(&cfg)
	if cfg.maxResponseBody != 0 {
		t.Fatalf("WithMaxResponseBodySize(0) = %d, want 0 (unlimited)", cfg.maxResponseBody)
	}
}

// TestNextProxyEntryHandlesEmptyRotator pins the nil check. NextEntry returns
// nil for a rotator holding no proxies; nextProxyEntry dereferenced it anyway,
// which would panic instead of letting dialRaw report "no usable proxies".
func TestNextProxyEntryHandlesEmptyRotator(t *testing.T) {
	pr := &ProxyRotator{health: &proxyHealth{}, primaryIdx: -1}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nextProxyEntry panicked on an empty rotator: %v", r)
		}
	}()

	u, entry := pr.nextProxyEntry()
	if u != nil || entry != nil {
		t.Fatalf("got (%v, %v), want (nil, nil)", u, entry)
	}
}
