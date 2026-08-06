package main

import (
	"net/http"
	"strings"
	"testing"
)

// The point of the HTTP leg is telling a challenge apart from a block: one is
// answered by carrying a token, the other is not answerable at all. Getting
// that backwards sends the reader to the wrong fix, so the mapping is pinned.
func TestClassify(t *testing.T) {
	tests := []struct {
		name   string
		status int
		header http.Header
		body   string
		vendor string
		kind   string
	}{
		{
			name:   "cloudflare managed challenge",
			status: 403,
			header: http.Header{"Cf-Mitigated": {"challenge"}, "Server": {"cloudflare"}},
			body:   `<title>Just a moment...</title>`,
			vendor: "Cloudflare",
			kind:   "challenge",
		},
		{
			name:   "cloudflare challenge without the header",
			status: 503,
			header: http.Header{"Server": {"cloudflare"}},
			body:   `<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>`,
			vendor: "Cloudflare",
			kind:   "challenge",
		},
		{
			name:   "cloudflare firewall block is not a challenge",
			status: 403,
			header: http.Header{"Server": {"cloudflare"}},
			body:   `<title>Attention Required! | Cloudflare</title><p>Error 1020</p>`,
			vendor: "Cloudflare",
			kind:   "block",
		},
		{
			name:   "cloudflare rate limit",
			status: 429,
			header: http.Header{"Server": {"cloudflare"}},
			body:   `<title>Error 1015</title>`,
			vendor: "Cloudflare",
			kind:   "rate limit",
		},
		{
			name:   "datadome captcha",
			status: 403,
			header: http.Header{"X-Datadome": {"protected"}},
			body:   `<iframe src="https://geo.captcha-delivery.com/captcha/?initialCid=x"></iframe>`,
			vendor: "DataDome",
			kind:   "challenge",
		},
		{
			name:   "akamai access denied",
			status: 403,
			header: http.Header{"Server": {"AkamaiGHost"}},
			body:   `Access Denied. Reference #18.4c2ab17.1730000000.1a2b3c`,
			vendor: "Akamai",
			kind:   "block",
		},
		{
			name:   "akamai bot manager watching a 200",
			status: 200,
			header: http.Header{"Set-Cookie": {"_abck=A1B2~-1~; Path=/", "bm_sz=99; Path=/"}},
			body:   `<title>Home</title>`,
			vendor: "Akamai",
			kind:   "watching",
		},
		{
			name:   "imperva incident page",
			status: 403,
			header: http.Header{"X-Iinfo": {"9-1234567-1234568 NNNN CT(1 1 0)"}},
			body:   `<b>Incapsula incident ID</b>: 0000-1111`,
			vendor: "Imperva",
			kind:   "block",
		},
		{
			name:   "aws waf challenge",
			status: 405,
			header: http.Header{"X-Amzn-Waf-Action": {"challenge"}},
			body:   ``,
			vendor: "AWS WAF",
			kind:   "challenge",
		},
		{
			name:   "captcha with nobody named",
			status: 200,
			header: http.Header{},
			body:   `<div class="g-recaptcha" data-sitekey="x"></div>`,
			vendor: "",
			kind:   "challenge",
		},
		{
			name:   "403 that says it is a quota is a rate limit",
			status: 403,
			header: http.Header{"Server": {"Varnish"}},
			body:   `{"message":"API rate limit exceeded for 1.2.3.4."}`,
			vendor: "Varnish",
			kind:   "rate limit",
		},
		{
			name:   "plain 403 with no vendor",
			status: 403,
			header: http.Header{"Server": {"nginx"}},
			body:   `<title>403 Forbidden</title>`,
			vendor: "nginx",
			kind:   "block",
		},
		{
			name:   "clean response carries no signal",
			status: 200,
			header: http.Header{"Server": {"nginx"}},
			body:   `<title>Home</title><p>hello</p>`,
			vendor: "",
			kind:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.status, tt.header, []byte(tt.body))
			if got.vendor != tt.vendor || got.kind != tt.kind {
				t.Fatalf("classify() = vendor %q kind %q, want vendor %q kind %q (why: %s)",
					got.vendor, got.kind, tt.vendor, tt.kind, got.why)
			}
			if tt.kind != "" && got.why == "" {
				t.Errorf("classify() named %q %q without evidence", got.vendor, got.kind)
			}
		})
	}
}

// A vendor marker quoted in a page about bot protection is not that vendor
// answering. Only the body of an actual edge response should classify, so the
// markers are matched, not merely mentioned — this pins the one case where the
// distinction is cheap to keep: headers outrank body text.
func TestClassifyPrefersHeaderOverBody(t *testing.T) {
	h := http.Header{"Cf-Mitigated": {"challenge"}}
	body := `Incapsula incident ID 1234 and a g-recaptcha widget`
	got := classify(403, h, []byte(body))
	if got.vendor != "Cloudflare" {
		t.Fatalf("header evidence lost to body text: got %q", got.vendor)
	}
	if !strings.Contains(got.why, "cf-mitigated") {
		t.Errorf("why = %q, want the header quoted back", got.why)
	}
}

func TestPageTitle(t *testing.T) {
	tests := []struct {
		body string
		want string
	}{
		{`<html><head><title>Just a moment...</title></head>`, `"Just a moment..."`},
		{"<title>\n  Access\n  denied\n</title>", `"Access denied"`},
		{`<TITLE lang="en">Attention Required!</TITLE>`, `"Attention Required!"`},
		{`{"error":"forbidden"}`, ``},
		{`<title></title>`, ``},
	}
	for _, tt := range tests {
		if got := pageTitle([]byte(tt.body)); got != tt.want {
			t.Errorf("pageTitle(%q) = %q, want %q", tt.body, got, tt.want)
		}
	}
}

// A proxy or gateway that refuses in plaintext puts its whole reason in the
// body. Printing only <title> would drop it.
func TestBodyGist(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"html title wins", `<html><title>Just a moment...</title><p>x</p>`, `"Just a moment..."`},
		{"plaintext refusal", "Blocked by policy: destination not allowed\n", `"Blocked by policy: destination not allowed"`},
		{"json error", `{"error":"forbidden","code":1010}`, `"{"error":"forbidden","code":1010}"`},
		{"markup without a title says nothing", `<html><body><div>hi</div></body></html>`, ``},
		{"binary body says nothing", "\x00\x01\x02gzipped", ``},
		{"empty body", ``, ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bodyGist([]byte(tt.body)); got != tt.want {
				t.Errorf("bodyGist(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

func TestPageTitleTruncates(t *testing.T) {
	long := "<title>" + strings.Repeat("a", 200) + "</title>"
	got := pageTitle([]byte(long))
	if len([]rune(got)) > 74 { // 70 runes + the ellipsis and quotes
		t.Errorf("pageTitle did not truncate: %d runes", len([]rune(got)))
	}
}

// -target may pin an address the client cannot be handed, and the request then
// resolves the name itself. Reporting that is the difference between a result
// about the target and a result about whatever DNS returns.
func TestRequestURL(t *testing.T) {
	tests := []struct {
		addr, name, path string
		want             string
		pinned           bool
	}{
		{"example.com:443", "example.com", "/", "https://example.com/", false},
		{"example.com:8443", "example.com", "/", "https://example.com:8443/", false},
		{"1.2.3.4:443", "example.com", "/", "https://example.com/", true},
		{"example.com:443", "example.com", "api/v1", "https://example.com/api/v1", false},
		{"example.com:443", "example.com", "/s?q=1&x=2", "https://example.com/s?q=1&x=2", false},
		{"example.com:443", "example.com", "", "https://example.com/", false},
	}
	for _, tt := range tests {
		got, pinned := requestURL(tt.addr, tt.name, tt.path)
		if got != tt.want || pinned != tt.pinned {
			t.Errorf("requestURL(%q, %q, %q) = %q/%v, want %q/%v",
				tt.addr, tt.name, tt.path, got, pinned, tt.want, tt.pinned)
		}
	}
}
