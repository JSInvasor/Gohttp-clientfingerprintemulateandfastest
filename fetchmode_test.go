package gofire

import (
	"net/http"
	"testing"
)

// requestFor builds a request the way DoWithContext stages one: caller headers
// first, then the browser defaults on top.
func requestFor(t *testing.T, browser BrowserProfile, method, rawURL string, headers map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	applyBrowserHeaders(req, browser, defaultNavigateAccept, "en-US,en;q=0.9")
	return req
}

// TestFetchModeAnnotation pins how each kind of request is labelled.
//
// Stamping every request as a document navigation was the single largest logic
// gap in the emulation: a POST with a JSON body announcing
// Sec-Fetch-Mode: navigate, Sec-Fetch-Dest: document and Accept: text/html is
// something no browser can produce, so it gives away a synthetic client on its
// own regardless of how exact the TLS and HTTP/2 layers are.
func TestFetchModeAnnotation(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    map[string]string
		absent  []string
	}{
		{
			name:   "GET is a navigation",
			method: "GET",
			want: map[string]string{
				"Sec-Fetch-Mode": "navigate",
				"Sec-Fetch-Dest": "document",
				"Accept":         defaultNavigateAccept,
			},
			absent: []string{"Origin"},
		},
		{
			name:    "JSON POST is a fetch",
			method:  "POST",
			headers: map[string]string{"Content-Type": "application/json"},
			want: map[string]string{
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Accept":         "*/*",
				"Origin":         "https://api.example.com",
			},
		},
		{
			name:    "form POST stays a navigation",
			method:  "POST",
			headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			want: map[string]string{
				"Sec-Fetch-Mode": "navigate",
				"Sec-Fetch-Dest": "document",
				// A form submission does carry Origin.
				"Origin": "https://api.example.com",
			},
		},
		{
			name:   "PUT is a fetch",
			method: "PUT",
			want: map[string]string{
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
				"Accept":         "*/*",
			},
		},
		{
			name:   "DELETE is a fetch",
			method: "DELETE",
			want: map[string]string{
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Dest": "empty",
			},
		},
		{
			name:    "caller-set Sec-Fetch headers win",
			method:  "POST",
			headers: map[string]string{"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"},
			want: map[string]string{
				"Sec-Fetch-Mode": "no-cors",
				"Sec-Fetch-Dest": "image",
			},
		},
	}

	for _, browser := range []struct {
		name string
		p    BrowserProfile
	}{{"safari", SafariIOS18}, {"chrome", Chrome150}} {
		for _, tc := range cases {
			t.Run(browser.name+"/"+tc.name, func(t *testing.T) {
				req := requestFor(t, browser.p, tc.method, "https://api.example.com/v1/items", tc.headers)
				for k, want := range tc.want {
					if got := req.Header.Get(k); got != want {
						t.Errorf("%s = %q, want %q", k, got, want)
					}
				}
				for _, k := range tc.absent {
					if got := req.Header.Get(k); got != "" {
						t.Errorf("%s should be absent, got %q", k, got)
					}
				}
			})
		}
	}
}

// TestChromeNavigationOnlyHeaders pins that Upgrade-Insecure-Requests and
// Sec-Fetch-User appear on navigations only. Chrome never attaches either to a
// fetch or XHR, so sending them on an API call is a mismatch a scorer can see.
func TestChromeNavigationOnlyHeaders(t *testing.T) {
	nav := requestFor(t, Chrome150, "GET", "https://example.com/", nil)
	if nav.Header.Get("Upgrade-Insecure-Requests") != "1" {
		t.Error("navigation is missing Upgrade-Insecure-Requests")
	}
	if nav.Header.Get("Sec-Fetch-User") != "?1" {
		t.Error("navigation is missing Sec-Fetch-User")
	}
	if got := nav.Header.Get("Priority"); got != "u=0, i" {
		t.Errorf("navigation Priority = %q, want %q", got, "u=0, i")
	}

	api := requestFor(t, Chrome150, "POST", "https://example.com/api",
		map[string]string{"Content-Type": "application/json"})
	if got := api.Header.Get("Upgrade-Insecure-Requests"); got != "" {
		t.Errorf("fetch carries Upgrade-Insecure-Requests = %q", got)
	}
	if got := api.Header.Get("Sec-Fetch-User"); got != "" {
		t.Errorf("fetch carries Sec-Fetch-User = %q", got)
	}
	if got := api.Header.Get("Priority"); got != "u=1, i" {
		t.Errorf("fetch Priority = %q, want %q", got, "u=1, i")
	}
}

// TestFetchSameOriginMode pins that a script request staying inside its own
// origin is labelled same-origin rather than cors.
func TestFetchSameOriginMode(t *testing.T) {
	req := requestFor(t, Chrome150, "POST", "https://example.com/api", map[string]string{
		"Content-Type": "application/json",
		"Referer":      "https://example.com/app",
	})
	if got := req.Header.Get("Sec-Fetch-Mode"); got != "same-origin" {
		t.Errorf("Sec-Fetch-Mode = %q, want same-origin", got)
	}
	if got := req.Header.Get("Sec-Fetch-Site"); got != "same-origin" {
		t.Errorf("Sec-Fetch-Site = %q, want same-origin", got)
	}
	if got := req.Header.Get("Origin"); got != "https://example.com" {
		t.Errorf("Origin = %q, want https://example.com", got)
	}
}

// TestOriginFollowsReferer pins that Origin reflects the initiating document,
// not the target, on a cross-origin call.
func TestOriginFollowsReferer(t *testing.T) {
	req := requestFor(t, Chrome150, "POST", "https://api.other.test/v1", map[string]string{
		"Content-Type": "application/json",
		"Referer":      "https://app.example.com/dashboard",
	})
	if got := req.Header.Get("Origin"); got != "https://app.example.com" {
		t.Errorf("Origin = %q, want https://app.example.com", got)
	}
	if got := req.Header.Get("Sec-Fetch-Mode"); got != "cors" {
		t.Errorf("Sec-Fetch-Mode = %q, want cors", got)
	}
}

// TestConfiguredAcceptSurvivesFetchMode pins that WithAccept is honoured. Only
// the built-in navigation default is swapped for */*.
func TestConfiguredAcceptSurvivesFetchMode(t *testing.T) {
	req, err := http.NewRequest("POST", "https://example.com/api", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	applyBrowserHeaders(req, Chrome150, "application/vnd.api+json", "en-US")

	if got := req.Header.Get("Accept"); got != "application/vnd.api+json" {
		t.Errorf("Accept = %q, want the configured value", got)
	}
}
