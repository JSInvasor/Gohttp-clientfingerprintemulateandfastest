package gofire

import (
	"net/http"
	"testing"
)

// Sec-Ch-Ua-Platform used to be a hardcoded "Windows", so overriding the
// User-Agent produced a request that named two operating systems at once. That
// is the contradiction the rest of this package is built to avoid, and it is
// invisible unless something checks the pair.
func TestSecChUaPlatformFollowsTheUserAgent(t *testing.T) {
	tests := []struct {
		ua   string
		want string
	}{
		{Chrome151UserAgent, `"Windows"`},
		{Chrome151LinuxUserAgent, `"Linux"`},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36", `"macOS"`},
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36", `"Android"`},
		{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36", `"Chrome OS"`},
		// A UA naming no platform falls back to the profile's own rather than
		// inventing a token no Chrome sends.
		{"something else entirely", `"Windows"`},
	}
	for _, tc := range tests {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		req.Header.Set("User-Agent", tc.ua)
		applyChromeHeaders(req, chromeNavigateAccept, "en-US,en;q=0.9", "", modeNavigate)

		if got := req.Header.Get("Sec-Ch-Ua-Platform"); got != tc.want {
			t.Errorf("UA %q -> Sec-Ch-Ua-Platform %s, want %s", tc.ua, got, tc.want)
		}
		if got := req.Header.Get("User-Agent"); got != tc.ua {
			t.Errorf("UA was rewritten to %q", got)
		}
	}
}

// The configured User-Agent arrives after the caller's headers are staged, so
// the hint has to be derived from the winner rather than from whatever the
// header happened to hold when the builder ran.
func TestSecChUaPlatformFollowsTheConfiguredUserAgent(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	applyChromeHeaders(req, chromeNavigateAccept, "en-US,en;q=0.9", Chrome151LinuxUserAgent, modeNavigate)

	if got := req.Header.Get("User-Agent"); got != Chrome151LinuxUserAgent {
		t.Errorf("User-Agent = %q, want the configured one", got)
	}
	if got := req.Header.Get("Sec-Ch-Ua-Platform"); got != `"Linux"` {
		t.Errorf("Sec-Ch-Ua-Platform = %s, want \"Linux\"", got)
	}
}

// Precedence: a header the caller put on the request beats the configured UA,
// which beats the profile default — and the hint tracks whichever won.
func TestUserAgentPrecedence(t *testing.T) {
	tests := []struct {
		name         string
		header       string
		configured   string
		wantUA       string
		wantPlatform string
	}{
		{"default", "", "", Chrome151UserAgent, `"Windows"`},
		{"configured", "", Chrome151LinuxUserAgent, Chrome151LinuxUserAgent, `"Linux"`},
		{"caller header wins", Chrome151UserAgent, Chrome151LinuxUserAgent, Chrome151UserAgent, `"Windows"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			if tc.header != "" {
				req.Header.Set("User-Agent", tc.header)
			}
			applyChromeHeaders(req, chromeNavigateAccept, "en-US,en;q=0.9", tc.configured, modeNavigate)

			if got := req.Header.Get("User-Agent"); got != tc.wantUA {
				t.Errorf("User-Agent = %q, want %q", got, tc.wantUA)
			}
			if got := req.Header.Get("Sec-Ch-Ua-Platform"); got != tc.wantPlatform {
				t.Errorf("Sec-Ch-Ua-Platform = %s, want %s", got, tc.wantPlatform)
			}
		})
	}
}

// Safari sends no Client Hints at all, but it still has to honour a configured
// User-Agent — the same option feeds both profiles.
func TestSafariHonoursConfiguredUserAgent(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	applySafariHeaders(req, defaultNavigateAccept, "en-US,en;q=0.9", "custom-ua", modeNavigate)

	if got := req.Header.Get("User-Agent"); got != "custom-ua" {
		t.Errorf("User-Agent = %q, want the configured one", got)
	}
	if got := req.Header.Get("Sec-Ch-Ua-Platform"); got != "" {
		t.Errorf("Safari sent Sec-Ch-Ua-Platform: %s", got)
	}
}

// The Linux UA is the same browser as the Windows one; only the OS token moves.
// If they ever drift apart in anything else, a cookie earned on one and replayed
// under the other stops matching.
func TestLinuxUserAgentDiffersOnlyInTheOSToken(t *testing.T) {
	if PlatformFromUserAgent(Chrome151UserAgent) != "Windows" {
		t.Error("the pinned Windows UA does not read as Windows")
	}
	if PlatformFromUserAgent(Chrome151LinuxUserAgent) != "Linux" {
		t.Error("the pinned Linux UA does not read as Linux")
	}
	if majorOf(t, Chrome151UserAgent) != majorOf(t, Chrome151LinuxUserAgent) {
		t.Errorf("the two pinned UAs claim different Chrome versions:\n  %s\n  %s",
			Chrome151UserAgent, Chrome151LinuxUserAgent)
	}
}

func majorOf(t *testing.T, ua string) string {
	t.Helper()
	const token = "Chrome/"
	i := len(token)
	for j := 0; j+len(token) <= len(ua); j++ {
		if ua[j:j+len(token)] == token {
			rest := ua[j+i:]
			for k := 0; k < len(rest); k++ {
				if rest[k] == '.' {
					return rest[:k]
				}
			}
		}
	}
	t.Fatalf("no Chrome version in %q", ua)
	return ""
}

func TestChromeUserAgentFor(t *testing.T) {
	if ua, ok := ChromeUserAgentFor("Linux"); !ok || ua != Chrome151LinuxUserAgent {
		t.Errorf("ChromeUserAgentFor(Linux) = %q, %v", ua, ok)
	}
	if ua, ok := ChromeUserAgentFor("Windows"); !ok || ua != Chrome151UserAgent {
		t.Errorf("ChromeUserAgentFor(Windows) = %q, %v", ua, ok)
	}
	// No pinned capture exists for these, and inventing one would produce a
	// fingerprint nothing has verified.
	if _, ok := ChromeUserAgentFor("macOS"); ok {
		t.Error("ChromeUserAgentFor(macOS) claimed a UA this package does not pin")
	}
	if _, ok := ChromeUserAgentFor(""); ok {
		t.Error("ChromeUserAgentFor(\"\") claimed a UA")
	}
}
