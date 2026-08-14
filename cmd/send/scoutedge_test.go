package main

import (
	"net/http"
	"strings"
	"testing"
)

func header(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Add(pairs[i], pairs[i+1])
	}
	return h
}

func TestIdentifyEdge(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		vendor  string
		mention string // something the reason has to name, so it is evidence and not a claim
	}{
		{
			name:   "cloudflare",
			header: header("cf-ray", "8a1b2c3d4e5f", "Server", "cloudflare"),
			vendor: "Cloudflare", mention: "cf-ray",
		},
		{
			name:   "datadome",
			header: header("x-datadome", "protected", "Server", "nginx"),
			vendor: "DataDome", mention: "x-datadome",
		},
		{
			// Cloudflare in front of CloudFront in front of an origin is an
			// ordinary arrangement, and the one nearest the client is the one
			// that would be doing the challenging.
			name: "layered, the nearest wins on evidence",
			header: header("cf-ray", "8a1b", "cf-cache-status", "DYNAMIC",
				"Server", "cloudflare", "x-amz-cf-id", "abc"),
			vendor: "Cloudflare", mention: "cf-cache-status",
		},
		{
			name:   "a bare origin announces nothing",
			header: header("Server", "nginx/1.24.0", "Content-Type", "text/html"),
			vendor: "",
		},
		{
			// x-served-by is not Fastly's alone; the cache- value is what makes
			// it one. Without it the header proves nothing.
			name:   "x-served-by without the cache marker is not evidence",
			header: header("x-served-by", "web-07"),
			vendor: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vendor, why := identifyEdge(tc.header)
			if vendor != tc.vendor {
				t.Errorf("identifyEdge = %q, want %q (reason %q)", vendor, tc.vendor, why)
			}
			if tc.mention != "" && !strings.Contains(why, tc.mention) {
				t.Errorf("reason %q does not name the header it read (%s)", why, tc.mention)
			}
		})
	}
}

func TestIdentifyChallenge(t *testing.T) {
	tests := []struct {
		name   string
		status int
		header http.Header
		body   string
		want   challengeKind
	}{
		{
			name: "cloudflare labels its own", status: 403,
			header: header("cf-mitigated", "challenge", "cf-ray", "8a1b"),
			want:   challengeCloudflare,
		},
		{
			name: "the challenge platform's script", status: 503,
			header: header("Server", "cloudflare"),
			body:   `<html><body><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1"></script></body></html>`,
			want:   challengeCloudflare,
		},
		{
			name: "the bootstrap object", status: 403, header: http.Header{},
			body: `<script>window._cf_chl_opt={cvId:"3"};</script>`,
			want: challengeCloudflare,
		},
		{
			name: "turnstile", status: 403, header: http.Header{},
			body: `<iframe src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform/"></iframe>`,
			want: challengeCloudflare,
		},
		{
			// The regression solver/challenge.js was written for: the
			// interstitial follows Accept-Language, so an English-only check
			// reports "no challenge" on the exits that most need one.
			name: "a localised interstitial with no markers left", status: 403,
			header: http.Header{},
			body:   `<html><head><title>Bir dakika…</title></head><body></body></html>`,
			want:   challengeCloudflare,
		},
		{
			name: "datadome is not ours to solve", status: 403, header: http.Header{},
			body: `<html><body><script src="https://geo.captcha-delivery.com/captcha/"></script></body></html>`,
			want: challengeVendor,
		},
		{
			name: "akamai scores by cookie", status: 403,
			header: header("Set-Cookie", "_abck=0~-1~-1; Path=/", "Server", "AkamaiGHost"),
			want:   challengeVendor,
		},
		{
			name: "a plain refusal has nothing to work through", status: 403,
			header: header("Server", "nginx"), body: "<html><body>Forbidden</body></html>",
			want: challengeBlocked,
		},
		{
			name: "already throttled", status: 429, header: header("Retry-After", "60"),
			want: challengeBlocked,
		},
		{
			name: "an ordinary page", status: 200, header: header("Server", "cloudflare", "cf-ray", "8a1b"),
			body: `<html><head><title>Home</title></head><body>hello</body></html>`,
			want: challengeNone,
		},
		{
			// A cookie a vendor sets on the way past is not a wall. Only a
			// refusal makes it one, or every Akamai-fronted site reads as blocked.
			name: "a bot-manager cookie on a 200 is not a challenge", status: 200,
			header: header("Set-Cookie", "_abck=0~-1~-1; Path=/"),
			body:   "<html><body>ok</body></html>",
			want:   challengeNone,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, why := identifyChallenge(tc.status, tc.header, []byte(tc.body))
			if got != tc.want {
				t.Fatalf("identifyChallenge = %v (%q), want %v", got, why, tc.want)
			}
			if got != challengeNone && why == "" {
				t.Error("a challenge was reported with no reason beside it")
			}
		})
	}
}

func TestDocumentTitle(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"plain", "<html><head><title>Home</title></head></html>", "Home"},
		{"uppercase", "<HTML><HEAD><TITLE>Home</TITLE></HEAD>", "Home"},
		{"with attributes", `<title data-x="1">Just a moment...</title>`, "Just a moment..."},
		{"padded", "<title>\n  Home \n</title>", "Home"},
		{"none", "<html><body>hi</body></html>", ""},
		{"unclosed", "<html><head><title>Home", ""},
		{"not html at all", `{"error":"forbidden"}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := documentTitle([]byte(tc.body)); got != tc.want {
				t.Errorf("documentTitle = %q, want %q", got, tc.want)
			}
		})
	}
}

// The title list has to stay in step with solver/challenge.js, and the entries
// that matter are the ones nobody would write from memory: a solve routed
// through a non-English exit sees the interstitial in that exit's language.
func TestChallengeTitlesAreLocalised(t *testing.T) {
	for _, title := range []string{
		"Just a moment...", "Bir dakika…", "Un momento…", "Einen Moment…",
		"Attention Required! | Cloudflare", "しばらくお待ちください",
	} {
		if !isChallengeTitle(title) {
			t.Errorf("isChallengeTitle(%q) = false — an interstitial in this language would read as no challenge at all", title)
		}
	}
	for _, title := range []string{"Home", "Sign in", "Products — Example"} {
		if isChallengeTitle(title) {
			t.Errorf("isChallengeTitle(%q) = true", title)
		}
	}
}
