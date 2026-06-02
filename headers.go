package gofire

import (
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// SafariIOS18UserAgent is the User-Agent string sent by Safari on iPhone with iOS 18.7.5.
const SafariIOS18UserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Mobile/15E148 Safari/604.1"

// safariIOS18HeaderOrder defines the exact header order Safari iOS 18 sends.
// Verified against a real Safari iOS 18.7.5 capture from tls.peet.ws:
//
//	:method, :scheme, :authority, :path (pseudo-headers)
//	sec-fetch-dest
//	user-agent
//	accept
//	[referer]
//	sec-fetch-site
//	sec-fetch-mode
//	accept-language
//	priority
//	accept-encoding
//
// NOTE: Safari header order is unique:
//   - sec-fetch-dest BEFORE user-agent (Chrome/Firefox put it after)
//   - accept-encoding LAST (Firefox/Chrome put it earlier)
//   - No upgrade-insecure-requests (Apple stopped sending it on top-level
//     navigations; Chrome/Firefox still send it)
//   - No sec-ch-ua (Safari doesn't support Client Hints)
//   - No TE: trailers (Firefox-only)
//   - No sec-fetch-user
var safariIOS18HeaderOrder = []string{
	"Sec-Fetch-Dest",
	"User-Agent",
	"Accept",
	"Content-Type",
	"Content-Length",
	"Origin",
	"Referer",
	"Cookie",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Accept-Language",
	"Priority",
	"Accept-Encoding",
}

// applySafariHeaders sets exact Safari iOS 18 default headers on the request.
// Only sets headers that are not already present, preserving user overrides.
func applySafariHeaders(req *http.Request, accept, lang string) {
	h := req.Header
	if h == nil {
		h = make(http.Header, 10)
		req.Header = h
	}

	setIfEmpty(h, "Sec-Fetch-Dest", "document")
	setIfEmpty(h, "User-Agent", SafariIOS18UserAgent)
	setIfEmpty(h, "Accept", accept)
	setIfEmpty(h, "Sec-Fetch-Site", secFetchSiteFor(req))
	setIfEmpty(h, "Sec-Fetch-Mode", "navigate")
	setIfEmpty(h, "Accept-Language", lang)
	setIfEmpty(h, "Priority", "u=0, i")
	setIfEmpty(h, "Accept-Encoding", "gzip, deflate, br")

	// NOTE: Safari iOS 18 does NOT send:
	// - Upgrade-Insecure-Requests (Apple stopped sending on top-level navs)
	// - TE: trailers (Firefox-only)
	// - Sec-Fetch-User (Chrome/Firefox send ?1)
	// - Sec-Ch-Ua headers (Chrome-only)
	// - zstd in Accept-Encoding (Safari only supports gzip, deflate, br)
}

// applyBrowserHeaders applies headers for the configured browser profile.
// Only Safari iOS 18 is supported.
func applyBrowserHeaders(req *http.Request, _ BrowserProfile, accept, lang string) {
	applySafariHeaders(req, accept, lang)
}

func setIfEmpty(h http.Header, key, value string) {
	if h.Get(key) == "" {
		h.Set(key, value)
	}
}

// secFetchSiteFor returns the correct Sec-Fetch-Site value for a navigation
// based on the relationship between the Referer and the request URL.
//
//   - none:        no referrer (address bar, bookmark, fresh tab)
//   - same-origin: scheme + host + port match
//   - same-site:   same registrable domain (eTLD+1), different host/port/scheme
//   - cross-site:  different registrable domain
//
// Hardcoding "same-origin" whenever a Referer exists is a fingerprint mismatch
// that Cloudflare/Akamai score against you - if the referrer is google.com but
// Sec-Fetch-Site says same-origin, the request is obviously synthetic. The
// referrer host has to drive the annotation.
func secFetchSiteFor(req *http.Request) string {
	if req == nil {
		return "none"
	}
	referer := req.Header.Get("Referer")
	if referer == "" {
		return "none"
	}
	refURL, err := url.Parse(referer)
	if err != nil || refURL.Host == "" || req.URL == nil || req.URL.Host == "" {
		return "none"
	}

	reqHost := strings.ToLower(req.URL.Hostname())
	refHost := strings.ToLower(refURL.Hostname())
	reqPort := req.URL.Port()
	refPort := refURL.Port()
	if reqPort == "" {
		reqPort = defaultPortForScheme(req.URL.Scheme)
	}
	if refPort == "" {
		refPort = defaultPortForScheme(refURL.Scheme)
	}

	if req.URL.Scheme == refURL.Scheme && reqHost == refHost && reqPort == refPort {
		return "same-origin"
	}
	if sameRegistrableDomain(reqHost, refHost) {
		return "same-site"
	}
	return "cross-site"
}

func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "https", "wss":
		return "443"
	case "http", "ws":
		return "80"
	}
	return ""
}

func sameRegistrableDomain(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	aSite, err := publicsuffix.EffectiveTLDPlusOne(a)
	if err != nil {
		return false
	}
	bSite, err := publicsuffix.EffectiveTLDPlusOne(b)
	if err != nil {
		return false
	}
	return aSite == bSite
}

// OrderHeaders returns headers sorted in Safari iOS 18 order.
// Headers not in the canonical order are appended at the end.
func OrderHeaders(h http.Header) []HeaderKV {
	result := make([]HeaderKV, 0, len(h))

	for _, key := range safariIOS18HeaderOrder {
		if values, ok := h[key]; ok {
			for _, v := range values {
				result = append(result, HeaderKV{Key: key, Value: v})
			}
		}
	}

	seen := make(map[string]bool, len(safariIOS18HeaderOrder))
	for _, k := range safariIOS18HeaderOrder {
		seen[k] = true
	}
	for key, values := range h {
		if !seen[key] {
			for _, v := range values {
				result = append(result, HeaderKV{Key: key, Value: v})
			}
		}
	}

	return result
}

// HeaderKV is a key-value pair for ordered headers.
type HeaderKV struct {
	Key   string
	Value string
}
