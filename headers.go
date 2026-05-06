package gofire

import (
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Firefox150UserAgent is the User-Agent string sent by Firefox 150 on Windows 10 x64.
const Firefox150UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0"

// Firefox148UserAgent is kept for backward compatibility. It now resolves to the
// Firefox 150 User-Agent because the underlying TLS/H2 fingerprint matches that
// release.
const Firefox148UserAgent = Firefox150UserAgent

// firefox148HeaderOrder defines the exact header order Firefox 148 sends
// in an HTTP/2 HEADERS frame (verified from tls.peet.ws capture).
//
// Real Firefox 148 header order:
//
//	:method, :path, :authority, :scheme (pseudo-headers)
//	user-agent
//	accept
//	accept-language
//	accept-encoding
//	[content-type]    (only on POST/PUT)
//	[content-length]  (only on POST/PUT)
//	[origin]          (only on POST/cross-origin)
//	[referer]         (only if referrer exists)
//	[cookie]          (only if cookies exist)
//	upgrade-insecure-requests
//	sec-fetch-dest
//	sec-fetch-mode
//	sec-fetch-site
//	sec-fetch-user
//	priority
//	te
//
// NOTE: Firefox 148 does NOT send DNT, Sec-GPC, Connection, Pragma, or Cache-Control headers.
var firefox148HeaderOrder = []string{
	"User-Agent",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
	"Content-Type",
	"Content-Length",
	"Origin",
	"Referer",
	"Cookie",
	"Upgrade-Insecure-Requests",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
	"Sec-Fetch-User",
	"Priority",
	"TE",
}

// applyFirefoxHeaders sets exact Firefox 148 default headers on the request.
// Only sets headers that are not already present, preserving user overrides.
//
// Verified against real Firefox 148 HTTP/2 HEADERS frame:
//
//	user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) ...
//	accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
//	accept-language: en-US,en;q=0.5
//	accept-encoding: gzip, deflate, br, zstd
//	upgrade-insecure-requests: 1
//	sec-fetch-dest: document
//	sec-fetch-mode: navigate
//	sec-fetch-site: none
//	sec-fetch-user: ?1
//	priority: u=0, i
//	te: trailers
func applyFirefoxHeaders(req *http.Request, accept, lang string) {
	h := req.Header
	if h == nil {
		h = make(http.Header, 12)
		req.Header = h
	}

	setIfEmpty(h, "User-Agent", Firefox150UserAgent)
	setIfEmpty(h, "Accept", accept)
	setIfEmpty(h, "Accept-Language", lang)
	setIfEmpty(h, "Accept-Encoding", "gzip, deflate, br, zstd")
	setIfEmpty(h, "Upgrade-Insecure-Requests", "1")
	setIfEmpty(h, "Sec-Fetch-Dest", "document")
	setIfEmpty(h, "Sec-Fetch-Mode", "navigate")
	setIfEmpty(h, "Sec-Fetch-Site", secFetchSiteFor(req))
	setIfEmpty(h, "Sec-Fetch-User", "?1")
	setIfEmpty(h, "Priority", "u=0, i")
	setIfEmpty(h, "TE", "trailers")

	// NOTE: Firefox 148 does NOT send these headers:
	// - DNT (removed in modern Firefox)
	// - Sec-GPC (not sent by default)
	// - Connection (not sent in HTTP/2)
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

// applyBrowserHeaders applies headers based on the browser profile.
func applyBrowserHeaders(req *http.Request, browser BrowserProfile, accept, lang string) {
	switch browser {
	case Chrome147:
		applyChromeHeaders(req, accept, lang)
	case SafariIOS18:
		applySafariHeaders(req, accept, lang)
	default:
		applyFirefoxHeaders(req, accept, lang)
	}
}

// OrderHeaders returns headers sorted in Firefox 148 order.
func OrderHeaders(h http.Header) []HeaderKV {
	result := make([]HeaderKV, 0, len(h))

	for _, key := range firefox148HeaderOrder {
		if values, ok := h[key]; ok {
			for _, v := range values {
				result = append(result, HeaderKV{Key: key, Value: v})
			}
		}
	}

	seen := make(map[string]bool, len(firefox148HeaderOrder))
	for _, k := range firefox148HeaderOrder {
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

// ========== Chrome 146 Headers ==========

// Chrome147UserAgent is the User-Agent string sent by Chrome 147 on Windows 10 x64.
const Chrome147UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"

// Chrome146UserAgent is kept for backward compatibility. It now resolves to
// the Chrome 147 User-Agent because the underlying TLS/H2 fingerprint matches
// that release (only UA + sec-ch-ua brand list moved).
const Chrome146UserAgent = Chrome147UserAgent

// Chrome147SecChUa is the sec-ch-ua header value for Chrome 147 on Windows.
// Chrome rotates the "Not A Brand" entry per major version using a deterministic
// algorithm, so this string is version-bound. Chrome 147 specifically emits:
//
//	"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"
//
// Note that the brand strings differ between versions (e.g. Chrome 146 used
// "Not-A.Brand";v="24"). UAM/bot scoring systems compare this header to the
// UA major version - drift here is a fake-Chrome signal.
const Chrome147SecChUa = `"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`

// chrome146HeaderOrder defines the exact header order Chrome 146 sends
// in an HTTP/2 HEADERS frame (verified from tls.peet.ws capture).
//
// Real Chrome 146 header order:
//
//	:method, :authority, :scheme, :path (pseudo-headers)
//	sec-ch-ua
//	sec-ch-ua-mobile
//	sec-ch-ua-platform
//	upgrade-insecure-requests
//	user-agent
//	accept
//	[content-type]    (only on POST/PUT)
//	[content-length]  (only on POST/PUT)
//	[origin]          (only on POST/cross-origin)
//	[referer]         (only if referrer exists)
//	[cookie]          (only if cookies exist)
//	sec-fetch-site
//	sec-fetch-mode
//	sec-fetch-user
//	sec-fetch-dest
//	accept-encoding
//	accept-language
//	priority
//
// NOTE: Chrome does NOT send TE, DNT, or Sec-GPC headers.
var chrome146HeaderOrder = []string{
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile",
	"Sec-Ch-Ua-Platform",
	"Upgrade-Insecure-Requests",
	"User-Agent",
	"Accept",
	"Content-Type",
	"Content-Length",
	"Origin",
	"Referer",
	"Cookie",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-User",
	"Sec-Fetch-Dest",
	"Accept-Encoding",
	"Accept-Language",
	"Priority",
}

// applyChromeHeaders sets exact Chrome 146 default headers on the request.
func applyChromeHeaders(req *http.Request, accept, lang string) {
	h := req.Header
	if h == nil {
		h = make(http.Header, 16)
		req.Header = h
	}

	// Chrome-specific Client Hints (not present in Firefox)
	setIfEmpty(h, "Sec-Ch-Ua", Chrome147SecChUa)
	setIfEmpty(h, "Sec-Ch-Ua-Mobile", "?0")
	setIfEmpty(h, "Sec-Ch-Ua-Platform", `"Windows"`)
	setIfEmpty(h, "Upgrade-Insecure-Requests", "1")
	setIfEmpty(h, "User-Agent", Chrome147UserAgent)
	setIfEmpty(h, "Accept", accept)
	setIfEmpty(h, "Sec-Fetch-Site", secFetchSiteFor(req))
	setIfEmpty(h, "Sec-Fetch-Mode", "navigate")
	setIfEmpty(h, "Sec-Fetch-User", "?1")
	setIfEmpty(h, "Sec-Fetch-Dest", "document")
	setIfEmpty(h, "Accept-Encoding", "gzip, deflate, br, zstd")
	setIfEmpty(h, "Accept-Language", lang)
	setIfEmpty(h, "Priority", "u=0, i")

	// NOTE: Chrome does NOT send these headers:
	// - TE (Firefox sends TE: trailers)
	// - DNT
	// - Sec-GPC
	// - Connection (not in HTTP/2)
}

// ========== Safari iOS 18 Headers ==========

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
