package gofire

import (
	"net/http"
)

// Firefox 148 User-Agent (Windows 10 x64)
const Firefox148UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"

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

	setIfEmpty(h, "User-Agent", Firefox148UserAgent)
	setIfEmpty(h, "Accept", accept)
	setIfEmpty(h, "Accept-Language", lang)
	setIfEmpty(h, "Accept-Encoding", "gzip, deflate, br, zstd")
	setIfEmpty(h, "Upgrade-Insecure-Requests", "1")
	setIfEmpty(h, "Sec-Fetch-Dest", "document")
	setIfEmpty(h, "Sec-Fetch-Mode", "navigate")
	setIfEmpty(h, "Sec-Fetch-Site", secFetchSiteFor(h))
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
// based on whether a Referer is present. Real browsers send "none" for
// address-bar/bookmark navigations (no referrer) and "same-origin" once a
// referrer chain exists. Hardcoding "same-origin" on a referer-less first
// request is a known bot signal that Cloudflare scores against you.
func secFetchSiteFor(h http.Header) string {
	if h.Get("Referer") == "" {
		return "none"
	}
	return "same-origin"
}

// applyBrowserHeaders applies headers based on the browser profile.
func applyBrowserHeaders(req *http.Request, browser BrowserProfile, accept, lang string) {
	switch browser {
	case Chrome146:
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

// Chrome 146 User-Agent (Windows 10 x64)
const Chrome146UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

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
	setIfEmpty(h, "Sec-Ch-Ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`)
	setIfEmpty(h, "Sec-Ch-Ua-Mobile", "?0")
	setIfEmpty(h, "Sec-Ch-Ua-Platform", `"Windows"`)
	setIfEmpty(h, "Upgrade-Insecure-Requests", "1")
	setIfEmpty(h, "User-Agent", Chrome146UserAgent)
	setIfEmpty(h, "Accept", accept)
	setIfEmpty(h, "Sec-Fetch-Site", secFetchSiteFor(h))
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

// Safari iOS 18 User-Agent (iPhone)
const SafariIOS18UserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1"

// safariIOS18HeaderOrder defines the exact header order Safari iOS 18 sends.
// From tls.peet.ws capture:
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
//   - upgrade-insecure-requests between user-agent and accept
//   - accept-encoding LAST (Firefox/Chrome put it earlier)
//   - No sec-ch-ua (Safari doesn't support Client Hints)
//   - No TE: trailers (Firefox-only)
//   - No sec-fetch-user
var safariIOS18HeaderOrder = []string{
	"Sec-Fetch-Dest",
	"User-Agent",
	"Upgrade-Insecure-Requests",
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
	setIfEmpty(h, "Upgrade-Insecure-Requests", "1")
	setIfEmpty(h, "Accept", accept)
	setIfEmpty(h, "Sec-Fetch-Site", secFetchSiteFor(h))
	setIfEmpty(h, "Sec-Fetch-Mode", "navigate")
	setIfEmpty(h, "Accept-Language", lang)
	setIfEmpty(h, "Priority", "u=0, i")
	setIfEmpty(h, "Accept-Encoding", "gzip, deflate, br")

	// NOTE: Safari does NOT send:
	// - TE: trailers (Firefox-only)
	// - Sec-Fetch-User (Chrome/Firefox send ?1)
	// - Sec-Ch-Ua headers (Chrome-only)
	// - zstd in Accept-Encoding (Safari only supports gzip, deflate, br)
}
