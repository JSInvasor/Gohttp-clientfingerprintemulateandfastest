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
	setIfEmpty(h, "Accept-Language", lang) // Firefox default: en-US,en;q=0.5
	setIfEmpty(h, "Accept-Encoding", "gzip, deflate, br, zstd")
	setIfEmpty(h, "Upgrade-Insecure-Requests", "1")
	setIfEmpty(h, "Sec-Fetch-Dest", "document")
	setIfEmpty(h, "Sec-Fetch-Mode", "navigate")
	setIfEmpty(h, "Sec-Fetch-Site", "none")
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
