package gofire

import (
	"net/http"
)

// Firefox 148 User-Agent (Windows 10 x64)
const Firefox148UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"

// firefox148HeaderOrder defines the exact header order Firefox 148 sends.
// This order is critical for HTTP/2 Akamai fingerprint and header-order detection.
var firefox148HeaderOrder = []string{
	"Host",
	"User-Agent",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
	"Content-Type",
	"Content-Length",
	"Origin",
	"DNT",
	"Sec-GPC",
	"Connection",
	"Referer",
	"Cookie",
	"Upgrade-Insecure-Requests",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
	"Sec-Fetch-User",
	"Priority",
	"TE",
	"Pragma",
	"Cache-Control",
}

// applyFirefoxHeaders sets default Firefox 148 headers on the request.
// Only sets headers that are not already present, preserving user overrides.
func applyFirefoxHeaders(req *http.Request, accept, lang string) {
	h := req.Header
	if h == nil {
		h = make(http.Header, 14)
		req.Header = h
	}

	setIfEmpty(h, "User-Agent", Firefox148UserAgent)
	setIfEmpty(h, "Accept", accept)
	setIfEmpty(h, "Accept-Language", lang)
	setIfEmpty(h, "Accept-Encoding", "gzip, deflate, br, zstd")
	setIfEmpty(h, "DNT", "1")
	setIfEmpty(h, "Sec-GPC", "1")
	setIfEmpty(h, "Upgrade-Insecure-Requests", "1")
	setIfEmpty(h, "Sec-Fetch-Dest", "document")
	setIfEmpty(h, "Sec-Fetch-Mode", "navigate")
	setIfEmpty(h, "Sec-Fetch-Site", "none")
	setIfEmpty(h, "Sec-Fetch-User", "?1")
	setIfEmpty(h, "Priority", "u=0, i")
	setIfEmpty(h, "TE", "trailers")

	if req.URL != nil && req.URL.Scheme == "https" {
		setIfEmpty(h, "Connection", "keep-alive")
	}
}

func setIfEmpty(h http.Header, key, value string) {
	if h.Get(key) == "" {
		h.Set(key, value)
	}
}

// OrderHeaders returns headers sorted in Firefox 148 order.
func OrderHeaders(h http.Header) []HeaderKV {
	result := make([]HeaderKV, 0, len(h))

	// Add headers in Firefox order first
	for _, key := range firefox148HeaderOrder {
		if values, ok := h[key]; ok {
			for _, v := range values {
				result = append(result, HeaderKV{Key: key, Value: v})
			}
		}
	}

	// Add any remaining headers not in the predefined order
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
