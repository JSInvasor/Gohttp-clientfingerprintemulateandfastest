package gofire

import (
	"net/http"
	"net/url"
	"strings"
	"sync"

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

// Pre-allocated single-value slices for the fast-path header set. http.Header
// is map[string][]string; h.Set always allocates a fresh []string{value}.
// For our fixed-value headers we can hand the map the same backing slice
// every call (the slice is never appended to or mutated). Saves 6-7 small
// allocations per request on the DoWithContext path.
var (
	safariSecFetchDest  = []string{"document"}
	safariUserAgent     = []string{SafariIOS18UserAgent}
	safariSecFetchMode  = []string{"navigate"}
	safariPriority      = []string{"u=0, i"}
	safariAcceptEncode  = []string{"gzip, deflate, br"}
)

// applySafariHeaders sets exact Safari iOS 18 default headers on the request.
// Only sets headers that are not already present, preserving user overrides.
//
// Hot path: skips textproto.CanonicalMIMEHeaderKey by writing into the map
// directly with already-canonical keys. http.Header.Set canonicalizes its key
// on every call (allocates a temp byte slice), and for a fixed set of
// well-known headers that's ~150-200ns per request of pure waste.
func applySafariHeaders(req *http.Request, accept, lang string) {
	h := req.Header
	if h == nil {
		h = make(http.Header, 10)
		req.Header = h
	}

	if _, ok := h["Sec-Fetch-Dest"]; !ok {
		h["Sec-Fetch-Dest"] = safariSecFetchDest
	}
	if _, ok := h["User-Agent"]; !ok {
		h["User-Agent"] = safariUserAgent
	}
	if _, ok := h["Accept"]; !ok {
		h["Accept"] = []string{accept}
	}
	if _, ok := h["Sec-Fetch-Site"]; !ok {
		h["Sec-Fetch-Site"] = []string{secFetchSiteFor(req)}
	}
	if _, ok := h["Sec-Fetch-Mode"]; !ok {
		h["Sec-Fetch-Mode"] = safariSecFetchMode
	}
	if _, ok := h["Accept-Language"]; !ok {
		h["Accept-Language"] = []string{lang}
	}
	if _, ok := h["Priority"]; !ok {
		h["Priority"] = safariPriority
	}
	if _, ok := h["Accept-Encoding"]; !ok {
		h["Accept-Encoding"] = safariAcceptEncode
	}

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

// secFetchSiteCache memoizes secFetchSiteFor results keyed by the
// (referer, scheme://host:port) pair. At sustained high RPS the same
// (referer, target) pair repeats indefinitely, and the underlying
// url.Parse + publicsuffix lookup is non-trivial.
//
// sync.Map is fine here: keys are bounded by the cardinality of distinct
// (referer, target-origin) pairs in a workload — typically tiny (1-10).
var secFetchSiteCache sync.Map // map[string]string

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
	if req.URL == nil || req.URL.Host == "" {
		return "none"
	}

	// Cache key uses target origin (scheme+host+port) + full referer URL.
	// We deliberately key on the full referer string (not just its origin) so
	// callers that pass a path-preserving referer still get the right answer
	// in the same-origin branch without paying for a re-parse.
	var keyBuf strings.Builder
	keyBuf.Grow(len(req.URL.Scheme) + len(req.URL.Host) + len(referer) + 4)
	keyBuf.WriteString(req.URL.Scheme)
	keyBuf.WriteByte('|')
	keyBuf.WriteString(req.URL.Host)
	keyBuf.WriteByte('|')
	keyBuf.WriteString(referer)
	key := keyBuf.String()

	if v, ok := secFetchSiteCache.Load(key); ok {
		return v.(string)
	}

	result := computeSecFetchSite(req, referer)
	secFetchSiteCache.Store(key, result)
	return result
}

func computeSecFetchSite(req *http.Request, referer string) string {
	refURL, err := url.Parse(referer)
	if err != nil || refURL.Host == "" {
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
