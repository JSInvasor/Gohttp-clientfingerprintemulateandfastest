package gofire

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/publicsuffix"
)

// SafariIOS18UserAgent is the User-Agent string sent by Safari on iPhone.
//
// The "iPhone OS 18_7" token is NOT stale — Apple freezes the OS token in
// Safari's UA while the Version/ token tracks the real release. A real iPhone 13
// on iOS 26.5.2 reports exactly this: OS 18_7 paired with Version/26.5.2.
// Bumping the OS token to match the true OS version is a fake-Safari signal.
//
// (Other iOS apps do not freeze it — the Google app reports "iPhone OS 26_5_2"
// in its own UA — but this constant is Safari's.)
const SafariIOS18UserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5.2 Mobile/15E148 Safari/604.1"

// safariIOS18HeaderOrder defines the exact header order Safari iOS 18 sends.
// Verified against a real iPhone 13 / Safari 26.5.2 capture from tls.peet.ws:
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

// defaultNavigateAccept is the Accept header a browser sends for a top-level
// document load. It is also clientConfig's default, which is what lets
// fetch-mode requests distinguish "the caller left Accept alone" from "the
// caller chose this value deliberately".
const defaultNavigateAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

// fetchMode distinguishes a top-level navigation from a script-initiated
// fetch/XHR.
//
// Browsers annotate the two very differently, and stamping every request as a
// navigation is a bot signal on its own: no browser can produce a POST with a
// JSON body carrying Sec-Fetch-Mode: navigate, Sec-Fetch-Dest: document and
// Accept: text/html. That combination gives away a synthetic client no matter
// how exact the TLS and HTTP/2 layers underneath it are.
type fetchMode int

const (
	modeNavigate fetchMode = iota
	modeFetch
)

// fetchModeFor infers how a browser would have issued req.
//
// Navigations are GET/HEAD document loads plus HTML form submissions — a real
// form POST carries application/x-www-form-urlencoded or multipart/form-data
// and is annotated as a navigation. Everything else (JSON bodies, PUT, PATCH,
// DELETE, other content types) is script-initiated.
//
// Callers who disagree can set Sec-Fetch-Mode or Sec-Fetch-Dest themselves;
// nothing below overwrites a header that is already present.
func fetchModeFor(req *http.Request) fetchMode {
	switch req.Method {
	case "", http.MethodGet, http.MethodHead:
		return modeNavigate
	case http.MethodPost:
		ct := strings.ToLower(req.Header.Get("Content-Type"))
		if strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
			strings.HasPrefix(ct, "multipart/form-data") {
			return modeNavigate
		}
	}
	return modeFetch
}

// acceptFor returns the Accept header for the request mode. A caller-configured
// value always wins; only the built-in navigation default is swapped for the
// */* that fetch and XHR send.
func acceptFor(configured string, mode fetchMode) string {
	if mode == modeFetch && configured == defaultNavigateAccept {
		return "*/*"
	}
	return configured
}

// secFetchModeFor returns the Sec-Fetch-Mode value. A script-initiated request
// is "same-origin" when it stays within its own origin and "cors" otherwise.
func secFetchModeFor(req *http.Request, mode fetchMode) string {
	if mode == modeNavigate {
		return "navigate"
	}
	if secFetchSiteFor(req) == "same-origin" {
		return "same-origin"
	}
	return "cors"
}

// originFor returns the Origin header value, or "" when a browser would send
// none. Origin accompanies every request with an unsafe method and every
// cross-origin fetch, but not a same-origin GET and not a plain navigation.
//
// The value is the initiating document's origin. A configured Referer is the
// closest thing to one we have; without it the request is treated as coming
// from the target's own origin.
func originFor(req *http.Request, mode fetchMode) string {
	if req.URL == nil || req.URL.Host == "" {
		return ""
	}

	switch req.Method {
	case "", http.MethodGet, http.MethodHead:
		// Safe methods carry Origin only on a cross-origin fetch.
		if mode != modeFetch {
			return ""
		}
		if site := secFetchSiteFor(req); site == "same-origin" || site == "none" {
			return ""
		}
	}

	if ref := req.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host != "" && u.Scheme != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return req.URL.Scheme + "://" + req.URL.Host
}

// Pre-allocated single-value slices for the fast-path header set. http.Header
// is map[string][]string; h.Set always allocates a fresh []string{value}.
// For our fixed-value headers we can hand the map the same backing slice
// every call (the slice is never appended to or mutated). Saves 6-7 small
// allocations per request on the DoWithContext path.
var (
	safariSecFetchDest      = []string{"document"}
	safariSecFetchDestFetch = []string{"empty"}
	safariUserAgent         = []string{SafariIOS18UserAgent}
	safariPriority          = []string{"u=0, i"}
	safariPriorityFetch     = []string{"u=1, i"}
	safariAcceptEncode      = []string{"gzip, deflate, br, zstd"}
)

// applySafariHeaders sets exact Safari iOS 18 default headers on the request.
// Only sets headers that are not already present, preserving user overrides.
//
// Hot path: skips textproto.CanonicalMIMEHeaderKey by writing into the map
// directly with already-canonical keys. http.Header.Set canonicalizes its key
// on every call (allocates a temp byte slice), and for a fixed set of
// well-known headers that's ~150-200ns per request of pure waste.
func applySafariHeaders(req *http.Request, accept, lang string, mode fetchMode) {
	h := req.Header
	if h == nil {
		h = make(http.Header, 10)
		req.Header = h
	}

	if _, ok := h["Sec-Fetch-Dest"]; !ok {
		if mode == modeFetch {
			h["Sec-Fetch-Dest"] = safariSecFetchDestFetch
		} else {
			h["Sec-Fetch-Dest"] = safariSecFetchDest
		}
	}
	if _, ok := h["User-Agent"]; !ok {
		h["User-Agent"] = safariUserAgent
	}
	if _, ok := h["Accept"]; !ok {
		h["Accept"] = []string{acceptFor(accept, mode)}
	}
	if _, ok := h["Origin"]; !ok {
		if origin := originFor(req, mode); origin != "" {
			h["Origin"] = []string{origin}
		}
	}
	if _, ok := h["Sec-Fetch-Site"]; !ok {
		h["Sec-Fetch-Site"] = []string{secFetchSiteFor(req)}
	}
	if _, ok := h["Sec-Fetch-Mode"]; !ok {
		h["Sec-Fetch-Mode"] = []string{secFetchModeFor(req, mode)}
	}
	if _, ok := h["Accept-Language"]; !ok {
		h["Accept-Language"] = []string{lang}
	}
	if _, ok := h["Priority"]; !ok {
		// u=0 is reserved for the main document. The navigation value is
		// pinned to a real iOS 26.5.2 capture; the fetch value follows RFC
		// 9218's urgency semantics and has not been checked against a device.
		if mode == modeFetch {
			h["Priority"] = safariPriorityFetch
		} else {
			h["Priority"] = safariPriority
		}
	}
	if _, ok := h["Accept-Encoding"]; !ok {
		h["Accept-Encoding"] = safariAcceptEncode
	}

	// NOTE: Safari on iPhone does NOT send:
	// - Upgrade-Insecure-Requests (Apple stopped sending on top-level navs)
	// - TE: trailers (Firefox-only)
	// - Sec-Fetch-User (Chrome/Firefox send ?1)
	// - Sec-Ch-Ua headers (Chrome-only)
	//
	// It DOES send zstd in Accept-Encoding. An earlier revision omitted it on
	// the belief that Safari supports only gzip/deflate/br; the iOS 26.5.2
	// capture sends "gzip, deflate, br, zstd". response.go decodes zstd, so
	// advertising it is safe.
}

// ========== Chrome 150 Headers ==========

// Chrome150UserAgent is the User-Agent string sent by Chrome 150 on Windows 10 x64.
// Verified against a real Chrome 150 capture from tls.peet.ws.
const Chrome150UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"

// Chrome147UserAgent and Chrome146UserAgent are backward-compatible aliases.
// They resolve to the Chrome 150 User-Agent so callers pinning an older name
// still get a UA consistent with the TLS/H2 fingerprint this package emits.
const (
	Chrome147UserAgent = Chrome150UserAgent
	Chrome146UserAgent = Chrome150UserAgent
)

// Chrome150SecChUa is the sec-ch-ua header value for Chrome 150 on Windows.
//
// Both the greased brand string and the list order are version-bound, and both
// are checked by UAM/bot scoring against the UA's major version. Chrome 150
// emits the greased entry first:
//
//	"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"
//
// Earlier releases differ in both respects — the Chrome 147 profile had
// "Google Chrome" first with a "Not.A/Brand" spelling, and Chrome 146 used
// "Not-A.Brand";v="24" — so this string must move whenever the UA does.
const Chrome150SecChUa = `"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"`

// Chrome147SecChUa is a backward-compatible alias for Chrome150SecChUa.
const Chrome147SecChUa = Chrome150SecChUa

// chromeHeaderOrder defines the exact header order Chrome sends in an
// HTTP/2 HEADERS frame. Verified unchanged against real Chrome 150.
//
//	:method, :authority, :scheme, :path (pseudo-headers)
//	sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform
//	upgrade-insecure-requests
//	user-agent
//	accept
//	[content-type], [content-length], [origin], [referer], [cookie]
//	sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest
//	accept-encoding
//	accept-language
//	priority
//
// NOTE: Chrome does NOT send TE, DNT, or Sec-GPC headers.
var chromeHeaderOrder = []string{
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

// applyChromeHeaders sets exact Chrome 150 default headers on the request.
// Only sets headers that are not already present, preserving user overrides.
func applyChromeHeaders(req *http.Request, accept, lang string, mode fetchMode) {
	h := req.Header
	if h == nil {
		h = make(http.Header, 16)
		req.Header = h
	}

	// Chrome-specific Client Hints (Safari doesn't support them at all)
	setIfEmpty(h, "Sec-Ch-Ua", Chrome150SecChUa)
	setIfEmpty(h, "Sec-Ch-Ua-Mobile", "?0")
	setIfEmpty(h, "Sec-Ch-Ua-Platform", `"Windows"`)
	if mode == modeNavigate {
		// Both are navigation-only. Upgrade-Insecure-Requests advertises what
		// the document load will accept, and Sec-Fetch-User marks a
		// user-activated navigation; neither appears on a fetch or XHR.
		setIfEmpty(h, "Upgrade-Insecure-Requests", "1")
	}
	setIfEmpty(h, "User-Agent", Chrome150UserAgent)
	setIfEmpty(h, "Accept", acceptFor(accept, mode))
	if origin := originFor(req, mode); origin != "" {
		setIfEmpty(h, "Origin", origin)
	}
	setIfEmpty(h, "Sec-Fetch-Site", secFetchSiteFor(req))
	setIfEmpty(h, "Sec-Fetch-Mode", secFetchModeFor(req, mode))
	if mode == modeNavigate {
		setIfEmpty(h, "Sec-Fetch-User", "?1")
		setIfEmpty(h, "Sec-Fetch-Dest", "document")
		setIfEmpty(h, "Priority", "u=0, i")
	} else {
		setIfEmpty(h, "Sec-Fetch-Dest", "empty")
		// u=0 is reserved for the main document; Chrome sends u=1 for
		// script-initiated requests.
		setIfEmpty(h, "Priority", "u=1, i")
	}
	setIfEmpty(h, "Accept-Encoding", "gzip, deflate, br, zstd")
	setIfEmpty(h, "Accept-Language", lang)

	// NOTE: Chrome does NOT send TE, DNT, Sec-GPC, or Connection.
}

// applyBrowserHeaders applies headers for the configured browser profile,
// annotated for how a browser would have issued this request.
func applyBrowserHeaders(req *http.Request, browser BrowserProfile, accept, lang string) {
	mode := fetchModeFor(req)
	switch browser {
	case Chrome150:
		applyChromeHeaders(req, accept, lang, mode)
	default:
		applySafariHeaders(req, accept, lang, mode)
	}
}

func setIfEmpty(h http.Header, key, value string) {
	if h.Get(key) == "" {
		h.Set(key, value)
	}
}

// secFetchSiteCache memoizes secFetchSiteFor results keyed by the
// (referer origin, target origin) pair. At sustained high RPS the same pair
// repeats indefinitely, and the underlying url.Parse + publicsuffix lookup is
// non-trivial.
//
// Both halves of the key are origins, never full URLs. computeSecFetchSite
// reads nothing but the referer's scheme, host and port, so keying on the whole
// referer only made the key space unbounded: a crawler that sets a per-request
// Referer (the normal way to walk a site) minted one permanent entry per page
// visited and the map grew for the life of the process.
const maxSecFetchSiteCacheEntries = 4096

var (
	secFetchSiteCache     sync.Map // map[string]string
	secFetchSiteCacheSize atomic.Int64
)

// refererOrigin returns the scheme://host[:port] prefix of a URL without
// parsing it. Cutting at the first '/', '?' or '#' after the scheme separator
// leaves exactly what computeSecFetchSite looks at.
func refererOrigin(referer string) string {
	i := strings.Index(referer, "://")
	if i < 0 {
		return referer
	}
	if j := strings.IndexAny(referer[i+3:], "/?#"); j >= 0 {
		return referer[:i+3+j]
	}
	return referer
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
	if req.URL == nil || req.URL.Host == "" {
		return "none"
	}

	// Cache key pairs the target origin (scheme+host+port) with the referer
	// origin. Anything past the origin cannot change the answer.
	refOrigin := refererOrigin(referer)

	var keyBuf strings.Builder
	keyBuf.Grow(len(req.URL.Scheme) + len(req.URL.Host) + len(refOrigin) + 4)
	keyBuf.WriteString(req.URL.Scheme)
	keyBuf.WriteByte('|')
	keyBuf.WriteString(req.URL.Host)
	keyBuf.WriteByte('|')
	keyBuf.WriteString(refOrigin)
	key := keyBuf.String()

	if v, ok := secFetchSiteCache.Load(key); ok {
		return v.(string)
	}

	result := computeSecFetchSite(req, refOrigin)

	// Hard ceiling as belt and braces. Past it the answer is still correct,
	// just recomputed each time, which is far better than growing without
	// bound in a process that runs for days.
	if secFetchSiteCacheSize.Load() < maxSecFetchSiteCacheEntries {
		if _, loaded := secFetchSiteCache.LoadOrStore(key, result); !loaded {
			secFetchSiteCacheSize.Add(1)
		}
	}
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
