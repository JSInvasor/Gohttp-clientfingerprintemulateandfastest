package main

import (
	"fmt"
	"net/http"
	"strings"
)

// Who is in front of this target, and did they stop us.
//
// Both are read out of one response, and both are read from structure rather
// than from prose: headers the edge stamps on everything it serves, and the
// markup its interstitial builds. Prose moves — Cloudflare localises the
// challenge page and rewords it between releases — so a check that reads the
// title is a check that quietly stops matching, and stops matching in exactly
// the case it was written for. The title is still consulted, last, as a second
// opinion on an interstitial whose markup changed but whose wording did not.
// That is the order solver/challenge.js uses, for the same reason.

// edgeSignature is a header that names its vendor.
type edgeSignature struct {
	vendor string
	header string
	value  string // when set, the header's value must contain this
}

// The headers here are the ones an edge adds to every response it touches — a
// request id, a cache status, a mitigation label — rather than anything an
// origin behind it might also send.
var edgeSignatures = []edgeSignature{
	{"Cloudflare", "cf-ray", ""},
	{"Cloudflare", "cf-cache-status", ""},
	{"Cloudflare", "cf-mitigated", ""},
	{"DataDome", "x-datadome", ""},
	{"DataDome", "x-dd-b", ""},
	{"Imperva", "x-iinfo", ""},
	{"Imperva", "x-cdn", "incapsula"},
	{"PerimeterX", "x-px", ""},
	{"Akamai", "x-akamai-transformed", ""},
	{"Akamai", "akamai-grn", ""},
	{"CloudFront", "x-amz-cf-id", ""},
	{"Fastly", "x-served-by", "cache-"},
	{"Fastly", "fastly-io-info", ""},
	{"Sucuri", "x-sucuri-id", ""},
	{"Vercel", "x-vercel-id", ""},
	{"Fly.io", "fly-request-id", ""},
	{"Netlify", "x-nf-request-id", ""},
}

// Server is worth reading too, but only for the values that are a vendor's name
// rather than a web server's — "nginx" says nothing about who is in front.
var edgeServers = []struct{ vendor, match string }{
	{"Cloudflare", "cloudflare"},
	{"Akamai", "akamaighost"},
	{"CloudFront", "cloudfront"},
	{"Imperva", "incapsula"},
	{"Sucuri", "sucuri"},
	{"Vercel", "vercel"},
	{"Netlify", "netlify"},
}

// identifyEdge names the CDN or WAF in front of a target, with what gave it
// away, or returns empty strings when nothing announces itself.
//
// The vendor with the most evidence wins rather than the first one matched,
// because a response can carry several vendors' headers at once — Cloudflare in
// front of CloudFront in front of an origin is an ordinary arrangement — and the
// one that stamped the most of them is the one nearest the client, which is the
// one that would be doing the challenging.
func identifyEdge(h http.Header) (vendor, why string) {
	evidence := map[string][]string{}
	var order []string
	note := func(v, what string) {
		if _, seen := evidence[v]; !seen {
			order = append(order, v)
		}
		evidence[v] = append(evidence[v], what)
	}

	for _, sig := range edgeSignatures {
		got := h.Get(sig.header)
		if got == "" {
			continue
		}
		if sig.value != "" && !strings.Contains(strings.ToLower(got), sig.value) {
			continue
		}
		note(sig.vendor, sig.header)
	}
	if server := h.Get("Server"); server != "" {
		low := strings.ToLower(server)
		for _, sv := range edgeServers {
			if strings.Contains(low, sv.match) {
				note(sv.vendor, "server: "+server)
				break
			}
		}
	}

	if len(order) == 0 {
		return "", ""
	}
	best := order[0]
	for _, v := range order[1:] {
		if len(evidence[v]) > len(evidence[best]) {
			best = v
		}
	}
	return best, strings.Join(evidence[best], ", ")
}

// challengeKind is what stood between the probe and the page.
//
// The distinction is the whole value of asking: -solve earns a cf_clearance and
// nothing else, so calling another vendor's interstitial "a challenge" would
// send someone to spend two minutes of browser on a wall it cannot climb — and
// calling a plain refusal a challenge would do the same with nothing to climb at
// all.
type challengeKind int

const (
	challengeNone       challengeKind = iota
	challengeCloudflare               // an interstitial -solve has an answer for
	challengeVendor                   // someone else's interstitial: real, and not solvable here
	challengeBlocked                  // refused outright, with nothing to work through
)

// cloudflareMarkers are the challenge platform's own structure. They are the
// raw-HTML form of the selectors solver/challenge.js looks for in the DOM,
// because a probe has bytes where the solver has a document.
//
// interstitialOnly separates the markers that only ever appear on a challenge
// page from the ones an ordinary page can carry too. The solver can use the
// looser set because it is looking at a page it already knows was withheld — it
// is asking "am I still on the interstitial". A scout is asking the prior
// question, "was anything withheld at all", and there the loose markers are the
// difference between reading a site correctly and sending someone to spend two
// minutes of browser on a page that was never held back.
var cloudflareMarkers = []struct {
	needle, why      string
	interstitialOnly bool
}{
	{needle: "_cf_chl_opt", why: "the page defines _cf_chl_opt, the challenge bootstrap's own object", interstitialOnly: true},
	{needle: "cf-challenge-running", why: "the page carries Cloudflare's challenge-running element", interstitialOnly: true},
	{needle: "id=\"challenge-form\"", why: "the page carries Cloudflare's challenge form", interstitialOnly: true},
	{needle: "__cf_chl_", why: "the page carries a __cf_chl_ parameter", interstitialOnly: true},
	// Both of these are on ordinary pages as often as on interstitials:
	// challenge-platform is the invisible bot-detection script, and the
	// Turnstile host is a widget anyone can put on a form.
	{needle: "/cdn-cgi/challenge-platform/", why: "the page loads /cdn-cgi/challenge-platform/"},
	{needle: "challenges.cloudflare.com", why: "the page embeds a Turnstile widget"},
}

// vendorMarkers are the same idea for the interstitials this tool cannot solve.
// Naming them is not a failure to handle them: an unrecognised wall reads as a
// broken target, and someone will spend an afternoon on their fingerprint before
// finding out it was never the fingerprint.
var vendorMarkers = []struct{ needle, vendor string }{
	{"captcha-delivery.com", "DataDome"},
	{"datadome.co", "DataDome"},
	{"px-captcha", "PerimeterX"},
	{"/_Incapsula_Resource", "Imperva"},
	{"Incapsula incident ID", "Imperva"},
	{"Request unsuccessful. Incapsula", "Imperva"},
}

// vendorCookies are set on the way past rather than only on the wall, so they
// only mean something alongside a refusal.
var vendorCookies = []struct{ name, vendor string }{
	{"_abck", "Akamai Bot Manager"},
	{"ak_bmsc", "Akamai Bot Manager"},
	{"datadome", "DataDome"},
	{"_px", "PerimeterX"},
	{"reese84", "Incapsula/Kasada"},
}

// identifyChallenge reports what stopped the probe, and why it says so.
//
// The bar for saying "challenge" is deliberately high, because the cost of a
// false positive lands entirely on the user: -solve launches a real Chromium,
// spends up to 150s on it, and is recommended on the strength of this answer. A
// site that served the page and merely has Cloudflare's machinery on it must
// come back as challengeNone — nothing needs solving to fetch what already
// arrived.
func identifyChallenge(status int, h http.Header, body []byte) (challengeKind, string) {
	// Cloudflare labels its own mitigations, and has since 2023. When the header
	// is there, nothing else needs consulting.
	if v := h.Get("cf-mitigated"); v != "" {
		// The label names the mitigation, and only one of them is a puzzle.
		// "challenge" is the interstitial; anything else is Cloudflare saying it
		// decided, and a solver has nothing to offer a decision.
		if strings.EqualFold(strings.TrimSpace(v), "challenge") {
			return challengeCloudflare, "cf-mitigated: challenge"
		}
		return challengeBlocked, fmt.Sprintf("cf-mitigated: %s — Cloudflare mitigated this without "+
			"presenting a challenge, so there is nothing for a browser to work through", v)
	}

	text := string(body)
	served := status >= 200 && status < 300

	loose := false // a Cloudflare marker that an ordinary page may also carry
	for _, m := range cloudflareMarkers {
		if !strings.Contains(text, m.needle) {
			continue
		}
		// On a 2xx the page arrived. Cloudflare's script is on an enormous number
		// of ordinary pages — /cdn-cgi/challenge-platform/ is loaded by its
		// invisible bot detection, and challenges.cloudflare.com is the Turnstile
		// widget host, which sits on login and signup forms of sites that
		// challenge nobody. Treating either as an interstitial would send a
		// solver at a page that was never withheld.
		//
		// _cf_chl_opt and its siblings are the exception: they are the challenge
		// bootstrap's own structure, defined only by the interstitial, so they
		// still count on a 2xx — the JS challenge has been served with one.
		if served && !m.interstitialOnly {
			loose = true
			continue
		}
		return challengeCloudflare, m.why
	}
	for _, m := range vendorMarkers {
		if strings.Contains(text, m.needle) && !served {
			return challengeVendor, fmt.Sprintf("a %s interstitial (%q is in the page)", m.vendor, m.needle)
		}
	}

	refused := status == http.StatusForbidden ||
		status == http.StatusTooManyRequests ||
		status == http.StatusServiceUnavailable

	if refused {
		for _, c := range vendorCookies {
			if hasSetCookie(h, c.name) {
				return challengeVendor, fmt.Sprintf("%d, and the response sets %s — %s is scoring this address",
					status, c.name, c.vendor)
			}
		}
	}

	// The wording, last: an interstitial whose markup changed but whose title did
	// not is still an interstitial.
	//
	// On a 2xx it needs corroboration. A title is prose, and prose belongs to
	// whoever wrote the page — "Just a moment…" is a plausible thing for a real
	// page to be called, and a site that served one is not withholding it. The
	// loose Cloudflare markers are not enough on their own to call a challenge,
	// but they are enough to stop a matching title from being a coincidence.
	if title := documentTitle(body); title != "" && isChallengeTitle(title) && (!served || loose) {
		return challengeCloudflare, fmt.Sprintf("the page is titled %q", title)
	}

	switch status {
	case http.StatusForbidden:
		return challengeBlocked, "403 with no interstitial in it — a refusal rather than something to work through"
	case http.StatusUnauthorized:
		return challengeBlocked, "401: the target wants credentials, which is a different problem from a fingerprint"
	case http.StatusTooManyRequests:
		return challengeBlocked, "429 to a single request — this address is already being throttled"
	case http.StatusServiceUnavailable:
		return challengeBlocked, "503 with no interstitial in it — the edge or the origin is refusing"
	}
	return challengeNone, ""
}

// carriesTurnstile reports whether a page that was served embeds a Turnstile
// widget.
//
// Deliberately separate from identifyChallenge, which answers "was anything
// withheld". This answers a different question — "is there a puzzle on the page
// I was given" — and the two must not be conflated: a widget on a login form
// blocks the form, not the document, and nothing about fetching the document
// needs solving. Worth reporting only so the report can say why -solve is
// absent from a page that visibly has Cloudflare's puzzle on it.
func carriesTurnstile(body []byte) bool {
	text := string(body)
	return strings.Contains(text, "challenges.cloudflare.com") ||
		strings.Contains(text, "cf-turnstile")
}

// hasSetCookie reports whether the response sets a cookie by this name.
func hasSetCookie(h http.Header, name string) bool {
	for _, c := range h.Values("Set-Cookie") {
		if attr, _, _ := strings.Cut(c, ";"); strings.HasPrefix(strings.TrimSpace(attr), name+"=") {
			return true
		}
	}
	return false
}

// challengeTitles mirrors CHALLENGE_TITLE_RE in solver/challenge.js. The
// non-English entries are the point rather than thoroughness: the interstitial
// follows Accept-Language, so an exit that asks for anything but English gets a
// title an English-only list would miss — and missing it looks exactly like a
// site with no challenge at all.
var challengeTitles = []string{
	"just a moment", "attention required", "checking your browser",
	"verify you are human", "un momento", "bir dakika", "einen moment",
	"un instant", "um momento", "один момент", "请稍候", "しばらく",
}

func isChallengeTitle(title string) bool {
	low := strings.ToLower(title)
	for _, t := range challengeTitles {
		if strings.Contains(low, t) {
			return true
		}
	}
	return false
}

// documentTitle pulls the <title> out of a document, or returns "".
//
// Indexing rather than parsing, and bounded: this runs on a response that may
// not be HTML at all, and its answer is only ever a second opinion.
func documentTitle(body []byte) string {
	const scan = 64 << 10 // the title lives in the head; further is wasted work
	text := string(body)
	if len(text) > scan {
		text = text[:scan]
	}
	low := strings.ToLower(text)

	open := strings.Index(low, "<title")
	if open < 0 {
		return ""
	}
	gt := strings.IndexByte(low[open:], '>')
	if gt < 0 {
		return ""
	}
	start := open + gt + 1
	end := strings.Index(low[start:], "</title>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(text[start : start+end])
}
