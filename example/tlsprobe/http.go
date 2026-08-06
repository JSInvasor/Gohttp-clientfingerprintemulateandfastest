package main

// The HTTP leg. A completed handshake only proves the target accepted the
// ClientHello; what it then says over that connection is a separate answer, and
// it is the one people actually came for. A challenge page, a block page and a
// working request all arrive as a finished TLS session — telling them apart
// means reading the response, so this sends one real request per profile
// through the package's own client and names what came back.

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// httpResult is one profile's response, or the error that replaced it.
type httpResult struct {
	err      error
	status   int
	proto    string
	took     time.Duration
	server   string
	location string
	cookies  []string
	bodyLen  int
	bodyType string
	title    string
	signal   edgeSignal
}

// edgeSignal is what the response says about who answered and why. vendor is
// empty when nothing recognisable answered; kind is empty when the response
// carries no sign of an edge decision at all.
type edgeSignal struct {
	vendor string // "Cloudflare", "DataDome", ...
	kind   string // challenge, block, rate limit, ...
	why    string // the evidence, quoted back
}

// httpRun requests target once per profile and reports each response.
func httpRun(reqURL, proxyURL string, profiles []string, pinned bool, insecure bool, timeout time.Duration) {
	fmt.Printf("http     GET %s  (redirects not followed)\n", reqURL)
	if pinned {
		// -target pinned an address that the client cannot be told to use, so
		// this leg resolves the name itself. Saying so beats printing a result
		// that quietly describes a different machine.
		fmt.Printf("%-8s note  the request resolves the name; it does not use the pinned address\n", "")
	}

	results := make(map[string]httpResult, len(profiles))
	for _, name := range profiles {
		res := httpProbe(reqURL, proxyURL, name, insecure, timeout)
		results[name] = res
		reportHTTP(name, res)
	}

	fmt.Println()
	httpVerdict(profiles, results)
}

// httpProbe sends the request with one emulated profile.
func httpProbe(reqURL, proxyURL, profile string, insecure bool, timeout time.Duration) httpResult {
	var browser gofire.BrowserProfile
	switch profile {
	case "chrome":
		browser = gofire.Chrome150
	case "safari":
		browser = gofire.SafariIOS18
	default:
		return httpResult{err: fmt.Errorf("no HTTP profile for %q", profile)}
	}

	opts := []gofire.Option{
		gofire.WithTimeout(timeout),
		// Following a redirect hides the response that caused it: a 302 into a
		// challenge path is the finding, not a step on the way to one.
		gofire.WithDisableRedirects(),
		gofire.WithMaxResponseBodySize(4 << 20),
	}
	if proxyURL != "" {
		opts = append(opts, gofire.WithProxy(proxyURL))
	}
	if insecure {
		opts = append(opts, gofire.WithInsecureSkipVerify())
	}

	client, err := gofire.Emulate(browser, opts...)
	if err != nil {
		return httpResult{err: err}
	}
	defer client.Close()

	start := time.Now()
	resp, err := client.Get(reqURL)
	if err != nil {
		return httpResult{err: err, took: time.Since(start)}
	}
	defer resp.Close()

	res := httpResult{
		status:   resp.StatusCode(),
		proto:    protoName(resp.Response),
		server:   resp.GetHeader("Server"),
		location: resp.GetHeader("Location"),
		bodyType: mediaType(resp.GetHeader("Content-Type")),
	}
	for _, c := range resp.GetCookies() {
		res.cookies = append(res.cookies, c.Name)
	}

	body, bodyErr := resp.Bytes()
	res.took = time.Since(start)
	if bodyErr != nil {
		// A body we could not read still leaves the headers worth classifying,
		// so this is reported beside the status rather than instead of it.
		res.title = "body not read: " + bodyErr.Error()
	}
	res.bodyLen = len(body)
	if res.title == "" {
		res.title = bodyGist(body)
	}
	res.signal = classify(res.status, resp.Headers(), body)
	return res
}

func reportHTTP(label string, res httpResult) {
	if res.err != nil {
		fmt.Printf("%-8s FAIL  %v\n", label, res.err)
		return
	}

	line := fmt.Sprintf("%-8s %d %s  %s  %v", label, res.status,
		http.StatusText(res.status), res.proto, res.took.Round(time.Millisecond))
	if res.signal.kind != "" {
		who := res.signal.vendor
		if who == "" {
			who = "unnamed edge"
		}
		line += fmt.Sprintf("  %s %s", who, res.signal.kind)
	}
	fmt.Println(line)

	if res.signal.why != "" {
		fmt.Printf("%-8s why   %s\n", "", res.signal.why)
	}
	if res.location != "" {
		fmt.Printf("%-8s to    %s\n", "", res.location)
	}
	if res.server != "" || len(res.cookies) > 0 {
		parts := make([]string, 0, 2)
		if res.server != "" {
			parts = append(parts, "server "+res.server)
		}
		if len(res.cookies) > 0 {
			parts = append(parts, "set-cookie "+strings.Join(res.cookies, ", "))
		}
		fmt.Printf("%-8s seen  %s\n", "", strings.Join(parts, "; "))
	}

	body := fmt.Sprintf("%s %s", size(res.bodyLen), orNone(res.bodyType))
	if res.title != "" {
		body += " — " + res.title
	}
	fmt.Printf("%-8s body  %s\n", "", body)
}

// httpVerdict turns the responses into the one sentence worth acting on, the
// same way the handshake verdict does.
func httpVerdict(profiles []string, results map[string]httpResult) {
	var (
		failed   int
		passed   int
		signals  = map[string]int{}
		lastSig  edgeSignal
		statuses []string
	)
	for _, name := range profiles {
		res, ok := results[name]
		if !ok {
			continue
		}
		if res.err != nil {
			failed++
			continue
		}
		statuses = append(statuses, fmt.Sprintf("%s %d", name, res.status))
		if res.signal.kind == "" && res.status >= 200 && res.status < 300 {
			passed++
			continue
		}
		key := res.signal.vendor + " " + res.signal.kind
		signals[key]++
		lastSig = res.signal
	}

	switch {
	case failed > 0 && passed == 0 && len(signals) == 0:
		fmt.Println("No profile got a response at all, so this failed below HTTP even")
		fmt.Println("though the handshake completed above — read the error: a timeout is")
		fmt.Println("the target not answering, a stream error is it hanging up on the")
		fmt.Println("request rather than on the ClientHello.")

	case passed == len(statuses) && len(statuses) > 0:
		fmt.Println("Every profile got a clean response, so nothing here is being")
		fmt.Println("blocked. Whatever fails in the real workload differs from this")
		fmt.Println("request in what comes after the handshake: the path, the method,")
		fmt.Println("the cookies it carries, or the rate it runs at.")

	case len(signals) == 1 && passed == 0:
		describeSignal(lastSig)

	case len(signals) > 0 && passed > 0:
		fmt.Printf("The profiles disagree (%s), so the decision is being made above\n", strings.Join(statuses, ", "))
		fmt.Println("TLS: both hellos completed, and the responses differ anyway. That")
		fmt.Println("leaves the header set and order, the User-Agent, and the HTTP/2")
		fmt.Println("settings fingerprint. Use the profile that got through.")

	default:
		fmt.Printf("Mixed responses (%s). Read each one above: the handshake is not\n", strings.Join(statuses, ", "))
		fmt.Println("what is deciding them.")
	}
}

// describeSignal says what a single, agreed-on edge verdict means for the
// client — specifically, whether changing the fingerprint could help.
func describeSignal(sig edgeSignal) {
	who := sig.vendor
	if who == "" {
		who = "The edge"
	}

	switch sig.kind {
	case "challenge":
		fmt.Printf("%s served a challenge to every profile. The fingerprint is not\n", who)
		fmt.Println("what is failing — it completed the handshake and the request; the")
		fmt.Println("edge wants a token this client cannot mint, because minting it means")
		fmt.Println("running the page's JavaScript. Get the clearance cookie with")
		fmt.Println("solver/index.js and replay it from the same profile and the same IP:")
		fmt.Println("the cookie is bound to the User-Agent, the JA4 and the address that")
		fmt.Println("earned it, so any of the three drifting brings the challenge back.")

	case "block":
		fmt.Printf("%s refused the request outright rather than challenging it. A\n", who)
		fmt.Println("block is a decision about the caller, not about the ClientHello:")
		fmt.Println("the address, its reputation, or the path being asked for. A")
		fmt.Println("different fingerprint does not move it — a different address might.")

	case "rate limit":
		fmt.Printf("%s is rate limiting this address. Nothing about the fingerprint\n", who)
		fmt.Println("changes that; the request rate does. Back off, spread the load over")
		fmt.Println("more addresses, or both.")

	case "auth required":
		fmt.Println("The target wants credentials. This is the application answering,")
		fmt.Println("not an edge blocking: send the session the request is missing.")

	default:
		fmt.Printf("%s answered every profile the same way (%s). The handshake and\n", who, sig.kind)
		fmt.Println("the request both completed, so this is the target's own answer to")
		fmt.Println("what was asked, not a fingerprint rejection.")
	}
}

// classify names who answered and what they decided. Header evidence is
// preferred over body text: a header is set by the edge, while body markers can
// be quoted by any page that happens to talk about them.
func classify(status int, h http.Header, body []byte) edgeSignal {
	// Scanning is capped: challenge and block pages put their markers in the
	// first few KB, and lowercasing a multi-megabyte body to find them is waste.
	const scanLimit = 256 << 10
	scan := body
	if len(scan) > scanLimit {
		scan = scan[:scanLimit]
	}
	text := strings.ToLower(string(scan))
	has := func(needle string) bool { return strings.Contains(text, needle) }
	cookies := strings.ToLower(strings.Join(h.Values("Set-Cookie"), "; "))
	hasCookie := func(name string) bool { return strings.Contains(cookies, name) }

	// Cloudflare states its own decision in a header, which is the only
	// unambiguous signal any of these vendors emit.
	// A 403 carrying this header is the managed challenge, not a firewall
	// block, and the header is what tells the two apart.
	if v := h.Get("Cf-Mitigated"); v != "" {
		return edgeSignal{"Cloudflare", strings.ToLower(v), "cf-mitigated: " + v}
	}
	switch {
	case has("cdn-cgi/challenge-platform"), has("_cf_chl_opt"), has("challenges.cloudflare.com/turnstile"):
		return edgeSignal{"Cloudflare", "challenge", `body carries the challenge platform script`}
	case has("attention required! | cloudflare"), has("error 1020"):
		return edgeSignal{"Cloudflare", "block", `body: "Attention Required" (firewall rule)`}
	case has("error 1015"), has("you are being rate limited"):
		return edgeSignal{"Cloudflare", "rate limit", "body: error 1015"}
	}

	if v := h.Get("X-Datadome"); v != "" || hasCookie("datadome=") || has("geo.captcha-delivery.com") {
		kind := "block"
		if has("geo.captcha-delivery.com") || has("captcha-delivery") {
			kind = "challenge"
		} else if status < 400 {
			kind = "watching"
		}
		why := "datadome cookie"
		if v != "" {
			why = "x-datadome: " + v
		} else if kind == "challenge" {
			why = "body points at captcha-delivery.com"
		}
		return edgeSignal{"DataDome", kind, why}
	}

	// "Reference #" alone is a phrase any page may contain, so it only counts
	// as Akamai's access-denied page when the response is actually a refusal.
	akamai := strings.Contains(strings.ToLower(h.Get("Server")), "akamaighost") ||
		hasCookie("_abck=") || hasCookie("bm_sz=")
	if akamai || (status >= 400 && has("reference #")) {
		kind := "watching"
		why := "akamai bot manager cookies (_abck/bm_sz)"
		switch {
		case has("reference #"):
			kind, why = "block", `body: "Reference #" access-denied page`
		case status == http.StatusForbidden:
			kind, why = "block", "403 from AkamaiGHost"
		case status == http.StatusTooManyRequests:
			kind, why = "rate limit", "429 from AkamaiGHost"
		}
		return edgeSignal{"Akamai", kind, why}
	}

	if h.Get("X-Iinfo") != "" || strings.EqualFold(h.Get("X-Cdn"), "Incapsula") ||
		has("incapsula incident id") || has("_incapsula_resource") {
		kind := "watching"
		why := "x-iinfo header"
		switch {
		case has("incapsula incident id"):
			kind, why = "block", "body: Incapsula incident ID"
		case has("_incapsula_resource"):
			kind, why = "challenge", "body loads _Incapsula_Resource"
		}
		return edgeSignal{"Imperva", kind, why}
	}

	if hasCookie("_px") || has("px-captcha") || has("perimeterx") || has("window._pxappid") {
		kind := "challenge"
		if status == http.StatusForbidden && !has("px-captcha") {
			kind = "block"
		}
		return edgeSignal{"HUMAN (PerimeterX)", kind, "perimeterx markers in the response"}
	}

	if v := h.Get("X-Amzn-Waf-Action"); v != "" || hasCookie("aws-waf-token") || has("awswaf") {
		kind := "challenge"
		if v == "block" || (v == "" && status == http.StatusForbidden && !has("awswaf")) {
			kind = "block"
		}
		why := "aws-waf-token cookie"
		if v != "" {
			why = "x-amzn-waf-action: " + v
		}
		return edgeSignal{"AWS WAF", kind, why}
	}

	if h.Get("X-Sucuri-Id") != "" && (status >= 400 || has("sucuri website firewall")) {
		return edgeSignal{"Sucuri", "block", "x-sucuri-id with a firewall page"}
	}

	// No vendor named itself. A captcha in the body is still a challenge
	// whoever put it there.
	if has("g-recaptcha") || has("hcaptcha.com/1/api.js") || has("recaptcha/api.js") {
		return edgeSignal{"", "challenge", "body embeds a captcha widget"}
	}

	server := h.Get("Server")
	switch {
	case status == http.StatusTooManyRequests:
		return edgeSignal{server, "rate limit", "429 with no vendor header"}
	case status == http.StatusUnauthorized:
		return edgeSignal{server, "auth required", "401"}
	case status == http.StatusForbidden:
		return edgeSignal{server, "block", "403 with no vendor header"}
	case status == http.StatusServiceUnavailable:
		return edgeSignal{server, "unavailable", "503 with no vendor header"}
	case status >= 300 && status < 400:
		return edgeSignal{server, "redirect", "redirects were not followed"}
	case status >= 500:
		return edgeSignal{server, "server error", fmt.Sprintf("%d from the origin", status)}
	}
	return edgeSignal{}
}

// bodyGist is the one line worth printing from a response body. On a challenge
// or a block page that is the <title>; on the short plaintext or JSON refusals
// that proxies and API gateways send, the message itself is the first line, and
// dropping it would throw away the only thing the response said.
func bodyGist(body []byte) string {
	if t := pageTitle(body); t != "" {
		return t
	}

	head := body
	if len(head) > 200 {
		head = head[:200]
	}
	// ToValidUTF8 also drops the partial rune the cut above may have left.
	text := strings.Join(strings.Fields(strings.ToValidUTF8(string(head), "")), " ")
	if text == "" {
		return ""
	}
	// Markup with no title says nothing in its first line, and binary bodies
	// say nothing at all.
	if strings.HasPrefix(text, "<") || strings.ContainsAny(text, "\x00\x01\x02\x03") {
		return ""
	}
	if len([]rune(text)) > 70 {
		text = string([]rune(text)[:70]) + "…"
	}
	return `"` + text + `"`
}

// pageTitle pulls the <title> out of an HTML body: on a challenge or block page
// it is the whole story ("Just a moment...", "Access denied").
var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func pageTitle(body []byte) string {
	const scanLimit = 64 << 10
	scan := body
	if len(scan) > scanLimit {
		scan = scan[:scanLimit]
	}
	m := titlePattern.FindSubmatch(scan)
	if m == nil {
		return ""
	}
	title := strings.Join(strings.Fields(string(m[1])), " ")
	if title == "" {
		return ""
	}
	if len(title) > 70 {
		title = title[:70] + "…"
	}
	return `"` + title + `"`
}

func protoName(resp *http.Response) string {
	if resp == nil || resp.Proto == "" {
		return "?"
	}
	if resp.ProtoMajor == 2 {
		return "h2"
	}
	return resp.Proto
}

func mediaType(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	return strings.TrimSpace(contentType)
}

func size(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
}

// requestURL builds the URL for the HTTP leg from the probe's target. It also
// reports whether -target pinned an address the client cannot be given, in
// which case the request resolves the name on its own.
func requestURL(addr, name, path string) (string, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, "443"
	}
	pinned := !strings.EqualFold(host, name)

	u := url.URL{Scheme: "https", Host: name, Path: "/"}
	if port != "443" {
		u.Host = name + ":" + port
	}
	if path != "" {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if q := strings.IndexByte(path, '?'); q >= 0 {
			u.Path, u.RawQuery = path[:q], path[q+1:]
		} else {
			u.Path = path
		}
	}
	return u.String(), pinned
}
