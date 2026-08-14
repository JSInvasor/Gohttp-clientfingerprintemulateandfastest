package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// -scout: look at a target, then say what to run against it.
//
// Every flag this tool has is a question about the target — does it challenge,
// does it speak h2, does the page have sub-resources, how far away is it — and
// until now the only way to answer them was to read the README and guess. The
// answers are all observable, and cheaply: a handful of requests, most of them
// concurrent, is enough to decide almost every flag that matters.
//
// What it will not do is find the rate limit. That is the one answer you can
// only get by pushing someone's server until it pushes back, and it is not this
// tool's to take on its own — so -c comes from the measured round-trip time and
// a rate you choose, which is arithmetic rather than an experiment on a
// stranger.
//
// The probes are shaped like ordinary traffic on purpose: a document fetch, a
// second one in another language, a few repeats to time the link. Nothing here
// is a scan, and nothing here is anything a browser would not also do.

// scoutRate is the request rate the suggested -c is computed for. It is a
// starting point, not a recommendation about what a target can take: the report
// prints the arithmetic so any other rate can be read straight off it.
const scoutRate = 200

// scoutRTTSamples is how many times the link is timed. The first request pays
// for the handshake, so it is measured separately and excluded.
const scoutRTTSamples = 4

// scoutProxyTries is how many entries of a proxy file are tried before giving
// up on finding somewhere to look from. A dead line at the top of the file
// should not fail a scout of the target, and which entry answers does not
// matter — what is being measured is the target, not the proxy.
const scoutProxyTries = 4

// scoutReport is what one look at a target found.
type scoutReport struct {
	target   string
	finalURL string
	via      string // the exit it was seen through, empty when direct

	status    int
	proto     string
	redirects []string

	edge         string // the CDN or WAF in front, when one announces itself
	edgeWhy      string
	challenge    challengeKind
	challengeWhy string

	cookies     []string
	encoding    string
	contentType string
	bodySize    int
	assets      int
	assetHosts  int

	// turnstile is a Turnstile widget on a page that was served. Not a challenge
	// — the document arrived — but the reason -solve is absent is worth saying
	// out loud, because a Cloudflare-fronted site with a visible widget on it is
	// exactly where someone would expect to see it suggested.
	turnstile bool

	localeAware bool
	langWhy     string

	// cold is the first request, DNS and handshake included; rtt is the median
	// of the ones after it. Kept apart because the difference is what -warmup
	// pays off, and one number averaging the two hides it.
	cold       time.Duration
	rtt        time.Duration
	rttSamples int

	// proxyCount is how many entries the proxy file has, which is the floor
	// under -s: a session is what pins a proxy, so fewer sessions than entries
	// means entries that never get dialled.
	proxyCount int

	notes []string
}

// scout probes target and returns what it found.
//
// The probes that do not depend on each other run at once, so the wall clock is
// a few round trips rather than a few times the number of questions asked.
func scout(ctx context.Context, o *options, profile gofire.BrowserProfile, target string) (*scoutReport, error) {
	r := &scoutReport{target: target, finalURL: target}

	exit, count, err := scoutExit(ctx, o, profile)
	if err != nil {
		return nil, err
	}
	r.via, r.proxyCount = exit.label(), count

	client, err := gofire.Emulate(profile, scoutOptions(o, exit.proxy)...)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// The document itself, and the redirect chain that leads to it. Two probes
	// rather than one because following redirects hides them, and the chain is
	// what says whether -no-redirect is safe.
	var wg sync.WaitGroup
	var body []byte
	var docErr, chainErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		body, docErr = scoutDocument(ctx, client, r, target)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		chainErr = scoutRedirects(ctx, o, profile, exit.proxy, r, target)
	}()

	wg.Wait()
	if docErr != nil {
		return nil, docErr
	}
	if chainErr != nil {
		r.notes = append(r.notes, "redirect chain: "+chainErr.Error())
	}

	// The rest all depend on having the document, and none on each other.
	wg.Add(1)
	go func() {
		defer wg.Done()
		scoutAssets(r, body, r.finalURL)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		scoutLanguage(ctx, o, profile, exit.proxy, r)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		scoutRTT(ctx, client, r)
	}()

	wg.Wait()
	return r, nil
}

// scoutExit picks the address to look from, and reports how many the run has to
// choose between.
//
// A datacenter IP is treated differently from a residential one by every edge
// worth scouting, so looking from the exit the run will use is the only reading
// that transfers. One entry is enough for that — this is not resolveExits, which
// measures every proxy because it is deciding how many solves to buy. Here the
// proxies are the instrument rather than the subject, so the first one that
// answers is taken and the rest are only counted.
func scoutExit(ctx context.Context, o *options, profile gofire.BrowserProfile) (exit, int, error) {
	switch {
	case o.proxyFile != "":
		rotator, err := gofire.NewProxyRotatorFromFile(o.proxyFile)
		if err != nil {
			return exit{}, 0, fmt.Errorf("proxy file: %w", err)
		}
		urls := rotator.ProxyURLs()
		if o.exitCheck == "" {
			// Measuring turned off. The report then says which proxy it looked
			// through but not where that leaves from, which is the honest
			// version of not having asked.
			return exit{proxy: urls[0]}, len(urls), nil
		}
		tries := min(len(urls), scoutProxyTries)
		for _, proxy := range urls[:tries] {
			ip, err := fetchExitIP(ctx, o, profile, proxy)
			if err != nil {
				continue
			}
			return exit{proxy: proxy, ip: ip}, len(urls), nil
		}
		return exit{}, len(urls), fmt.Errorf("none of the first %d entries in %s answered %s",
			tries, o.proxyFile, o.exitCheck)
	case o.proxy != "":
		return exit{proxy: o.proxy}, 1, nil
	}
	return exit{}, 0, nil
}

// scoutOptions is the client the probes run through: the run's own settings,
// minus anything that would change what the target says back.
func scoutOptions(o *options, proxy string) []gofire.Option {
	opts := []gofire.Option{
		gofire.WithTimeout(scoutTimeout(o)),
		gofire.WithTLSHandshakeTimeout(scoutTimeout(o)),
	}
	if proxy != "" {
		opts = append(opts, gofire.WithProxy(proxy))
	}
	if o.insecure {
		opts = append(opts, gofire.WithInsecureSkipVerify())
	}
	if o.lang != "" {
		opts = append(opts, gofire.WithAcceptLanguage(o.lang))
	}
	if o.userAgent != "" {
		opts = append(opts, gofire.WithUserAgent(o.userAgent))
	}
	return opts
}

func scoutTimeout(o *options) time.Duration {
	if o.timeout > 0 && o.timeout < 15*time.Second {
		return o.timeout
	}
	return 15 * time.Second
}

// scoutDocument fetches the page and reads everything the response itself says.
//
// It is the first request this client makes, so it pays DNS, the TCP handshake
// and the TLS handshake. That cost is recorded rather than discarded: measured
// against the warm round trip below it is exactly what -warmup buys back.
func scoutDocument(ctx context.Context, client *gofire.Client, r *scoutReport, target string) ([]byte, error) {
	start := time.Now()
	resp, err := client.DoWithContext(ctx, http.MethodGet, target, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", target, err)
	}
	defer resp.Close()
	r.cold = time.Since(start)

	r.status = resp.StatusCode()
	r.proto = resp.Proto
	r.encoding = resp.Header.Get("Content-Encoding")
	r.contentType, _, _ = strings.Cut(resp.Header.Get("Content-Type"), ";")
	r.contentType = strings.TrimSpace(r.contentType)
	if u := resp.Request; u != nil && u.URL != nil {
		r.finalURL = u.URL.String()
	}
	for _, c := range resp.Cookies() {
		r.cookies = append(r.cookies, c.Name)
	}
	sort.Strings(r.cookies)

	r.edge, r.edgeWhy = identifyEdge(resp.Header)

	body, err := resp.Bytes()
	if err != nil {
		// A body that will not decode is still a finding — it is what the run
		// would hit too — so the report continues without it.
		r.notes = append(r.notes, "body: "+err.Error())
		body = nil
	}
	r.bodySize = len(body)
	r.challenge, r.challengeWhy = identifyChallenge(r.status, resp.Header, body)
	r.turnstile = r.challenge == challengeNone && carriesTurnstile(body)
	return body, nil
}

// scoutRedirects walks the chain without following it, so the report can say
// where the target actually leads and whether -no-redirect would break it.
func scoutRedirects(ctx context.Context, o *options, profile gofire.BrowserProfile, proxy string, r *scoutReport, target string) error {
	opts := append(scoutOptions(o, proxy), gofire.WithDisableRedirects())
	client, err := gofire.Emulate(profile, opts...)
	if err != nil {
		return err
	}
	defer client.Close()

	const maxHops = 5
	at := target
	for hop := 0; hop < maxHops; hop++ {
		resp, err := client.DoWithContext(ctx, http.MethodGet, at, nil, nil)
		if err != nil {
			return err
		}
		loc := resp.Header.Get("Location")
		code := resp.StatusCode()
		resp.Close()

		if code < 300 || code > 399 || loc == "" {
			return nil
		}
		next, err := url.Parse(at)
		if err != nil {
			return err
		}
		resolved, err := next.Parse(loc)
		if err != nil {
			return err
		}
		at = resolved.String()
		r.redirects = append(r.redirects, fmt.Sprintf("%d → %s", code, at))
	}
	return nil
}

// scoutAssets counts what the document pulls in after itself.
func scoutAssets(r *scoutReport, body []byte, base string) {
	if len(body) == 0 {
		return
	}
	docURL, err := url.Parse(base)
	if err != nil {
		return
	}
	found := parseAssets(body, docURL, 200)
	r.assets = len(found)

	hosts := map[string]bool{}
	for _, a := range found {
		if u, err := url.Parse(a.url); err == nil && u.Host != "" {
			hosts[u.Host] = true
		}
	}
	r.assetHosts = len(hosts)
}

// scoutLanguage asks whether the target cares what language is requested. A
// site that redirects to a locale, or answers differently, is one where -lang
// is a content decision rather than only a fingerprint one.
func scoutLanguage(ctx context.Context, o *options, profile gofire.BrowserProfile, proxy string, r *scoutReport) {
	const other = "ja-JP,ja;q=0.9"
	opts := append(scoutOptions(o, proxy), gofire.WithAcceptLanguage(other))
	client, err := gofire.Emulate(profile, opts...)
	if err != nil {
		return
	}
	defer client.Close()

	resp, err := client.DoWithContext(ctx, http.MethodGet, r.target, nil, nil)
	if err != nil {
		return
	}
	defer resp.Close()

	finalURL := r.target
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	if finalURL != r.finalURL {
		r.localeAware = true
		r.langWhy = "asking in ja-JP landed on " + finalURL
		return
	}
	if v := resp.Header.Get("Content-Language"); v != "" {
		r.localeAware = true
		r.langWhy = "answers with Content-Language: " + v
		return
	}
	// Vary is the target saying so itself, and it costs nothing to read on a
	// response already in hand. It catches the case the probe above cannot: a
	// site that varies by language but happens to serve the same URL and the
	// same Content-Language for ja as for the default.
	for _, v := range resp.Header.Values("Vary") {
		if strings.Contains(strings.ToLower(v), "accept-language") {
			r.localeAware = true
			r.langWhy = "says so itself: Vary lists Accept-Language"
			return
		}
	}
}

// scoutRTT times the link on the connection the document already opened, so the
// number is the round trip a run sees rather than a handshake it pays once.
//
// It goes to the final URL rather than the given one: a target that redirects
// would otherwise be timed at two round trips per sample, and the run this is
// sizing will be pointed at the destination.
//
// The median rather than the mean, and taken while the language probe is in
// flight beside it — a scout that serialised its probes to protect the timing
// would take longer than the run it is sizing. One concurrent request is inside
// the noise the median is there to absorb.
func scoutRTT(ctx context.Context, client *gofire.Client, r *scoutReport) {
	var samples []time.Duration
	for i := 0; i < scoutRTTSamples; i++ {
		start := time.Now()
		resp, err := client.DoWithContext(ctx, http.MethodGet, r.finalURL, nil, nil)
		if err != nil {
			break
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck // timing the read too
		resp.Close()
		samples = append(samples, time.Since(start))
	}
	if len(samples) == 0 {
		return
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	r.rtt = samples[len(samples)/2]
	r.rttSamples = len(samples)
}
