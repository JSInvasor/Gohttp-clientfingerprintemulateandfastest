package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// scoutOpts is what the probes run with against a stand-in server: self-signed,
// so certificate verification has to be off, and on a short leash so a hung
// test fails rather than waits.
func scoutOpts() *options {
	return &options{insecure: true, timeout: 5 * time.Second}
}

func runScout(t *testing.T, o *options, target string) *scoutReport {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	r, err := scout(ctx, o, gofire.Chrome151, target)
	if err != nil {
		t.Fatalf("scout(%s): %v", target, err)
	}
	return r
}

const scoutPage = `<html><head><title>Home</title>
<link rel="stylesheet" href="/a.css">
<script src="/a.js"></script>
<script src="https://cdn.example.test/b.js"></script>
</head><body><img src="/logo.png"></body></html>`

// An ordinary target, read end to end: what came back, who is in front, what it
// set, what the page pulls in, and how far away it is.
func TestScoutReadsATarget(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("cf-ray", "8a1b2c3d4e5f-FRA")
		w.Header().Set("Server", "cloudflare")
		http.SetCookie(w, &http.Cookie{Name: "__cf_bm", Value: "x", Path: "/"})
		fmt.Fprint(w, scoutPage)
	}))
	defer srv.Close()

	r := runScout(t, scoutOpts(), srv.URL)

	if r.status != 200 {
		t.Errorf("status = %d", r.status)
	}
	if r.edge != "Cloudflare" {
		t.Errorf("edge = %q (%s), want Cloudflare", r.edge, r.edgeWhy)
	}
	if r.challenge != challengeNone {
		t.Errorf("challenge = %v (%s), want none", r.challenge, r.challengeWhy)
	}
	if len(r.cookies) != 1 || r.cookies[0] != "__cf_bm" {
		t.Errorf("cookies = %v, want [__cf_bm]", r.cookies)
	}
	// One stylesheet, two scripts, one image — and two hosts, since one script
	// is on a CDN.
	if r.assets != 4 || r.assetHosts != 2 {
		t.Errorf("assets = %d across %d hosts, want 4 across 2", r.assets, r.assetHosts)
	}
	if r.rtt <= 0 || r.rttSamples == 0 {
		t.Errorf("round trip was never measured (%s, %d samples)", r.rtt, r.rttSamples)
	}
	if r.cold <= 0 {
		t.Error("the first request was not timed, so -warmup has nothing to weigh")
	}
}

// A scout is a look, not a load test. What keeps it honest is that it is
// bounded by construction: a fixed handful of requests whatever the target
// does, so nothing about it can turn into finding a limit by pushing at one.
func TestScoutIsBoundedAndFast(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, scoutPage)
	}))
	defer srv.Close()

	start := time.Now()
	runScout(t, scoutOpts(), srv.URL)
	elapsed := time.Since(start)

	// document + redirect probe + language probe + the timing samples.
	const ceiling = scoutRTTSamples + 4
	if n := hits.Load(); n > ceiling {
		t.Errorf("the scout made %d requests, want at most %d — this is a look, not a run", n, ceiling)
	}
	if elapsed > 10*time.Second {
		t.Errorf("the scout took %s against a local server; the probes are not running concurrently", elapsed)
	}
}

// The chain is walked without being followed, so the report can say where a
// target actually leads — and the suggestion can point straight at it.
func TestScoutFollowsAndReportsRedirects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/en/", http.StatusMovedPermanently)
			return
		}
		fmt.Fprint(w, scoutPage)
	}))
	defer srv.Close()

	r := runScout(t, scoutOpts(), srv.URL+"/")

	if !strings.HasSuffix(r.finalURL, "/en/") {
		t.Errorf("finalURL = %q, want the destination", r.finalURL)
	}
	if len(r.redirects) != 1 || !strings.Contains(r.redirects[0], "/en/") {
		t.Errorf("redirects = %v, want the one hop that was walked", r.redirects)
	}

	p := recommend(r, &options{})
	if !strings.Contains(p.command, "/en/") {
		t.Errorf("command %q still points at the hop", p.command)
	}
}

// A challenged target has to come back as challenged rather than as a broken
// one, because those lead to opposite next steps.
func TestScoutSeesAChallenge(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("cf-ray", "8a1b2c3d4e5f-FRA")
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("cf-mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<html><head><title>Just a moment...</title></head>
<body><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1"></script></body></html>`)
	}))
	defer srv.Close()

	r := runScout(t, scoutOpts(), srv.URL)
	if r.challenge != challengeCloudflare {
		t.Fatalf("challenge = %v (%s), want a Cloudflare challenge", r.challenge, r.challengeWhy)
	}

	p := recommend(r, &options{})
	if !strings.Contains(p.command, "-solve") {
		t.Errorf("command %q does not solve the challenge in the way", p.command)
	}
	// The page numbers describe the interstitial. Reporting them as the site's
	// would be a measurement of the wrong document.
	var sb strings.Builder
	renderScout(&sb, r, p)
	if !strings.Contains(sb.String(), "interstitial") {
		t.Error("the report presents the interstitial's size and assets as the page's")
	}
}

// The language probe asks the same page in another language and reports what
// changed, so -lang can be a content decision rather than only a fingerprint one.
func TestScoutNoticesLanguage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := "en"
		if strings.Contains(r.Header.Get("Accept-Language"), "ja") {
			lang = "ja"
		}
		w.Header().Set("Content-Language", lang)
		fmt.Fprint(w, scoutPage)
	}))
	defer srv.Close()

	r := runScout(t, scoutOpts(), srv.URL)
	if !r.localeAware {
		t.Error("a target that answers with Content-Language went unnoticed")
	}
	if !strings.Contains(r.langWhy, "Content-Language") {
		t.Errorf("langWhy = %q, does not say what was observed", r.langWhy)
	}
}

// Vary is the target saying it varies by language, and it costs nothing to read
// on a response already in hand — which is the only way to catch a site that
// serves the same URL and the same Content-Language for ja as for the default.
func TestScoutReadsVaryForLanguage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept-Encoding, Accept-Language")
		fmt.Fprint(w, scoutPage)
	}))
	defer srv.Close()

	r := runScout(t, scoutOpts(), srv.URL)
	if !r.localeAware {
		t.Error("a target that declares Vary: Accept-Language went unnoticed")
	}
	if !strings.Contains(r.langWhy, "Vary") {
		t.Errorf("langWhy = %q, does not say what was read", r.langWhy)
	}
}

// routingProxy is a CONNECT proxy that goes where it is asked.
//
// Which is what separates it from tunnelProxy in exitip_test.go, and the
// difference is the point: that one ignores the request line so a simulated exit
// can answer with an address it does not have, and one backend is all it ever
// needs. A scout reaches the address check and the target through the same
// entry, so a proxy that only ever dialled one of them could not carry it.
func routingProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				br := bufio.NewReader(client)

				request, err := br.ReadString('\n')
				if err != nil {
					return
				}
				fields := strings.Fields(request)
				if len(fields) < 2 || fields[0] != http.MethodConnect {
					fmt.Fprint(client, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
					return
				}
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}

				up, err := net.Dial("tcp", fields[1])
				if err != nil {
					fmt.Fprint(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				if _, err := fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					return
				}
				go io.Copy(up, br) //nolint:errcheck // the tunnel ends when either side closes
				io.Copy(client, up)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

// A scout through a proxy list looks from an exit rather than from here, because
// a datacenter address and a residential one are not handled alike by anything
// worth scouting. It takes the first entry that answers rather than the first
// line, and counts the rest: that count is the floor under -s.
func TestScoutLooksFromAnExit(t *testing.T) {
	trace := traceServer(t, "203.0.113.9")
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, scoutPage)
	}))
	defer target.Close()

	// A dead entry first, so the walk past it is what is being tested.
	live := routingProxy(t)
	file := proxyFile(t, "http://127.0.0.1:1", live, live, live)

	o := scoutOpts()
	o.proxyFile = file
	o.exitCheck = trace.URL

	r := runScout(t, o, target.URL)

	if r.proxyCount != 4 {
		t.Errorf("proxyCount = %d, want the 4 entries in the file", r.proxyCount)
	}
	if !strings.Contains(r.via, "203.0.113.9") {
		t.Errorf("via = %q, does not name the address it looked from", r.via)
	}
	if r.status != 200 {
		t.Errorf("status = %d through the exit", r.status)
	}

	// Loopback answers faster than any rate needs threads, so -c lands at 1 and
	// three of the four entries have no worker to be dialled from. That is a
	// real outcome rather than a quirk of the harness — a list can always
	// outnumber the workers a target's round trip calls for — and the thing that
	// must not happen is it passing without a word.
	p := recommend(r, &options{proxyFile: file})
	if !strings.Contains(warningsJoined(p), "4 entries") {
		t.Errorf("the notes %q do not mention that most of the list would go undialled",
			warningsJoined(p))
	}
}

// A target that will not answer at all is an error rather than a report full of
// zeroes with a confident command under it.
func TestScoutFailsLoudlyOnADeadTarget(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead := srv.URL
	srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := scout(ctx, scoutOpts(), gofire.Chrome151, dead); err == nil {
		t.Error("scouting a closed port returned a report")
	}
}
