package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

func cookieNamed(t *testing.T, client *gofire.Client, target, name string) string {
	t.Helper()
	cookies, err := client.GetCookies(target)
	if err != nil {
		t.Fatalf("GetCookies: %v", err)
	}
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// The seeds reach the jars they were solved for. Everything upstream of this
// keeps a cookie paired with its exit; this is where the pairing is finally
// spent, and a session holding the wrong cf_clearance is a 403 that reads as
// the target blocking the client.
func TestSessionPoolSeedsEachSessionWithItsOwnSolve(t *testing.T) {
	const target = "https://site.test/"
	o := &options{
		sessions:  3,
		proxyList: []string{"http://a.test:1", "http://b.test:2"},
		solveSeeds: []solveSeed{
			{proxy: "http://a.test:1", userAgent: "UA-151", cookies: []string{"cf_clearance=for-a"}},
			{proxy: "http://b.test:2", userAgent: "UA-151", cookies: []string{"cf_clearance=for-b"}},
		},
		cookies: cookieList{"lang=en"},
		maxBody: -1,
	}

	pool, err := newSessionPool(o, gofire.Chrome151, target)
	if err != nil {
		t.Fatalf("newSessionPool: %v", err)
	}
	defer pool.Close()

	// Three sessions over two exits: the third wraps back onto the first, which
	// is legitimate — same IP, same UA, same fingerprint — and is also how the
	// proxy pinning wraps, so the two must agree.
	for i, want := range []string{"for-a", "for-b", "for-a"} {
		if got := cookieNamed(t, pool.sessions[i].client, target, "cf_clearance"); got != want {
			t.Errorf("session %d replays cf_clearance=%q, want %q", i, got, want)
		}
		// A -cookie the user typed is seeded alongside the solve, not replaced
		// by it.
		if got := cookieNamed(t, pool.sessions[i].client, target, "lang"); got != "en" {
			t.Errorf("session %d lost the -cookie seed, lang=%q", i, got)
		}
	}
}

// A solve narrows the file to the exits that earned a cookie. If the pool read
// the file again instead, the dropped ones would come back into rotation with
// nothing to present at them.
func TestSessionPoolRotatesOnlyOverSolvedExits(t *testing.T) {
	path := proxyFile(t, "http://a.test:1", "http://dead.test:2", "http://c.test:3")
	o := &options{
		sessions:   1,
		proxyFile:  path,
		proxyList:  []string{"http://a.test:1", "http://c.test:3"},
		solveSeeds: []solveSeed{{proxy: "http://a.test:1"}, {proxy: "http://c.test:3"}},
		maxBody:    -1,
	}

	pool, err := newSessionPool(o, gofire.Chrome151, "https://site.test/")
	if err != nil {
		t.Fatalf("newSessionPool: %v", err)
	}
	defer pool.Close()

	got := pool.rotator.ProxyURLs()
	if len(got) != 2 {
		t.Fatalf("rotator holds %v, want only the solved exits", got)
	}
	for _, p := range got {
		if p == "http://dead.test:2" {
			t.Errorf("rotator holds %v, the dropped exit came back through the file", got)
		}
	}
}

// Without a solve nothing changes: the file is the list, and -cookie is still
// seeded into every session.
func TestSessionPoolWithoutSeedsUsesTheFile(t *testing.T) {
	const target = "https://site.test/"
	o := &options{
		sessions:  2,
		proxyFile: proxyFile(t, "http://a.test:1", "http://b.test:2"),
		cookies:   cookieList{"lang=en"},
		maxBody:   -1,
	}

	pool, err := newSessionPool(o, gofire.Chrome151, target)
	if err != nil {
		t.Fatalf("newSessionPool: %v", err)
	}
	defer pool.Close()

	if got := pool.rotator.Count(); got != 2 {
		t.Errorf("rotator holds %d proxies, want the file's 2", got)
	}
	for i, s := range pool.sessions {
		if got := cookieNamed(t, s.client, target, "lang"); got != "en" {
			t.Errorf("session %d: lang=%q, want en", i, got)
		}
	}
}

// A cookie value can hold '=' — base64 padding is the common case — and the
// split that turns a seed back into an http.Cookie takes the first one only.
func TestSessionPoolKeepsCookieValuesWhole(t *testing.T) {
	const target = "https://site.test/"
	o := &options{
		sessions:   1,
		solveSeeds: []solveSeed{{cookies: []string{"cf_clearance=a=b=="}}},
		maxBody:    -1,
	}

	pool, err := newSessionPool(o, gofire.Chrome151, target)
	if err != nil {
		t.Fatalf("newSessionPool: %v", err)
	}
	defer pool.Close()

	if got := cookieNamed(t, pool.sessions[0].client, target, "cf_clearance"); got != "a=b==" {
		t.Errorf("cf_clearance = %q, want the value kept whole", got)
	}
}

// The solved UA is what the cookie was issued to, so it has to be the UA that
// replays it — unless the user typed one, which is a deliberate choice worth
// keeping (solveAndSeed warns about the mismatch rather than hiding it).
func TestClientOptionsTakesTheSeedUA(t *testing.T) {
	seed := &solveSeed{userAgent: "UA-from-solve"}

	if got := lastUserAgent(clientOptions(&options{maxBody: -1}, seed)); got != "UA-from-solve" {
		t.Errorf("user agent = %q, want the solved one", got)
	}
	explicit := &options{userAgent: "mine", maxBody: -1}
	if got := lastUserAgent(clientOptions(explicit, seed)); got != "mine" {
		t.Errorf("user agent = %q, want the explicit -ua to win", got)
	}
	if got := lastUserAgent(clientOptions(&options{maxBody: -1}, nil)); got != "" {
		t.Errorf("user agent = %q, want the profile default left alone", got)
	}
}

// lastUserAgent applies the options to a client and reports the User-Agent they
// left it with, which is what Emulate would do with them.
func lastUserAgent(opts []gofire.Option) string {
	client, err := gofire.Emulate(gofire.Chrome151, opts...)
	if err != nil {
		return "emulate: " + err.Error()
	}
	defer client.Close()

	req, err := client.PrepareRequest(http.MethodGet, "https://site.test/")
	if err != nil {
		return "prepare: " + err.Error()
	}
	// The profile's own UA is not an override, and the caller is asking which
	// override survived.
	if ua := req.Header.Get("User-Agent"); ua != gofire.ReferenceFor(gofire.Chrome151).UserAgent {
		return ua
	}
	return ""
}

// The jar is not the wire.
//
// Every test above checks that a solved cookie reached the session's cookie jar,
// which is a different claim from the one that matters: that it goes out on the
// request. A cf_clearance that sits in a jar and is never sent produces exactly
// what a rejected one produces — a fresh challenge — and nothing distinguishes
// them from the outside.
func TestSeededCookiesReachTheWire(t *testing.T) {
	var got struct {
		cookie string
		ua     string
		hits   int
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.cookie = r.Header.Get("Cookie")
		got.ua = r.Header.Get("User-Agent")
		got.hits++
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	// Exactly the shape -solve leaves behind on the single-exit path: the
	// cookies and the UA folded into the options the pool is built from.
	o := &options{
		mode: modeClient, sessions: 1, concurrency: 1, count: 1,
		insecure: true, timeout: 10 * time.Second, maxBody: -1,
		cookies:   cookieList{"cf_clearance=solved-value", "__cf_bm=bm-value"},
		userAgent: "Mozilla/5.0 (X11; Linux x86_64) Chrome/151.0.0.0",
	}
	pool, err := newSessionPool(o, gofire.Chrome151, srv.URL)
	if err != nil {
		t.Fatalf("newSessionPool: %v", err)
	}
	defer pool.Close()

	resp, err := pool.sessions[0].client.DoWithContext(
		context.Background(), http.MethodGet, srv.URL, nil, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Close()

	if got.hits != 1 {
		t.Fatalf("server saw %d requests", got.hits)
	}
	for _, want := range []string{"cf_clearance=solved-value", "__cf_bm=bm-value"} {
		if !strings.Contains(got.cookie, want) {
			t.Errorf("Cookie header %q does not carry %s", got.cookie, want)
		}
	}
	if got.ua != o.userAgent {
		t.Errorf("User-Agent = %q, want the solved one %q", got.ua, o.userAgent)
	}
}
