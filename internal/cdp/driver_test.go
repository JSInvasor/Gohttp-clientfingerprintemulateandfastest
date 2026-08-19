package cdp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The driver tests need a browser. A box without one skips rather than fails:
// the pure-logic tests are elsewhere and this file is about whether the protocol
// work is right, which cannot be answered without the other end of the pipe.
func testBrowser(t *testing.T) *Browser {
	t.Helper()
	if _, err := Find(); err != nil {
		t.Skip("no Chrome or Chromium installed:", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	b, err := Launch(ctx, LaunchConfig{
		// Headless on purpose here: these tests are about the protocol, and a
		// box running them may have no display and no Xvfb.
		Headless: true,
		Args:     []string{"--no-sandbox", "--disable-dev-shm-usage"},
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func TestLaunchAnswersVersion(t *testing.T) {
	b := testBrowser(t)
	if !strings.Contains(b.Version.Product, "/") {
		t.Fatalf("Browser.getVersion product = %q, want something like Chrome/141.0.0.0", b.Version.Product)
	}
	if b.PID() == 0 {
		t.Fatal("browser reports no pid")
	}
}

// Runtime.evaluate has to work without Runtime.enable, or the whole premise of
// this package is wrong. See the package comment.
func TestEvaluateWithoutRuntimeEnable(t *testing.T) {
	b := testBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tab, err := b.DefaultContext().NewTab(ctx)
	if err != nil {
		t.Fatalf("new tab: %v", err)
	}
	defer tab.Close(ctx)

	var got int
	if err := tab.Evaluate(ctx, "6*7", &got); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got != 42 {
		t.Fatalf("evaluate = %d, want 42", got)
	}

	// And the structured read the solve actually makes.
	var identity struct {
		UserAgent string   `json:"userAgent"`
		Languages []string `json:"languages"`
		Timezone  string   `json:"timezone"`
	}
	err = tab.Evaluate(ctx, `({userAgent: navigator.userAgent,
		languages: navigator.languages,
		timezone: Intl.DateTimeFormat().resolvedOptions().timeZone})`, &identity)
	if err != nil {
		t.Fatalf("identity evaluate: %v", err)
	}
	if identity.UserAgent == "" {
		t.Fatal("navigator.userAgent came back empty")
	}
}

// origin serves the tests that need a real one.
//
// 127.0.0.1 rather than a data: URL, and that is not a detail. Two of the things
// this package pins are only reachable from a secure context — navigator
// .userAgentData is undefined on about:blank, and document.cookie throws a
// SecurityError on an opaque origin — so a test written against about:blank
// cannot see the properties it is checking. localhost counts as trustworthy, so
// it is the cheapest real origin there is.
//
// It also makes the assertion the right one. What Cloudflare reads is the
// request header, not the page object, so the handler records every header the
// browser sent and the test checks those.
type origin struct {
	server  *httptest.Server
	mu      sync.Mutex
	headers http.Header
}

func newOrigin(t *testing.T) *origin {
	t.Helper()
	o := &origin{}
	o.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.headers = r.Header.Clone()
		o.mu.Unlock()
		// Accept-CH asks the browser for the high-entropy hints on the next
		// request, which is how a real challenge collects them.
		w.Header().Set("Accept-CH", "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<html><body>ok</body></html>")
	}))
	t.Cleanup(o.server.Close)
	return o
}

func (o *origin) header(name string) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.headers.Get(name)
}

// The UA override has to move the header, the page object and the Client Hints
// together. A UA that moves alone is the mismatch the solver exists to prevent:
// a request claiming Chrome 151 while sending no sec-ch-ua at all is a
// combination no real Chrome emits, on the request that earns cf_clearance.
func TestSetUserAgentPinsIdentityAndHints(t *testing.T) {
	b := testBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	site := newOrigin(t)

	tab, err := b.DefaultContext().NewTab(ctx)
	if err != nil {
		t.Fatalf("new tab: %v", err)
	}
	defer tab.Close(ctx)

	const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	meta := &UserAgentMetadata{
		Brands: []Brand{
			{Brand: "Not=A?Brand", Version: "99"},
			{Brand: "Google Chrome", Version: "151"},
			{Brand: "Chromium", Version: "151"},
		},
		FullVersionList: []Brand{
			{Brand: "Not=A?Brand", Version: "99.0.0.0"},
			{Brand: "Google Chrome", Version: "151.0.7204.50"},
			{Brand: "Chromium", Version: "151.0.7204.50"},
		},
		FullVersion:  "151.0.7204.50",
		Platform:     "Linux",
		Architecture: "x86",
		Bitness:      "64",
		Mobile:       false,
	}
	// A preference list, not a header: "en-US,en" is what produces the header
	// "en-US,en;q=0.9". See SetUserAgent and TestAcceptLanguageDerivation.
	if err := tab.SetUserAgent(ctx, ua, "en-US,en", "Linux", meta); err != nil {
		t.Fatalf("set user agent: %v", err)
	}
	if err := tab.Navigate(ctx, site.server.URL); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	// What the edge reads.
	if got := site.header("User-Agent"); got != ua {
		t.Fatalf("User-Agent header = %q, want %q", got, ua)
	}
	if got := site.header("Sec-CH-UA"); got == "" {
		t.Fatal("the UA override cleared sec-ch-ua: a Chrome 151 UA with no Client Hints is not a browser that exists")
	} else if !strings.Contains(got, `"Google Chrome";v="151"`) {
		t.Fatalf("Sec-CH-UA = %q, want the pinned Chrome 151 brand", got)
	}
	if got := site.header("Sec-CH-UA-Platform"); got != `"Linux"` {
		t.Fatalf("Sec-CH-UA-Platform = %q, want %q", got, `"Linux"`)
	}
	if got := site.header("Sec-CH-UA-Mobile"); got != "?0" {
		t.Fatalf("Sec-CH-UA-Mobile = %q, want ?0", got)
	}
	// The header is derived rather than echoed: a tag carrying a region gains
	// its base language at q=0.9. Asserting the derived value is what keeps a
	// caller from passing a finished header and getting "en-US,en;q=0.9;q=0.9".
	if got := site.header("Accept-Language"); got != "en-US,en;q=0.9" {
		t.Fatalf("Accept-Language = %q, want en-US,en;q=0.9", got)
	}

	// What the challenge's own JavaScript reads, which has to agree with it.
	var got string
	if err := tab.Evaluate(ctx, "navigator.userAgent", &got); err != nil {
		t.Fatalf("read ua: %v", err)
	}
	if got != ua {
		t.Fatalf("navigator.userAgent = %q, want %q", got, ua)
	}

	var brands []Brand
	if err := tab.Evaluate(ctx, "navigator.userAgentData.brands", &brands); err != nil {
		t.Fatalf("read brands: %v", err)
	}
	if len(brands) != 3 {
		t.Fatalf("userAgentData.brands = %v, want the three pinned entries", brands)
	}
	// Chrome puts its greased entry first and the ordering is itself observable,
	// so nothing that builds this list may sort it.
	if brands[0].Brand != "Not=A?Brand" {
		t.Fatalf("brand order changed: got %q first, want the greased entry", brands[0].Brand)
	}

	// The high-entropy hints carry the real build, not the frozen <major>.0.0.0
	// of the UA string — that is what a real browser answers, and Accept-CH on
	// the first response is what asks for them.
	if err := tab.Navigate(ctx, site.server.URL); err != nil {
		t.Fatalf("second navigate: %v", err)
	}
	if got := site.header("Sec-CH-UA-Full-Version-List"); !strings.Contains(got, "151.0.7204.50") {
		t.Fatalf("Sec-CH-UA-Full-Version-List = %q, want the pinned full version", got)
	}
	if got := site.header("Sec-CH-UA-Bitness"); got != `"64"` {
		t.Fatalf("Sec-CH-UA-Bitness = %q, want %q", got, `"64"`)
	}
}

// The timezone override has to reach Intl, which is the half of the identity no
// header carries. An unconfigured container answers "Etc/Unknown" here, which is
// not a zone any installed browser reports.
func TestSetTimezoneReachesIntl(t *testing.T) {
	b := testBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tab, err := b.DefaultContext().NewTab(ctx)
	if err != nil {
		t.Fatalf("new tab: %v", err)
	}
	defer tab.Close(ctx)

	if err := tab.SetTimezone(ctx, "Europe/Istanbul"); err != nil {
		t.Fatalf("set timezone: %v", err)
	}
	var got string
	err = tab.Evaluate(ctx, "Intl.DateTimeFormat().resolvedOptions().timeZone", &got)
	if err != nil {
		t.Fatalf("read timezone: %v", err)
	}
	if got != "Europe/Istanbul" {
		t.Fatalf("Intl timeZone = %q, want Europe/Istanbul", got)
	}
}

// An init script has to be in place before the document's own scripts run.
func TestAddInitScriptRunsBeforeDocument(t *testing.T) {
	b := testBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tab, err := b.DefaultContext().NewTab(ctx)
	if err != nil {
		t.Fatalf("new tab: %v", err)
	}
	defer tab.Close(ctx)

	if err := tab.AddInitScript(ctx, `window.__pinned = "before";`); err != nil {
		t.Fatalf("add init script: %v", err)
	}
	if err := tab.Navigate(ctx, "data:text/html,<html><body>hi</body></html>"); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	var got string
	if err := tab.Evaluate(ctx, "window.__pinned", &got); err != nil {
		t.Fatalf("read pinned: %v", err)
	}
	if got != "before" {
		t.Fatalf("init script did not run: window.__pinned = %q", got)
	}
}

// Two contexts must not see each other's cookies. This is the property batch
// mode is built on: one browser, one exit per context, and a cf_clearance that
// belongs to exactly the exit that earned it.
func TestContextsHaveSeparateCookieJars(t *testing.T) {
	b := testBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	first, err := b.NewContext(ctx, "")
	if err != nil {
		t.Fatalf("first context: %v", err)
	}
	defer first.Close(ctx)
	second, err := b.NewContext(ctx, "")
	if err != nil {
		t.Fatalf("second context: %v", err)
	}
	defer second.Close(ctx)

	site := newOrigin(t)

	tab, err := first.NewTab(ctx)
	if err != nil {
		t.Fatalf("tab: %v", err)
	}
	defer tab.Close(ctx)

	if err := tab.Navigate(ctx, site.server.URL); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if err := tab.Evaluate(ctx, `document.cookie = "solved=first; path=/"`, nil); err != nil {
		t.Fatalf("set cookie: %v", err)
	}

	firstJar, err := first.Cookies(ctx)
	if err != nil {
		t.Fatalf("first jar: %v", err)
	}
	secondJar, err := second.Cookies(ctx)
	if err != nil {
		t.Fatalf("second jar: %v", err)
	}
	if !hasCookie(firstJar, "solved") {
		t.Fatalf("the context that set the cookie does not hold it: %v", firstJar)
	}
	if hasCookie(secondJar, "solved") {
		t.Fatalf("a second context sees the first one's cookie: %v", secondJar)
	}
}

func hasCookie(jar []Cookie, name string) bool {
	for _, c := range jar {
		if c.Name == name {
			return true
		}
	}
	return false
}

// A context created with a proxy must actually dial it. Pointing one at a dead
// port is the cheap way to prove the proxy reached the browser: the navigation
// fails with a tunnel error rather than the site loading.
func TestContextProxyIsApplied(t *testing.T) {
	b := testBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c, err := b.NewContext(ctx, "http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("proxied context: %v", err)
	}
	defer c.Close(ctx)

	tab, err := c.NewTab(ctx)
	if err != nil {
		t.Fatalf("tab: %v", err)
	}
	defer tab.Close(ctx)

	navCtx, navCancel := context.WithTimeout(ctx, 20*time.Second)
	defer navCancel()
	_ = tab.Navigate(navCtx, "http://example.com/")

	var body string
	if err := tab.Evaluate(ctx, "document.body ? document.body.innerText : ''", &body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	// Chrome renders its own error page for a proxy it cannot reach. Whatever
	// the wording, what must not happen is the site loading.
	if strings.Contains(strings.ToLower(body), "example domain") {
		t.Fatal("the page loaded through a proxy that does not exist: the context proxy was ignored")
	}
}

func TestFindHonoursSolverChrome(t *testing.T) {
	t.Setenv("SOLVER_CHROME", "/definitely/not/here")
	if _, err := Find(); err == nil {
		t.Fatal("Find() accepted a SOLVER_CHROME that does not exist")
	}

	self, err := os.Executable()
	if err != nil {
		t.Skip("no executable path")
	}
	t.Setenv("SOLVER_CHROME", self)
	got, err := Find()
	if err != nil {
		t.Fatalf("Find(): %v", err)
	}
	if got != self {
		t.Fatalf("Find() = %q, want the SOLVER_CHROME value %q", got, self)
	}
}
