package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

const assetDoc = `<!doctype html><html><head>
<link rel="stylesheet" href="/a.css">
<link rel="icon" href="/favicon.ico">
<link rel="preload" as="font" href="/f.woff2" crossorigin>
<link rel="preload" as="script" href="//cdn.other.test/p.js">
<script src="https://static.site.test/b.js"></script>
<script>inline()</script>
</head><body>
<img src="img/c.png">
<img src="data:image/gif;base64,R0lGOD">
<img src="/a.css">
</body></html>`

func TestParseAssetsFindsWhatABrowserWouldFetch(t *testing.T) {
	base := mustURL(t, "https://site.test/page/")
	got := parseAssets([]byte(assetDoc), base, 0)

	want := []asset{
		{"https://site.test/a.css", destStyle},
		{"https://site.test/favicon.ico", destImage},
		{"https://site.test/f.woff2", destFont},
		{"https://cdn.other.test/p.js", destScript},
		{"https://static.site.test/b.js", destScript},
		{"https://site.test/page/img/c.png", destImage},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d assets, want %d:\n%+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("asset %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A data: URL never reaches the network, and an inline <script> has nothing to
// fetch. Requesting either would invent traffic no browser produces.
func TestParseAssetsSkipsNonNetworkRefs(t *testing.T) {
	base := mustURL(t, "https://site.test/")
	for _, doc := range []string{
		`<img src="data:image/gif;base64,R0lGOD">`,
		`<script>var x = 1</script>`,
		`<link rel="stylesheet" href="">`,
		`<img src="blob:https://site.test/abc">`,
		`<link rel="preconnect" href="https://cdn.test">`,
		`<link rel="dns-prefetch" href="https://cdn.test">`,
	} {
		if got := parseAssets([]byte(doc), base, 0); len(got) != 0 {
			t.Errorf("%s -> %+v, want none", doc, got)
		}
	}
}

// The same URL referenced twice is one fetch, and the limit is a ceiling.
func TestParseAssetsDedupesAndLimits(t *testing.T) {
	base := mustURL(t, "https://site.test/")
	dup := `<img src="/x.png"><img src="/x.png"><img src="/x.png#frag">`
	if got := parseAssets([]byte(dup), base, 0); len(got) != 1 {
		t.Errorf("duplicates were not collapsed: %+v", got)
	}
	many := `<img src="/1.png"><img src="/2.png"><img src="/3.png"><img src="/4.png">`
	if got := parseAssets([]byte(many), base, 2); len(got) != 2 {
		t.Errorf("limit ignored: %+v", got)
	}
}

// These values are the measured ones. A guess here is a header no Chrome sends.
func TestAssetHeadersMatchTheMeasuredBrowser(t *testing.T) {
	doc := mustURL(t, "https://site.test/page")
	tests := []struct {
		dest      assetDest
		accept    string
		mode      string
		priority  string
		hasOrigin bool
	}{
		{destStyle, "text/css,*/*;q=0.1", "no-cors", "u=0", false},
		{destScript, "*/*", "no-cors", "u=1", false},
		{destImage, "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8", "no-cors", "u=2, i", false},
		{destFont, "*/*", "cors", "u=1", true},
	}
	for _, tc := range tests {
		h := assetHeaders(asset{url: "https://site.test/x", dest: tc.dest}, doc)
		if h["Accept"] != tc.accept {
			t.Errorf("%s Accept = %q, want %q", tc.dest, h["Accept"], tc.accept)
		}
		if h["Sec-Fetch-Mode"] != tc.mode {
			t.Errorf("%s Sec-Fetch-Mode = %q, want %q", tc.dest, h["Sec-Fetch-Mode"], tc.mode)
		}
		if h["Sec-Fetch-Dest"] != string(tc.dest) {
			t.Errorf("%s Sec-Fetch-Dest = %q", tc.dest, h["Sec-Fetch-Dest"])
		}
		if h["Priority"] != tc.priority {
			t.Errorf("%s Priority = %q, want %q", tc.dest, h["Priority"], tc.priority)
		}
		if h["Referer"] != "https://site.test/page" {
			t.Errorf("%s Referer = %q", tc.dest, h["Referer"])
		}
		if _, ok := h["Origin"]; ok != tc.hasOrigin {
			t.Errorf("%s Origin present = %v, want %v", tc.dest, ok, tc.hasOrigin)
		}
		// Navigation-only headers must not appear on a subresource.
		for _, forbidden := range []string{"Upgrade-Insecure-Requests", "Sec-Fetch-User"} {
			if _, ok := h[forbidden]; ok {
				t.Errorf("%s carried %s, which is navigation-only", tc.dest, forbidden)
			}
		}
	}
}

func TestAssetFetchSite(t *testing.T) {
	doc := mustURL(t, "https://site.test/page")
	tests := []struct{ url, want string }{
		{"https://site.test/a.css", "same-origin"},
		{"https://site.test:443/a.css", "same-origin"}, // 443 is the https default, so one origin
		{"https://static.site.test/b.js", "same-site"},
		{"https://cdn.other.test/p.js", "cross-site"},
		{"http://site.test/a.css", "cross-site"}, // scheme is part of the origin
	}
	for _, tc := range tests {
		if got := assetFetchSite(doc, tc.url); got != tc.want {
			t.Errorf("%s -> %q, want %q", tc.url, got, tc.want)
		}
	}
}

// A missing image is normal on a real page. It must be counted, not fatal.
type stubDoer struct {
	calls  atomic.Int64
	failOn string
}

func (s *stubDoer) DoWithContext(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (*gofire.Response, error) {
	s.calls.Add(1)
	if s.failOn != "" && rawURL == s.failOn {
		return nil, errors.New("connection refused")
	}
	return nil, errors.New("no transport in this test")
}

func TestFetchAssetsCountsFailuresWithoutAborting(t *testing.T) {
	doc := mustURL(t, "https://site.test/")
	assets := []asset{
		{"https://site.test/a.css", destStyle},
		{"https://site.test/b.js", destScript},
		{"https://site.test/c.png", destImage},
	}
	s := &stubDoer{}
	ok, failed := fetchAssets(context.Background(), s, doc, assets, 2)
	if ok != 0 || failed != len(assets) {
		t.Errorf("ok=%d failed=%d, want 0 and %d", ok, failed, len(assets))
	}
	if n := s.calls.Load(); n != int64(len(assets)) {
		t.Errorf("made %d requests, want %d", n, len(assets))
	}
}

// A cancelled run must stop issuing asset requests.
func TestFetchAssetsHonoursContext(t *testing.T) {
	doc := mustURL(t, "https://site.test/")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := &stubDoer{}
	ok, failed := fetchAssets(ctx, s, doc, []asset{{"https://site.test/a.css", destStyle}}, 1)
	if ok != 0 || failed != 0 {
		t.Errorf("a cancelled context still fetched: ok=%d failed=%d", ok, failed)
	}
	if n := s.calls.Load(); n != 0 {
		t.Errorf("made %d requests after cancellation", n)
	}
}

// A run interrupted while its assets are still in flight has to stop counting
// before it reports, and it has to have stopped its goroutines.
//
// It did neither. The cancellation path returned from inside the loop, reading
// ok and failed with no lock while the fetches already running were still
// incrementing them under one — a data race confirmed with `go test -race` — and
// it returned before wg.Wait(), so the number printed was still moving as it was
// printed and the goroutines outlived the function that started them.
//
// The doer below cancels the run from inside the first request, which is the
// shape of a Ctrl-C landing mid-page.
type cancellingDoer struct {
	cancel  context.CancelFunc
	calls   atomic.Int64
	running atomic.Int64
	max     atomic.Int64
}

func (d *cancellingDoer) DoWithContext(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (*gofire.Response, error) {
	n := d.running.Add(1)
	for {
		got := d.max.Load()
		if n <= got || d.max.CompareAndSwap(got, n) {
			break
		}
	}
	d.calls.Add(1)
	d.cancel()
	time.Sleep(10 * time.Millisecond)
	d.running.Add(-1)
	return nil, errors.New("interrupted")
}

func TestFetchAssetsCancelledMidFlightWaitsForItsOwnGoroutines(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	doc := mustURL(t, "https://site.test/")
	var list []asset
	for i := 0; i < 40; i++ {
		list = append(list, asset{fmt.Sprintf("https://site.test/%d.png", i), destImage})
	}

	d := &cancellingDoer{cancel: cancel}
	ok, failed := fetchAssets(ctx, d, doc, list, 8)

	// Nothing is still running by the time the counts are read: that is what
	// makes reading them without a lock safe, and what makes the printed number
	// final rather than a snapshot of a moving one.
	if n := d.running.Load(); n != 0 {
		t.Errorf("%d fetches were still in flight after fetchAssets returned", n)
	}
	if int64(ok+failed) != d.calls.Load() {
		t.Errorf("reported ok=%d failed=%d but %d requests were made", ok, failed, d.calls.Load())
	}
	// The interrupt stopped it early rather than working the whole list.
	if d.calls.Load() >= int64(len(list)) {
		t.Errorf("a cancelled run fetched all %d assets", len(list))
	}
	// And the parallel ceiling held on the way out.
	if n := d.max.Load(); n > 8 {
		t.Errorf("ran %d fetches at once, want at most 8", n)
	}
}
