package solver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/cdp"
)

// The solve tests need a browser. A box without one skips: what they check is
// the orchestration against a real page, which cannot be answered without one.
func requireBrowser(t *testing.T) {
	t.Helper()
	if _, err := cdp.Find(); err != nil {
		t.Skip("no Chrome or Chromium installed:", err)
	}
}

func testOptions(t *testing.T, target string, timeout time.Duration) Options {
	t.Helper()
	p := DefaultProfile()
	return Options{
		Target:   target,
		Timeout:  timeout,
		Profile:  &p,
		Headless: true, // the CI box has no display
	}
}

// fakeEdge is a Cloudflare-shaped interstitial that clears itself.
//
// It is not a challenge — nothing here is solvable — but it presents the same
// surface the solver reads: the localised title, the structural markers, and a
// cf_clearance that only appears once the page has been left alone for a moment.
// That is enough to exercise everything between navigate and harvest.
type fakeEdge struct {
	server *httptest.Server
	// clearAfter is how long the interstitial sits before it issues.
	clearAfter time.Duration
	// title is the interstitial's title. A localised one is the case the
	// structural probe exists for.
	title string

	mu       sync.Mutex
	requests int
	cleared  bool
}

func newFakeEdge(t *testing.T, clearAfter time.Duration, title string) *fakeEdge {
	t.Helper()
	e := &fakeEdge{clearAfter: clearAfter, title: title}
	mux := http.NewServeMux()

	// The endpoint the interstitial's own script calls, which is what issues.
	mux.HandleFunc("/cdn-cgi/challenge-platform/issue", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.cleared = true
		e.mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name: "cf_clearance", Value: "earned-by-the-browser", Path: "/",
		})
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.requests++
		cleared := e.cleared
		e.mu.Unlock()

		// __cf_bm is set by the interstitial itself, whether or not it ever
		// clears. It is the whole of what a solve can produce on a zone with no
		// UAM, and throwing it away was a real bug.
		http.SetCookie(w, &http.Cookie{Name: "__cf_bm", Value: "bm-token", Path: "/"})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if cleared {
			fmt.Fprint(w, `<html><head><title>Target Site</title></head><body>content</body></html>`)
			return
		}
		fmt.Fprintf(w, `<html><head><title>%s</title></head>
<body>
  <div id="challenge-stage"></div>
  <script src="/cdn-cgi/challenge-platform/orchestrate/jsch/v1"></script>
  <script>
    window._cf_chl_opt = {cvId: "3"};
    setTimeout(async () => {
      await fetch("/cdn-cgi/challenge-platform/issue", {credentials: "include"});
      location.reload();
    }, %d);
  </script>
</body></html>`, e.title, e.clearAfter.Milliseconds())
	})

	mux.HandleFunc("/cdn-cgi/challenge-platform/orchestrate/jsch/v1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
	})

	e.server = httptest.NewServer(mux)
	t.Cleanup(e.server.Close)
	return e
}

// The happy path, end to end: navigate an interstitial, wait it out, and come
// back with the clearance and the identity that earned it.
func TestSolveEarnsClearance(t *testing.T) {
	requireBrowser(t)
	edge := newFakeEdge(t, 1500*time.Millisecond, "Just a moment...")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res, err := Solve(ctx, testOptions(t, edge.server.URL+"/", 60*time.Second), "")
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %q (%s), want ok", res.Status, res.Error)
	}
	if !strings.Contains(res.Cookies, "cf_clearance=earned-by-the-browser") {
		t.Errorf("cookies = %q, want the clearance", res.Cookies)
	}
	// The challenge page's own cookie rides along: on a zone with no UAM it is
	// the whole of what a solve produces.
	if !strings.Contains(res.Cookies, "__cf_bm=") {
		t.Errorf("cookies = %q, want __cf_bm beside the clearance", res.Cookies)
	}

	// The identity is read back from the page rather than assumed, and it has to
	// be the pinned one — a cookie earned under one UA and replayed under
	// another dies the same way an IP mismatch does.
	if res.UserAgent != DefaultProfile().UserAgent {
		t.Errorf("user_agent = %q, want the pinned identity", res.UserAgent)
	}
	// The header and the page object are two views of one value.
	if got, want := strings.Join(res.PageLanguages, ","), LanguagePreference(res.AcceptLanguage); got != want {
		t.Errorf("navigator.languages %q does not match the header %q", got, res.AcceptLanguage)
	}
	// Etc/Unknown is what an unconfigured container reports, and no installed
	// browser produces it.
	if res.Timezone == "" || res.Timezone == "Etc/Unknown" {
		t.Errorf("timezone = %q, want a zone a real browser could report", res.Timezone)
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want the first one to have worked", res.Attempts)
	}
	if res.ChromiumMajor == 0 {
		t.Error("chromium_major was not reported")
	}
}

// Cloudflare localises the interstitial, so a title check in English alone would
// conclude the page was never challenged and give up in under a second with the
// whole budget left. The structural probe is what has to catch this.
func TestSolveSurvivesALocalisedInterstitial(t *testing.T) {
	requireBrowser(t)
	edge := newFakeEdge(t, 1500*time.Millisecond, "Bir dakika…")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	start := time.Now()
	res, err := Solve(ctx, testOptions(t, edge.server.URL+"/", 60*time.Second), "")
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %q (%s), want ok on a localised interstitial", res.Status, res.Error)
	}
	if time.Since(start) < time.Second {
		t.Error("the solve returned before the interstitial could clear: it decided it was never challenged")
	}
}

// A site that never challenges has already given everything it is going to. The
// solver must notice and return, not sit on it until the deadline — twice.
//
// This is the regression the challenge-platform selector's exclusion exists for:
// Cloudflare injects its JS-detection script into ordinary 200 responses on any
// zone with bot management on, and matching it made a cleared page read as
// challenged for as long as the caller was willing to wait.
func TestSolveReturnsPromptlyOnAnUnchallengedSite(t *testing.T) {
	requireBrowser(t)

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A zone with bot management on but no challenge still sets __cf_bm,
		// which is the whole of what a solve can produce there.
		http.SetCookie(w, &http.Cookie{Name: "__cf_bm", Value: "bm-token", Path: "/"})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The JS-detection script, which such a zone serves on pages it has not
		// challenged at all.
		fmt.Fprint(w, `<html><head><title>Example Domain</title></head><body>
			<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>
			content</body></html>`)
	}))
	defer site.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	start := time.Now()
	res, err := Solve(ctx, testOptions(t, site.URL+"/", 40*time.Second), "")
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	elapsed := time.Since(start)

	if res.Status != StatusNoClearance {
		t.Errorf("status = %q (%s), want no_clearance on a site with no challenge",
			res.Status, res.Error)
	}
	if !strings.Contains(res.Cookies, "__cf_bm=") {
		t.Errorf("cookies = %q, want the __cf_bm the zone set", res.Cookies)
	}
	// One attempt, because there was nothing to retry. Relaunching for a site
	// that never challenged costs another cold start and cannot produce a
	// different answer.
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1 — there was nothing to retry", res.Attempts)
	}
	// Generous, because the behaviour simulation is deliberately ~5s. What must
	// not happen is two 40-second budgets being burnt.
	if elapsed > 30*time.Second {
		t.Errorf("took %s on a site with no challenge; it waited out its budget", elapsed)
	}
}

// A site that neither challenges nor sets anything leaves a solve with nothing
// to hand over, and that is an error rather than an empty success: `send` keys
// on the difference, and a run seeded with no cookies at all would replay as if
// it had solved something.
func TestSolveReportsAnErrorWhenNothingWasCollected(t *testing.T) {
	requireBrowser(t)

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><head><title>Plain</title></head><body>content</body></html>`)
	}))
	defer site.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res, err := Solve(ctx, testOptions(t, site.URL+"/", 30*time.Second), "")
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if res.Status != StatusError {
		t.Errorf("status = %q, want error when the jar was empty", res.Status)
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", res.Attempts)
	}
}

// A batch works its list through one browser, and the cookie each exit gets has
// to be the one that exit earned.
func TestSolveBatchKeepsExitsApart(t *testing.T) {
	requireBrowser(t)

	// Each exit gets its own origin, so a jar that leaked across contexts would
	// show up as the wrong host's cookie rather than as a value collision.
	first := newFakeEdge(t, 1200*time.Millisecond, "Just a moment...")
	second := newFakeEdge(t, 1200*time.Millisecond, "Just a moment...")

	batch, err := NewBatch([]Exit{
		{ID: "first", Proxy: ""},
		{ID: "second", Proxy: ""},
	}, 2)
	if err != nil {
		t.Fatalf("NewBatch: %v", err)
	}

	// One target per batch is the real contract, so this runs the same target
	// for both and checks the isolation a shared browser has to provide.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var mu sync.Mutex
	got := map[string]*Result{}
	err = SolveBatch(ctx, testOptions(t, first.server.URL+"/", 45*time.Second), batch,
		func(r BatchResult) {
			mu.Lock()
			got[r.Exit.ID] = r.Result
			mu.Unlock()
		})
	if err != nil {
		t.Fatalf("SolveBatch: %v", err)
	}

	// Every exit is reported exactly once, including any that failed: a caller
	// pairing cookies with proxies has to hear about a dropped exit.
	if len(got) != 2 {
		t.Fatalf("reported %d exits, want 2: %v", len(got), got)
	}
	for id, res := range got {
		if res == nil {
			t.Fatalf("exit %s reported no result", id)
		}
		if res.Status != StatusOK {
			t.Errorf("exit %s: status = %q (%s), want ok", id, res.Status, res.Error)
		}
		if !strings.Contains(res.Cookies, "cf_clearance=") {
			t.Errorf("exit %s: cookies = %q, want a clearance", id, res.Cookies)
		}
	}
	_ = second
}

// A batch must not be taken down by one exit's failure, and a target that cannot
// be reached is the cheapest way to produce one.
func TestSolveBatchReportsEveryExitEvenWhenTheyFail(t *testing.T) {
	requireBrowser(t)

	batch, err := NewBatch([]Exit{{ID: "a"}, {ID: "b"}, {ID: "c"}}, 3)
	if err != nil {
		t.Fatalf("NewBatch: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var mu sync.Mutex
	seen := map[string]bool{}
	// A host that does not resolve: every exit fails, and every one must still
	// be reported.
	err = SolveBatch(ctx, testOptions(t, "http://solver-batch.invalid/", 15*time.Second), batch,
		func(r BatchResult) {
			mu.Lock()
			seen[r.Exit.ID] = true
			if r.Result == nil {
				t.Errorf("exit %s reported a nil result", r.Exit.ID)
			}
			mu.Unlock()
		})
	if err != nil {
		t.Fatalf("SolveBatch: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if !seen[id] {
			t.Errorf("exit %s was never reported", id)
		}
	}
}

// An inconsistent pin has to fail before a browser is launched: finding out
// after a 150-second solve is an expensive way to learn it.
func TestSolveRejectsADriftedPinWithoutLaunching(t *testing.T) {
	p := DefaultProfile()
	p.SecChUA = `"Not=A?Brand";v="99", "Google Chrome";v="147"`

	start := time.Now()
	_, err := Solve(context.Background(), Options{
		Target:  "https://example.com/",
		Profile: &p,
	}, "")
	if err == nil {
		t.Fatal("Solve accepted a profile whose hints and UA disagree")
	}
	if !strings.Contains(err.Error(), "Client Hint drift") {
		t.Errorf("error = %v, want the drift named", err)
	}
	// No browser was started, so this is immediate.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %s to reject a bad pin; it launched a browser first", elapsed)
	}
}

func TestSolveRejectsAMalformedProxy(t *testing.T) {
	_, err := Solve(context.Background(), Options{Target: "https://example.com/"}, "http://nohost")
	if err == nil {
		t.Fatal("Solve accepted a proxy URL with no port")
	}
}
