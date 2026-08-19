package solver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWAF is an interstitial that belongs to nobody.
//
// It is shaped after a real one: a proof-of-work page served with a 403, its own
// markup, a title in no detector's regex, an inline script with no src to match,
// and a cookie issued by its own endpoint rather than by the edge. None of
// Cloudflare's markers appear anywhere in it — which is the point, because the
// solver used to read their absence as proof that the site had not challenged at
// all and give up in about a second.
//
// It also records what the page could observe about the client at the moment it
// submitted, which is the other half of what this file covers.
type fakeWAF struct {
	server *httptest.Server
	// solveAfter is how long the page "hashes" before it submits, standing in
	// for the proof-of-work. It is what decides whether anything had a chance to
	// move the pointer first.
	solveAfter time.Duration

	mu       sync.Mutex
	verified bool
	signals  wafSignals
}

type wafSignals struct {
	MouseMoves int `json:"mm"`
	ElapsedMS  int `json:"el"`
}

const wafCookie = "__ka_pass"

func newFakeWAF(t *testing.T, solveAfter time.Duration) *fakeWAF {
	t.Helper()
	w := &fakeWAF{solveAfter: solveAfter}
	mux := http.NewServeMux()

	// The endpoint the interstitial's own script posts its answer to. It issues
	// the cookie, under a name nothing in this repo knows about.
	mux.HandleFunc("/__ka/verify", func(rw http.ResponseWriter, r *http.Request) {
		var sig wafSignals
		_ = json.NewDecoder(r.Body).Decode(&sig)
		w.mu.Lock()
		w.verified = true
		w.signals = sig
		w.mu.Unlock()
		http.SetCookie(rw, &http.Cookie{Name: wafCookie, Value: "earned", Path: "/"})
		rw.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(wafCookie); err == nil && c.Value == "earned" {
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(rw, `<html><head><title>Hedef Site</title></head><body>content</body></html>`)
			return
		}

		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The refusal is the only thing about this page that says "not the page
		// you asked for" in a way anything but this vendor could read.
		rw.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(rw, `<html><head><title>site.example — bağlantı kontrol ediliyor</title></head>
<body>
  <div id="card"><div id="capca-grid"></div></div>
  <script>
  (function(){
    var moves = 0;
    window.addEventListener("mousemove", function(){ moves++; }, {passive:true});
    var started = Date.now();
    setTimeout(function(){
      fetch("/__ka/verify", {
        method: "POST",
        credentials: "same-origin",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({mm: moves, el: Date.now() - started})
      }).then(function(){ location.reload(); });
    }, %d);
  })();
  </script>
</body></html>`, w.solveAfter.Milliseconds())
	})

	w.server = httptest.NewServer(mux)
	t.Cleanup(w.server.Close)
	return w
}

func (w *fakeWAF) observed() (wafSignals, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.signals, w.verified
}

// A challenge with none of Cloudflare's markers still has to be waited out.
//
// This is the case the solver was blind to. Its detection was three Cloudflare
// questions — is there a cf_clearance, does the title match this regex, does the
// DOM carry one of these seven markers — and against anything else all three
// answer no, which the wait read as "never challenged". It returned in about a
// second, reported a site with no challenge, and left the whole budget unspent
// on a page that would have cleared itself given four more.
func TestSolvePassesANonCloudflareChallenge(t *testing.T) {
	requireBrowser(t)
	waf := newFakeWAF(t, 1500*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	start := time.Now()
	res, err := Solve(ctx, testOptions(t, waf.server.URL+"/", 60*time.Second), "")
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}

	if res.Status != StatusOK {
		t.Fatalf("status = %q (%s), want ok — the 403 interstitial cleared itself", res.Status, res.Error)
	}
	if !strings.Contains(res.Cookies, wafCookie+"=earned") {
		t.Errorf("cookies = %q, want the cookie the interstitial issued", res.Cookies)
	}
	if _, ok := waf.observed(); !ok {
		t.Error("the page never submitted: the solver did not leave it running long enough")
	}
	// The old code could only return before the page had a chance to solve.
	if time.Since(start) < waf.solveAfter {
		t.Errorf("returned in %s, before the interstitial could clear: it decided it was never challenged",
			time.Since(start))
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want the first one to have worked", res.Attempts)
	}
}

// The behaviour a challenge scores has to happen while it is still deciding.
//
// The choreography used to run only after a clearance was in hand, which is
// right for what it was written for and useless to a challenge that samples the
// seconds before its verdict. A page that reads mouseMoveCount and submits when
// its own work finishes saw a pointer that had never moved.
func TestChallengeSeesActivityBeforeItDecides(t *testing.T) {
	requireBrowser(t)
	// Long enough that the drift has room to act, short enough to stay a test.
	waf := newFakeWAF(t, 2500*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	res, err := Solve(ctx, testOptions(t, waf.server.URL+"/", 60*time.Second), "")
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %q (%s), want ok", res.Status, res.Error)
	}

	sig, ok := waf.observed()
	if !ok {
		t.Fatal("the page never submitted, so it observed nothing")
	}
	if sig.MouseMoves == 0 {
		t.Errorf("the challenge saw %d mouse moves before it decided; "+
			"the behaviour simulation is running after the verdict, not during it", sig.MouseMoves)
	}
}
