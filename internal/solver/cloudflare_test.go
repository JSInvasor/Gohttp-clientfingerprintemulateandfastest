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
)

// A managed challenge, as close to the real shape as a local server gets.
//
// The fake edge in solve_test.go serves its interstitial with a 200, which is
// what an unprotected page looks like on the wire, and it clears itself on a
// timer. Neither is what a live Under Attack zone does: it answers with a 503,
// and a managed variant sits on a widget until something presses it. Both of
// those are exactly the parts of this that changed, so they get their own edge.
type cfEdge struct {
	server *httptest.Server
	// widget puts a Turnstile-shaped element on the page that has to be clicked
	// before anything is issued.
	widget bool

	mu      sync.Mutex
	cleared bool
	clicked bool
}

func newCFEdge(t *testing.T, widget bool) *cfEdge {
	t.Helper()
	e := &cfEdge{widget: widget}
	mux := http.NewServeMux()

	mux.HandleFunc("/cdn-cgi/challenge-platform/orchestrate/jsch/v1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
	})

	mux.HandleFunc("/cdn-cgi/challenge-platform/issue", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.cleared = true
		e.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "cf_clearance", Value: "earned-by-the-browser", Path: "/"})
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/cdn-cgi/challenge-platform/clicked", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.clicked = true
		e.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		cleared := e.cleared
		e.mu.Unlock()

		http.SetCookie(w, &http.Cookie{Name: "__cf_bm", Value: "bm-token", Path: "/"})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if cleared {
			fmt.Fprint(w, `<html><head><title>Target Site</title></head><body>content</body></html>`)
			return
		}

		// 503 is what an Under Attack zone answers with, and it is the signal
		// the wait now reads. The markers below are what it read before.
		w.WriteHeader(http.StatusServiceUnavailable)

		if e.widget {
			// The id prefix findTurnstileBox looks for. The click has to be a
			// real one — a shim calling .click() carries isTrusted false, and a
			// managed challenge is not fooled by it.
			fmt.Fprint(w, `<html><head><title>Just a moment...</title></head>
<body>
  <div id="challenge-stage"></div>
  <script src="/cdn-cgi/challenge-platform/orchestrate/jsch/v1"></script>
  <div id="cf-chl-widget-a1b2" style="width:300px;height:65px;background:#eee"></div>
  <script>
    window._cf_chl_opt = {cvId: "3"};
    document.getElementById("cf-chl-widget-a1b2").addEventListener("click", async (ev) => {
      if (!ev.isTrusted) return;
      await fetch("/cdn-cgi/challenge-platform/clicked", {credentials: "include"});
      await fetch("/cdn-cgi/challenge-platform/issue", {credentials: "include"});
      location.reload();
    });
  </script>
</body></html>`)
			return
		}

		fmt.Fprint(w, `<html><head><title>Just a moment...</title></head>
<body>
  <div id="challenge-stage"></div>
  <script src="/cdn-cgi/challenge-platform/orchestrate/jsch/v1"></script>
  <script>
    window._cf_chl_opt = {cvId: "3"};
    setTimeout(async () => {
      await fetch("/cdn-cgi/challenge-platform/issue", {credentials: "include"});
      location.reload();
    }, 1500);
  </script>
</body></html>`)
	})

	e.server = httptest.NewServer(mux)
	t.Cleanup(e.server.Close)
	return e
}

func (e *cfEdge) wasClicked() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clicked
}

// An Under Attack interstitial answers with a 503, which is a refusal — and the
// wait must not read a refusal as anything but "still in the way".
//
// This is the combination the generalisation had to not break: the status says
// challenge and so does the markup, and the clearance is what ends it.
func TestCloudflareUnderAttackStillSolves(t *testing.T) {
	requireBrowser(t)
	edge := newCFEdge(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	res, err := Solve(ctx, testOptions(t, edge.server.URL+"/", 60*time.Second), "")
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %q (%s), want ok on a 503 interstitial", res.Status, res.Error)
	}
	if !strings.Contains(res.Cookies, "cf_clearance=earned-by-the-browser") {
		t.Errorf("cookies = %q, want the clearance", res.Cookies)
	}
}

// A managed challenge sits on its widget until something presses it, and until
// now nothing did: the press was guarded by a condition that could not be true
// when it was reached. A zone like this consumed both attempts and every second
// of the budget, then reported no clearance.
func TestCloudflareManagedWidgetGetsClicked(t *testing.T) {
	requireBrowser(t)
	edge := newCFEdge(t, true)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	res, err := Solve(ctx, testOptions(t, edge.server.URL+"/", 60*time.Second), "")
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if !edge.wasClicked() {
		t.Fatal("the widget was never clicked, so the managed challenge never started")
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %q (%s), want ok once the widget is pressed", res.Status, res.Error)
	}
	if !strings.Contains(res.Cookies, "cf_clearance=earned-by-the-browser") {
		t.Errorf("cookies = %q, want the clearance the click earned", res.Cookies)
	}
}
