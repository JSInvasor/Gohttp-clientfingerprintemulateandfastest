package gofire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// The pace tests. Pre-warming used to start every connection at once, which at
// the counts this tool runs at — a bare -tls resolves to a five-figure number on
// a box with a raised fd limit — is a burst rather than a warm-up: tens of
// thousands of goroutines contending for the CPU the handshakes need, a tail
// that fails on a timeout measuring nothing but the size of the burst, and an
// arrival curve at the target that no browser produces.
//
// What is pinned here is that the burst is bounded whether or not the caller
// asks, that an explicit rate is honoured, that cancelling stops it, and that
// the count returned is what was actually opened.

// inFlight tracks a concurrent count and the high-water mark it reached.
type inFlight struct {
	now, peak atomic.Int64
}

func (f *inFlight) enter() {
	n := f.now.Add(1)
	for {
		peak := f.peak.Load()
		if n <= peak || f.peak.CompareAndSwap(peak, n) {
			return
		}
	}
}

func (f *inFlight) leave() { f.now.Add(-1) }

// newHandshakeCountingServer starts an h2 test server that counts how many TLS
// handshakes are in progress at once, holding each one long enough that a burst
// overlaps visibly.
//
// The count is taken in GetConfigForClient because that is the handshake itself:
// counting accepted connections would miss the overlap entirely, since a
// connection is only accepted once its handshake is through.
func newHandshakeCountingServer(t *testing.T, hold time.Duration) (url string, roots *x509.CertPool, flight *inFlight) {
	t.Helper()

	flight = new(inFlight)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			flight.enter()
			defer flight.leave()
			time.Sleep(hold)
			return nil, nil // nil keeps the server's own config
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	roots = x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return server.URL, roots, flight
}

func newClientFor(t *testing.T, roots *x509.CertPool) *Client {
	t.Helper()
	client, err := NewClient(WithRootCAs(roots))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

// TestPreConnectBoundsConcurrency pins the ceiling on simultaneous handshakes,
// and that the ceiling is the caller's to set.
//
// Both halves matter. A bound that is never approached would pass a test that
// only checked the ceiling, so the same warm is run unbounded on the same server
// and has to show a peak the bounded one never reaches — otherwise the bound is
// pinning nothing.
func TestPreConnectBoundsConcurrency(t *testing.T) {
	url, roots, flight := newHandshakeCountingServer(t, 20*time.Millisecond)

	const (
		want  = 40
		bound = 4
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	opened, err := newClientFor(t, roots).PreConnectWithConfig(ctx, url, want,
		PreConnectConfig{Concurrency: bound})
	if err != nil {
		t.Fatalf("bounded PreConnectWithConfig: %v", err)
	}
	if opened != want {
		t.Errorf("bounded warm opened %d connection(s), want %d", opened, want)
	}
	bounded := flight.peak.Load()
	if bounded > bound {
		t.Errorf("peak %d handshakes in flight, want at most %d (Concurrency %d)", bounded, bound, bound)
	}

	// The same warm with the default ceiling, which is well above the count.
	flight.peak.Store(0)
	if _, err := newClientFor(t, roots).PreConnectWithConfig(ctx, url, want, PreConnectConfig{}); err != nil {
		t.Fatalf("unbounded PreConnectWithConfig: %v", err)
	}
	if unbounded := flight.peak.Load(); unbounded <= bounded {
		t.Errorf("a warm with the default ceiling peaked at %d, no higher than the bounded one's %d — "+
			"the bound is not what is holding the burst down", unbounded, bounded)
	}
}

// TestPreConnectRateLimits pins that Rate is a per-second ceiling and not a
// suggestion. Only the lower bound on elapsed time is asserted: a slow machine
// may take longer, but no machine may go faster than the rate allows.
func TestPreConnectRateLimits(t *testing.T) {
	url, roots, _ := newHandshakeCountingServer(t, 0)

	const (
		rate = 20
		want = 30 // one and a half seconds' worth
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	start := time.Now()
	opened, err := newClientFor(t, roots).PreConnectWithConfig(ctx, url, want, PreConnectConfig{Rate: rate})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("PreConnectWithConfig: %v", err)
	}
	if opened != want {
		t.Errorf("opened %d connection(s), want %d", opened, want)
	}
	// The bucket starts empty and refills in slices, so 30 at 20/s cannot be
	// through in under a second and a half. Half of that is the tolerance, which
	// still fails an implementation that ignores the rate.
	if floor := 750 * time.Millisecond; elapsed < floor {
		t.Errorf("%d connection(s) at %d/s took %s, want at least %s", want, rate, elapsed, floor)
	}
}

// TestPreConnectStopsOnContextCancel pins that a cancelled warm gives up
// promptly and reports what it managed. Without it, interrupting a five-figure
// warm meant waiting out every remaining dial.
func TestPreConnectStopsOnContextCancel(t *testing.T) {
	url, roots, _ := newHandshakeCountingServer(t, 0)
	client := newClientFor(t, roots)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(200*time.Millisecond, cancel)

	type result struct{ opened int }
	done := make(chan result, 1)
	go func() {
		opened, _ := client.PreConnectWithConfig(ctx, url, 100000, PreConnectConfig{Rate: 10})
		done <- result{opened}
	}()

	select {
	case r := <-done:
		// 10/s for 200ms is a handful; anything near the count asked for means
		// the cancel was not being read.
		if r.opened > 100 {
			t.Errorf("a warm cancelled after 200ms at 10/s opened %d connection(s)", r.opened)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a cancelled warm did not return")
	}
}

// TestPreConnectReportsProgress pins the callback, which is the only thing
// between a long warm and a caller who cannot tell it from a hang.
func TestPreConnectReportsProgress(t *testing.T) {
	url, roots, _ := newHandshakeCountingServer(t, 0)

	const want = 6
	var (
		calls int
		last  int
		total int
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The callback is documented as serialised, so counting without a lock is
	// part of what this pins: a Progress that raced would trip the race detector
	// here rather than in a caller.
	if _, err := newClientFor(t, roots).PreConnectWithConfig(ctx, url, want, PreConnectConfig{
		Progress: func(opened, n int) {
			calls++
			last = opened
			total = n
		},
	}); err != nil {
		t.Fatalf("PreConnectWithConfig: %v", err)
	}

	// The final call is guaranteed; the once-a-second ones are not, for a warm
	// this short.
	if calls < 1 {
		t.Fatal("Progress was never called")
	}
	if last != want {
		t.Errorf("the last Progress call reported %d opened, want %d", last, want)
	}
	if total != want {
		t.Errorf("Progress reported a total of %d, want %d", total, want)
	}
}
