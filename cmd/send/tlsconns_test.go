package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// -tls=N pins an explicit connection count. It has to reach o.tlsConns without
// disturbing the load-shape dials it sits beside — a run that meant -c 100 and
// got 100 connections instead of 100 threads is the wrong shape.
func TestTLSFlagPinsExplicitCount(t *testing.T) {
	o, target, err := parseFlags([]string{"-tls=4", "https://site.com", "30s", "100"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if target != "https://site.com" {
		t.Errorf("target = %q", target)
	}
	if o.tlsConns != 4 {
		t.Errorf("tlsConns = %d, want 4", o.tlsConns)
	}
	// The dials next to it are untouched: 100 is still threads, not connections.
	if o.concurrency != 100 || o.duration != 30*time.Second {
		t.Errorf("-tls disturbed the dials: c=%d t=%s", o.concurrency, o.duration)
	}
}

// A bare -tls is the whole point of the flag: no number, "open as many as the
// machine allows". It must set the auto sentinel and, because it stands alone,
// must not swallow the URL or the dials that follow it.
func TestTLSFlagBareMeansAuto(t *testing.T) {
	o, target, err := parseFlags([]string{"-tls", "https://site.com", "30s", "100"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if target != "https://site.com" {
		t.Errorf("target = %q, want the URL kept as a positional", target)
	}
	if o.tlsConns != tlsConnsAuto {
		t.Errorf("bare -tls set tlsConns=%d, want auto (%d)", o.tlsConns, tlsConnsAuto)
	}
	if o.concurrency != 100 || o.duration != 30*time.Second {
		t.Errorf("bare -tls swallowed a dial: c=%d t=%s", o.concurrency, o.duration)
	}
	// Auto resolves to a real, positive per-session count.
	if got := o.tlsConnCount(); got < 1 {
		t.Errorf("auto -tls resolved to %d connections, want >= 1", got)
	}
}

// -tls=N with a nonsense value is rejected at parse, naming the flag. A bare -tls
// is the only way to the auto sentinel, so an explicit negative cannot reach it.
func TestTLSFlagRejectsBadCount(t *testing.T) {
	for _, bad := range []string{"-tls=-5", "-tls=0", "-tls=abc"} {
		_, _, err := parseFlags([]string{bad, "https://site.com"})
		if err == nil {
			t.Errorf("parseFlags accepted %s", bad)
			continue
		}
		if !strings.Contains(err.Error(), "-tls") {
			t.Errorf("%s: error %q does not name -tls", bad, err)
		}
	}
}

// warmConns is the one number the run pre-opens, and it is the larger of the two
// flags that ask for connections up front — so -tls alone stands up its count,
// -warmup alone still works, and giving both does not warm twice.
func TestWarmConns(t *testing.T) {
	tests := []struct {
		name   string
		warmup int
		tls    int
		want   int
	}{
		{"neither", 0, 0, 0},
		{"warmup only", 8, 0, 8},
		{"tls only", 0, 5, 5},
		{"tls larger", 3, 10, 10},
		{"warmup larger", 20, 4, 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := &options{warmup: tc.warmup, tlsConns: tc.tls}
			if got := o.warmConns(); got != tc.want {
				t.Errorf("warmConns() = %d, want %d", got, tc.want)
			}
		})
	}
}

// A bare -tls shares one file-descriptor budget across the sessions, so more
// sessions can only lower the per-session count, never raise it, and it never
// drops below one.
func TestAutoTLSConnsSharesBudgetAcrossSessions(t *testing.T) {
	one := (&options{sessions: 1}).autoTLSConns()
	many := (&options{sessions: 64}).autoTLSConns()
	if one < 1 || many < 1 {
		t.Fatalf("auto count fell below 1: one=%d many=%d", one, many)
	}
	if many > one {
		t.Errorf("more sessions raised the per-session count: 1->%d, 64->%d", one, many)
	}
}

// The dial has to actually open connections, not just park a number in the
// options. With -tls=N and nothing warming otherwise, the run stands up N TLS
// connections per session before the first request — the whole point of the
// flag. If it were ignored, warmConns would be 0 and nothing would be dialled.
func TestTLSFlagPreopensConnections(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	const want = 3
	o := &options{
		sessions: 1, concurrency: 1, count: 1,
		insecure: true, timeout: 10 * time.Second, maxBody: -1,
		tlsConns: want,
	}
	pool, err := newSessionPool(o, gofire.Chrome151, srv.URL)
	if err != nil {
		t.Fatalf("newSessionPool: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool.warm(ctx, srv.URL, o.warmConns(), o.tlsRate)

	if got := pool.sessions[0].client.ActiveConnections(); got < want {
		t.Errorf("-tls %d opened %d TLS connections, want at least %d", want, got, want)
	}
}

// -tls-rate reaches the warm. A bare -tls resolves to a five-figure count on a
// box with a raised fd limit, and every one of those used to be started at
// once; the flag is how a run says how fast to get there instead. Parsing it
// into a field nothing reads would leave the burst exactly as it was.
func TestTLSRateFlagPacesTheWarm(t *testing.T) {
	o, _, err := parseFlags([]string{"-tls=200", "-tls-rate", "500", "https://site.com", "30s"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if o.tlsRate != 500 {
		t.Fatalf("tlsRate = %d, want 500", o.tlsRate)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	const (
		want = 10
		rate = 10
	)
	ro := &options{
		sessions: 1, concurrency: 1, count: 1,
		insecure: true, timeout: 10 * time.Second, maxBody: -1,
		tlsConns: want, tlsRate: rate,
	}
	pool, err := newSessionPool(ro, gofire.Chrome151, srv.URL)
	if err != nil {
		t.Fatalf("newSessionPool: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	pool.warm(ctx, srv.URL, ro.warmConns(), ro.tlsRate)
	elapsed := time.Since(start)

	if got := pool.sessions[0].client.ActiveConnections(); got < want {
		t.Errorf("the paced warm opened %d connection(s), want %d", got, want)
	}
	// Ten at ten a second is a second's work against a loopback server that
	// hands back a handshake in microseconds. Half of it is the tolerance.
	if floor := 500 * time.Millisecond; elapsed < floor {
		t.Errorf("-tls-rate %d opened %d connection(s) in %s, want at least %s — the pace is not reaching the warm",
			rate, want, elapsed, floor)
	}
}

// A negative pace is a typo, not a request, and it has to be refused where the
// other dials are rather than becoming an unpaced warm three layers down.
func TestNegativeTLSRateIsRefused(t *testing.T) {
	if _, _, err := parseFlags([]string{"-tls-rate=-5", "https://site.com"}); err == nil {
		t.Error("-tls-rate -5 was accepted")
	} else if !strings.Contains(err.Error(), "-tls-rate") {
		t.Errorf("the error does not name the flag: %v", err)
	}
}
