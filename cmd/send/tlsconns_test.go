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

// -tls is the connection count as its own dial. It has to reach o.tlsConns
// without disturbing the load-shape dials it sits beside — a run that meant
// -c 100 and got 100 connections instead of 100 threads is the wrong shape.
func TestTLSFlagParses(t *testing.T) {
	o, target, err := parseFlags([]string{"-tls", "4", "https://site.com", "30s", "100"})
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

// A negative count is nonsense, and the equals form is what reaches the check —
// `-tls -1` is taken as the flag followed by another flag, the same quirk the
// positional tests document for a bare negative.
func TestTLSFlagRejectsNegative(t *testing.T) {
	_, _, err := parseFlags([]string{"-tls=-1", "https://site.com"})
	if err == nil {
		t.Fatal("parseFlags accepted -tls=-1")
	}
	if !strings.Contains(err.Error(), "-tls") {
		t.Errorf("error %q does not name -tls", err)
	}
}

// warmConns is the one number the run pre-opens, and it is the larger of the
// two flags that ask for connections up front — so -tls alone stands up its
// count, -warmup alone still works, and giving both does not warm twice.
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

// The dial has to actually open connections, not just park a number in the
// options. With -tls N and nothing warming otherwise, the run stands up N TLS
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
	pool.warm(ctx, srv.URL, o.warmConns())

	if got := pool.sessions[0].client.ActiveConnections(); got < want {
		t.Errorf("-tls %d opened %d TLS connections, want at least %d", want, got, want)
	}
}
