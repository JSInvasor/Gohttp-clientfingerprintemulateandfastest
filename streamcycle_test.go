package gofire

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Connection cycling is a fingerprint property, not a resource one.
//
// A browser does not run a hundred thousand streams over one HTTP/2 connection.
// It cycles on idle and lifetime, so its stream IDs stay in the low thousands;
// a client that never cycles presents a single long monotonic sequence, which is
// visible to anything counting. MaxStreamsPerConn is what keeps this client in
// the browser's range, and until now nothing checked that it does anything at
// all — the implementation is one clause inside idleStateLocked in the vendored
// transport, exactly the kind of thing an upstream re-apply drops.

// countingListener records how many connections were accepted.
type countingListener struct {
	net.Listener
	mu sync.Mutex
	n  int
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.n++
		l.mu.Unlock()
	}
	return c, err
}

func (l *countingListener) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n
}

func newCountingH2Server(t *testing.T) (*httptest.Server, *countingListener) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	counter := &countingListener{Listener: srv.Listener}
	srv.Listener = counter
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, counter
}

// With a cap set, one connection must not carry every request.
func TestMaxStreamsPerConnCyclesTheConnection(t *testing.T) {
	srv, counter := newCountingH2Server(t)

	const cap = 4
	const requests = 24

	c, err := Emulate(Chrome151, WithInsecureSkipVerify(), WithMaxStreamsPerConn(cap))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer c.Close()

	for i := 0; i < requests; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		resp, err := c.DoWithContext(ctx, "GET", srv.URL+"/", nil, nil)
		cancel()
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if resp.Proto != "HTTP/2.0" {
			t.Fatalf("request %d used %s; this test is about HTTP/2 stream cycling", i, resp.Proto)
		}
		resp.Close()
	}

	// Stream IDs step by 2, and the cap is compared as nextStreamID > 2*cap+1,
	// so a connection retires after cap+1 streams rather than exactly cap. The
	// assertion stays well clear of that boundary: what must not happen is one
	// connection serving all 24.
	got := counter.count()
	if want := requests / (cap + 1); got < want {
		t.Errorf("%d requests with MaxStreamsPerConn=%d opened %d connections, want at least %d — "+
			"the cap is not retiring connections", requests, cap, got, want)
	}
	if got == 1 {
		t.Error("every request went over one connection: the stream-ID cap did nothing")
	}
}

// Without a cap, the connection is reused — the pool still works, and the cap is
// what changes the behaviour rather than something else in the dial path.
func TestWithoutACapTheConnectionIsReused(t *testing.T) {
	srv, counter := newCountingH2Server(t)

	c, err := Emulate(Chrome151, WithInsecureSkipVerify(), WithMaxStreamsPerConn(0))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer c.Close()

	for i := 0; i < 24; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		resp, err := c.DoWithContext(ctx, "GET", srv.URL+"/", nil, nil)
		cancel()
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Close()
	}

	if got := counter.count(); got != 1 {
		t.Errorf("24 requests with no cap opened %d connections, want 1: "+
			"something other than the cap is retiring them", got)
	}
}
