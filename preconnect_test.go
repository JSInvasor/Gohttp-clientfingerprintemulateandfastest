package gofire

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newH2TestClient starts an HTTP/2 test server and a client that trusts it.
func newH2TestClient(t *testing.T, handler http.HandlerFunc) (*Client, string) {
	client, url, _, _ := newCountingH2TestClient(t, handler)
	return client, url
}

// newCountingH2TestClient is newH2TestClient plus counters for the connections
// the server accepted and the requests it served, so a test can tell "warmed a
// connection" apart from "sent a request".
func newCountingH2TestClient(t *testing.T, handler http.HandlerFunc) (c *Client, url string, conns, reqs *atomic.Int64) {
	t.Helper()

	conns = new(atomic.Int64)
	reqs = new(atomic.Int64)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		handler(w, r)
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	client, err := NewClient(WithRootCAs(roots))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(client.Close)

	return client, server.URL, conns, reqs
}

// TestPreConnectOpensRequestedConnections pins that PreConnect warms the number
// of connections it was asked for, keeps them, and sends no HTTP request while
// doing so.
//
// All three matter. The HTTP/2 pool hands a connection to any request with
// spare stream capacity, so firing n concurrent requests is not enough — they
// collapse onto one connection — and the request itself is a shape the emulated
// browser never produces. PreConnect dials explicitly and registers each
// connection with the pool instead, which is what <link rel="preconnect"> does.
func TestPreConnectOpensRequestedConnections(t *testing.T) {
	client, url, serverConns, serverReqs := newCountingH2TestClient(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const want = 5
	if err := client.PreConnect(ctx, url, want); err != nil {
		t.Fatalf("PreConnect: %v", err)
	}

	if got := client.ActiveConnections(); got < want {
		t.Fatalf("PreConnect(%d) opened %d TLS connections", want, got)
	}
	if got := serverConns.Load(); got < want {
		t.Errorf("server accepted %d connections, want %d — warmed connections "+
			"were dropped instead of pooled", got, want)
	}
	if got := serverReqs.Load(); got != 0 {
		t.Errorf("PreConnect sent %d HTTP request(s); it must warm the "+
			"connection without one", got)
	}

	// The warmed connections must be usable, not just counted.
	before := client.ActiveConnections()
	resp, err := client.GetWithContext(ctx, url)
	if err != nil {
		t.Fatalf("Get after PreConnect: %v", err)
	}
	resp.Close()
	if after := client.ActiveConnections(); after != before {
		t.Errorf("a request after PreConnect dialled again (%d -> %d); "+
			"the warmed connections were not reused", before, after)
	}
	if got := serverReqs.Load(); got != 1 {
		t.Errorf("server served %d requests, want exactly the 1 sent after warming", got)
	}
}
