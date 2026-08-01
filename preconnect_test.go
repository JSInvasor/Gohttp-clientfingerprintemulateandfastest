package gofire

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newH2TestClient starts an HTTP/2 test server and a client that trusts it.
func newH2TestClient(t *testing.T, handler http.HandlerFunc) (*Client, string) {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())

	client, err := NewClient(WithRootCAs(roots))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(client.Close)

	return client, server.URL
}

// TestPreConnectOpensRequestedConnections pins that PreConnect actually warms
// the number of connections it was asked for.
//
// The HTTP/2 pool hands a connection to any request that still has stream
// capacity, so simply firing n concurrent HEADs is not enough: they can all
// land on one connection. PreConnect dials explicitly and registers each
// connection with the pool instead.
func TestPreConnectOpensRequestedConnections(t *testing.T) {
	client, url := newH2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
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
}
