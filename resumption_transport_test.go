package gofire

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestTransportResumesAcrossRequests exercises the wiring between Transport and
// the TLS layer, which the ctls package's own tests cannot reach: the session
// cache lives on Transport, and the cache key is built from the network exit
// chosen during the dial.
//
// The handler reports r.TLS.DidResume, so this asserts what the server actually
// observed rather than an internal flag on our side.
func TestTransportResumesAcrossRequests(t *testing.T) {
	var (
		mu      sync.Mutex
		resumed []bool
	)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.TLS != nil {
			resumed = append(resumed, r.TLS.DidResume)
		}
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	c, err := Emulate(Chrome150, WithRootCAs(pool))
	if err != nil {
		t.Fatalf("emulate: %v", err)
	}
	defer c.Close()

	const rounds = 3
	for i := 0; i < rounds; i++ {
		resp, err := c.Get(srv.URL + "/")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if _, err := resp.Bytes(); err != nil {
			t.Fatalf("request %d body: %v", i, err)
		}
		resp.Close()
		// Drop the pooled connection so the next request must handshake again;
		// otherwise every request rides the first connection and resumption
		// never gets exercised.
		c.Close()
	}

	mu.Lock()
	defer mu.Unlock()

	if len(resumed) != rounds {
		t.Fatalf("server handled %d TLS requests, want %d", len(resumed), rounds)
	}
	if resumed[0] {
		t.Error("first connection resumed with an empty cache")
	}
	for i := 1; i < rounds; i++ {
		if !resumed[i] {
			t.Errorf("connection %d did not resume; the ticket issued on the "+
				"previous connection was not reused", i)
		}
	}
}
