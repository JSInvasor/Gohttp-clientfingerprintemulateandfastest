package gofire

import (
	"context"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"
)

// silentProxy accepts the TCP connection and then says nothing at all — the
// peer that "completes the connection and goes quiet".
func silentProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Accepted connections are held open and never written to. Closing one would
	// give the client an EOF, which is the case that already worked — the bug is
	// about a peer that stays connected and silent.
	var (
		mu   sync.Mutex
		held []net.Conn
	)
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	return ln.Addr().String()
}

// A proxy handshake has to be bounded even when the caller brought no deadline.
//
// Both proxy paths set a deadline only when the context already carried one, and
// nothing upstream guarantees that: net.Dialer.Timeout covers the TCP connect and
// stops there, and http.NewRequest with no client timeout produces a context with
// no deadline. So a proxy that accepted and went quiet hung the dial forever —
// the same hole wrapTLS was written to close one layer up.
func TestProxyHandshakeIsBoundedWithoutAContextDeadline(t *testing.T) {
	addr := silentProxy(t)

	cfg := defaultTransportConfig()
	cfg.TLSHandshakeTimeout = 300 * time.Millisecond
	tr := newTransport(cfg, Chrome151)

	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			u, err := url.Parse(scheme + "://" + addr)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			done := make(chan error, 1)
			start := time.Now()
			go func() {
				c, err := tr.dialViaProxy(context.Background(), "tcp", "example.com:443", u)
				if c != nil {
					c.Close()
				}
				done <- err
			}()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("a silent proxy produced a usable connection")
				}
				if elapsed := time.Since(start); elapsed > 5*time.Second {
					t.Errorf("took %s to give up on a silent proxy", elapsed)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("still blocked on a silent proxy with no context deadline")
			}
		})
	}
}

// A deadline the caller did bring still wins when it is the earlier of the two,
// so a per-request timeout is never extended by the bound above.
func TestProxyHandshakeHonoursTheCallersDeadline(t *testing.T) {
	addr := silentProxy(t)

	cfg := defaultTransportConfig()
	cfg.TLSHandshakeTimeout = 30 * time.Second
	tr := newTransport(cfg, Chrome151)

	u, err := url.Parse("socks5://" + addr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	c, err := tr.dialViaProxy(ctx, "tcp", "example.com:443", u)
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("a silent proxy produced a usable connection")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("waited %s, so the 30s bound overrode the caller's 300ms deadline", elapsed)
	}
}
