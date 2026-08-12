package gofire

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// blackHoleListener accepts connections and then reads without ever answering,
// which is how a black-holing edge, a stalled proxy or a tarpit behaves: the TCP
// handshake succeeds, so nothing at the dial layer notices, and the TLS
// handshake simply never progresses.
func blackHoleListener(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Drain the ClientHello and say nothing back.
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr()
}

// TestHandshakeTimeoutIsEnforced covers a bound that did not exist.
//
// net/http only applies Transport.TLSHandshakeTimeout inside its own addTLS
// path, and a custom DialTLSContext replaces that path outright — so setting the
// field did nothing, and the http2 transport has no equivalent knob at all. With
// no deadline on the request context, which is what http.NewRequest without a
// client timeout produces, a handshake against a peer that accepts and then goes
// quiet had nothing to stop it.
func TestHandshakeTimeoutIsEnforced(t *testing.T) {
	addr := blackHoleListener(t)

	cfg := defaultTransportConfig()
	cfg.TLSHandshakeTimeout = 250 * time.Millisecond
	tr := newTransport(cfg, SafariIOS18)

	// context.Background() on purpose: the point is that the transport bounds
	// this on its own, with no help from the caller.
	start := time.Now()
	conn, err := tr.dialTLS(context.Background(), "tcp", addr.String(), []string{"h2"})
	elapsed := time.Since(start)

	if err == nil {
		conn.Close()
		t.Fatal("handshake against a silent peer succeeded")
	}

	// dialTLS retries a timed-out handshake up to three times with a short
	// backoff, so the ceiling is a few times the per-attempt timeout — the
	// point is that it returns at all.
	if limit := 4 * cfg.TLSHandshakeTimeout; elapsed > limit {
		t.Fatalf("dial took %v, want under %v", elapsed, limit)
	}
	if !errors.Is(err, context.DeadlineExceeded) && !isTimeoutErr(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRequestContextDeadlineStillWins pins that the transport-level timeout is a
// backstop and never an extension: a caller asking for less keeps it.
func TestRequestContextDeadlineStillWins(t *testing.T) {
	addr := blackHoleListener(t)

	cfg := defaultTransportConfig()
	cfg.TLSHandshakeTimeout = 30 * time.Second
	tr := newTransport(cfg, SafariIOS18)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	conn, err := tr.dialTLS(ctx, "tcp", addr.String(), []string{"h2"})
	elapsed := time.Since(start)

	if err == nil {
		conn.Close()
		t.Fatal("handshake against a silent peer succeeded")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the context deadline was extended by the transport timeout: dial took %v", elapsed)
	}
}

func isTimeoutErr(err error) bool {
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}
