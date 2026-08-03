package ctls

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestHandshakeRejectsNoProgressRecordFlood pins the ceiling on records that
// carry no handshake data.
//
// ChangeCipherSpec and warning alerts are both skipped with a `continue`, so a
// server that sends nothing else kept the handshake loop reading forever. Only
// the context deadline bounded it, which means a peer could hold a connection
// (and the goroutine driving it) for the whole dial budget while sending a
// trickle of meaningless records.
func TestHandshakeRejectsNoProgressRecordFlood(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Consume the ClientHello record so the client's write completes.
		var hdr [recordHeaderLen]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		length := int(hdr[3])<<8 | int(hdr[4])
		if _, err := io.ReadFull(conn, make([]byte, length)); err != nil {
			return
		}

		// Answer with nothing but ChangeCipherSpec, far past the budget.
		for i := 0; i < maxNoProgressRecords*4; i++ {
			if err := writeRawRecord(conn, recordTypeChangeCipherSpec, []byte{0x01}); err != nil {
				return
			}
		}
		// Hold the connection open so a client without a ceiling would keep
		// waiting rather than seeing EOF.
		time.Sleep(30 * time.Second)
	}()

	// A generous deadline: the point is that the ceiling trips well before it.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := WrapConn(ctx, conn, "example.com", []string{"h2"}, false, nil, BrowserSafari)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("handshake succeeded against a server that sent only ChangeCipherSpec")
		}
		if !strings.Contains(err.Error(), "without a server hello") {
			t.Fatalf("want the no-progress ceiling to trip, got: %v", err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("handshake was bounded by the deadline, not the record ceiling: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handshake never returned: the no-progress ceiling did not trip")
	}
}
