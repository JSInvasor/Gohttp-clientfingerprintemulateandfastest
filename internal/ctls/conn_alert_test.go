package ctls

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// newTestConnWithRecords builds a Conn fed by the records build seals, using a
// matched AEAD pair so they decrypt. It is enough to exercise Read's record
// dispatch without standing up a handshake.
func newTestConnWithRecords(t testing.TB, build func(seal func(plaintext []byte, innerType uint8))) *Conn {
	t.Helper()
	send, recv := newTestRecordPair(t)
	var wire []byte
	build(func(plaintext []byte, innerType uint8) {
		record, err := send.sealRecord(nil, plaintext, innerType)
		if err != nil {
			t.Fatalf("sealRecord: %v", err)
		}
		wire = append(wire, record...)
	})
	return &Conn{
		br:           bufio.NewReader(bytes.NewReader(wire)),
		serverReader: recv,
	}
}

// TestConnReadTreatsWarningAlertsAsFatal is the post-handshake half of RFC 8446
// §6.2. The level byte means nothing in TLS 1.3, so an error alert has to end
// the read whichever level it arrived at.
//
// Reading the level instead meant a server tearing the connection down at
// warning level was skipped here: the loop kept reading, and the caller saw the
// read spin to its deadline — or trip the no-progress ceiling — rather than the
// reason the peer gave.
func TestConnReadTreatsWarningAlertsAsFatal(t *testing.T) {
	for _, level := range []uint8{alertLevelWarning, alertLevelFatal} {
		c := newTestConnWithRecords(t, func(seal func([]byte, uint8)) {
			seal([]byte{level, alertInternalError}, recordTypeAlert)
		})

		n, err := c.Read(make([]byte, 16))
		if err == nil {
			t.Fatalf("level %d: alert ignored, read returned %d bytes", level, n)
		}
		if errors.Is(err, io.EOF) {
			t.Fatalf("level %d: internal_error surfaced as a clean EOF", level)
		}
		if !strings.Contains(err.Error(), "internal_error") {
			t.Fatalf("level %d: error %q does not name the alert", level, err)
		}
	}
}

// TestConnReadCloseNotifyIsEOF pins the exemption that makes the rule above
// safe. net/http ends a Content-Length-less HTTP/1.1 body on io.EOF and treats
// anything else as a truncated response, so reporting close_notify as an error
// would corrupt every connection-close-delimited body.
func TestConnReadCloseNotifyIsEOF(t *testing.T) {
	for _, level := range []uint8{alertLevelWarning, alertLevelFatal} {
		c := newTestConnWithRecords(t, func(seal func([]byte, uint8)) {
			seal([]byte("body"), recordTypeApplicationData)
			seal([]byte{level, alertCloseNotify}, recordTypeAlert)
		})

		buf := make([]byte, 16)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("level %d: first read: %v", level, err)
		}
		if string(buf[:n]) != "body" {
			t.Fatalf("level %d: payload = %q", level, buf[:n])
		}
		if _, err := c.Read(buf); !errors.Is(err, io.EOF) {
			t.Fatalf("level %d: close_notify surfaced as %v, want io.EOF", level, err)
		}
	}
}

// TestConnReadIgnoresUserCanceled covers the other closure alert. §6.1 has it
// precede a close_notify, so it must not end the read on its own.
func TestConnReadIgnoresUserCanceled(t *testing.T) {
	c := newTestConnWithRecords(t, func(seal func([]byte, uint8)) {
		seal([]byte{alertLevelWarning, alertUserCanceled}, recordTypeAlert)
		seal([]byte("after"), recordTypeApplicationData)
	})

	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "after" {
		t.Fatalf("payload = %q, want %q", buf[:n], "after")
	}
}

// TestConnReadRejectsMalformedAlert checks the framing case: an alert record
// with no description byte used to fall through to the no-progress counter and
// be read past, which is a decode error being treated as a hiccup.
func TestConnReadRejectsMalformedAlert(t *testing.T) {
	c := newTestConnWithRecords(t, func(seal func([]byte, uint8)) {
		seal([]byte{alertLevelFatal}, recordTypeAlert)
	})
	if _, err := c.Read(make([]byte, 16)); err == nil {
		t.Fatal("one-byte alert record accepted")
	}
}

// TestKeyUpdateFloodIsBounded pins the ceiling on peer-driven rekeying.
//
// Each KeyUpdate costs two HKDF expansions and an AEAD setup, and the per-Read
// no-progress counter does not bound them because it resets on every byte of
// application data — so a peer could alternate one byte with a burst of updates
// indefinitely. Real servers rekey a handful of times over a connection's life.
func TestKeyUpdateFloodIsBounded(t *testing.T) {
	ks := newKeySchedule(cipherTLS_CHACHA20_POLY1305_SHA256)
	ks.deriveHandshakeSecrets(make([]byte, 32), make([]byte, 32))
	ks.deriveMasterSecrets(make([]byte, 32))

	// Each KeyUpdate rekeys the reader, so the sender has to advance its own
	// secret in lockstep or the second record simply fails to decrypt and the
	// ceiling is never reached.
	secret := ks.serverAppTraffic
	newWriter := func() *encryptedRecord {
		aead, iv, err := ks.makeTrafficKeys(secret)
		if err != nil {
			t.Fatalf("makeTrafficKeys: %v", err)
		}
		return newEncryptedRecord(aead, iv)
	}
	readerAEAD, readerIV, err := ks.makeTrafficKeys(secret)
	if err != nil {
		t.Fatalf("makeTrafficKeys: %v", err)
	}

	var wire []byte
	sender := newWriter()
	for i := 0; i < maxKeyUpdates*2; i++ {
		record, err := sender.sealRecord(nil, []byte{handshakeTypeKeyUpdate, 0, 0, 1, keyUpdateNotRequested}, recordTypeHandshake)
		if err != nil {
			t.Fatalf("sealRecord: %v", err)
		}
		wire = append(wire, record...)
		secret = hkdfExpandLabel(ks.h, secret, "traffic upd", nil, ks.h().Size())
		sender = newWriter()
	}

	c := &Conn{
		br:              bufio.NewReader(bytes.NewReader(wire)),
		serverReader:    newEncryptedRecord(readerAEAD, readerIV),
		ks:              ks,
		serverAppSecret: ks.serverAppTraffic,
		clientAppSecret: ks.clientAppTraffic,
	}

	_, err = c.Read(make([]byte, 16))
	if err == nil {
		t.Fatal("unbounded key_update flood accepted")
	}
	if !strings.Contains(err.Error(), "key_update") {
		t.Fatalf("error %q does not identify the flood", err)
	}
	if c.keyUpdates > maxKeyUpdates+1 {
		t.Fatalf("honoured %d key_updates, ceiling is %d", c.keyUpdates, maxKeyUpdates)
	}
}

// deadlineConn records the deadlines set on it and fails every read, so a
// handshake against it ends immediately with the deadlines still observable.
type deadlineConn struct {
	net.Conn
	deadlines []time.Time
}

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, t)
	return nil
}
func (c *deadlineConn) SetReadDeadline(time.Time) error  { return nil }
func (c *deadlineConn) SetWriteDeadline(time.Time) error { return nil }
func (c *deadlineConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *deadlineConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *deadlineConn) Close() error                     { return nil }

// TestWrapConnAlwaysSetsADeadline covers the one path that had no bound at all.
//
// Every other ceiling in this package limits work rather than wall clock, so a
// peer that completes the TCP handshake and then goes quiet — a black-holing
// edge, a stalled proxy, a tarpit — held the dialing goroutine forever whenever
// the caller's context carried no deadline, which is what http.NewRequest
// without a client timeout produces.
func TestWrapConnAlwaysSetsADeadline(t *testing.T) {
	t.Run("no context deadline", func(t *testing.T) {
		c := &deadlineConn{}
		before := time.Now()
		if _, err := WrapConn(context.Background(), c, "example.com", []string{"h2"}, true, nil, BrowserChrome); err == nil {
			t.Fatal("handshake against a dead connection succeeded")
		}
		if len(c.deadlines) == 0 {
			t.Fatal("no deadline was installed for a context without one")
		}
		got := c.deadlines[0]
		if got.IsZero() {
			t.Fatal("the installed deadline was the zero value, which clears it")
		}
		if slack := got.Sub(before); slack > DefaultHandshakeTimeout+time.Second {
			t.Fatalf("deadline is %v out, want about %v", slack, DefaultHandshakeTimeout)
		}
	})

	// A caller that does set a deadline must keep it: the default is a backstop,
	// never an extension.
	t.Run("context deadline wins", func(t *testing.T) {
		want := time.Now().Add(2 * time.Second)
		ctx, cancel := context.WithDeadline(context.Background(), want)
		defer cancel()

		c := &deadlineConn{}
		if _, err := WrapConn(ctx, c, "example.com", []string{"h2"}, true, nil, BrowserChrome); err == nil {
			t.Fatal("handshake against a dead connection succeeded")
		}
		if len(c.deadlines) == 0 || !c.deadlines[0].Equal(want) {
			t.Fatalf("deadline = %v, want the context's %v", c.deadlines, want)
		}
	})
}
