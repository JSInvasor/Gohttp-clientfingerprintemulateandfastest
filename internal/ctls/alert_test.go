package ctls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestReceivedAlertIgnoresLevel is the core of RFC 8446 §6.2: the level byte
// carries no meaning in TLS 1.3, so an error alert has to be fatal whichever
// level it was sent at.
//
// Trusting the level meant a server that aborted at warning level was silently
// skipped. During the handshake the loop kept reading and reported "server sent
// 64 records without a server hello"; afterwards Conn.Read spun to its deadline.
// Either way the caller never saw the reason the peer actually gave.
func TestReceivedAlertIgnoresLevel(t *testing.T) {
	for _, level := range []uint8{alertLevelWarning, alertLevelFatal} {
		for _, desc := range []uint8{
			alertHandshakeFailure, alertIllegalParameter, alertInternalError,
			alertUnrecognizedName, alertBadRecordMAC, alertProtocolVersion,
		} {
			_, err := receivedAlert([]byte{level, desc})
			if err == nil {
				t.Fatalf("alert %s at level %d was ignored", alertName(desc), level)
			}
			var pa *peerAlert
			if !errors.As(err, &pa) {
				t.Fatalf("alert %s: got %T, want *peerAlert", alertName(desc), err)
			}
			if pa.desc != desc {
				t.Fatalf("alert description = %d, want %d", pa.desc, desc)
			}
		}
	}
}

// TestReceivedAlertClosureAlerts pins the two exemptions §6.1 keeps. Everything
// else being fatal is only safe if these two are not.
func TestReceivedAlertClosureAlerts(t *testing.T) {
	for _, desc := range []uint8{alertCloseNotify, alertUserCanceled} {
		for _, level := range []uint8{alertLevelWarning, alertLevelFatal} {
			got, err := receivedAlert([]byte{level, desc})
			if err != nil {
				t.Fatalf("%s at level %d: %v", alertName(desc), level, err)
			}
			if got != desc {
				t.Fatalf("description = %d, want %d", got, desc)
			}
		}
	}
}

// TestReceivedAlertRejectsShortRecord covers the framing: a one-byte alert has
// no description to act on, and reading past it would be an out-of-range slice.
func TestReceivedAlertRejectsShortRecord(t *testing.T) {
	for _, body := range [][]byte{nil, {}, {alertLevelFatal}} {
		if _, err := receivedAlert(body); err == nil {
			t.Fatalf("%d-byte alert record accepted", len(body))
		}
	}
}

// TestAlertNamesAreReadable pins that the error text names the alert. "server
// alert: 47" gives no hint that a ClientHello field was rejected; the name does,
// and that is usually the whole diagnosis for a fingerprint regression.
func TestAlertNamesAreReadable(t *testing.T) {
	err := &peerAlert{desc: alertIllegalParameter}
	if !strings.Contains(err.Error(), "illegal_parameter") {
		t.Fatalf("alert error %q does not name the alert", err.Error())
	}
	if !strings.Contains(err.Error(), "47") {
		t.Fatalf("alert error %q dropped the numeric code", err.Error())
	}
	// An unassigned code still has to render without pretending to be known.
	if got := alertName(200); got != "alert(200)" {
		t.Fatalf("alertName(200) = %q", got)
	}
}

// TestAlertDescForPropagatesTaggedFailure checks the plumbing sendFatalAlert
// relies on: the alert to send is carried by the error, survives wrapping, and
// the innermost tag wins over one added higher up the stack.
func TestAlertDescForPropagatesTaggedFailure(t *testing.T) {
	inner := alertErrf(alertBadCertificate, "bad chain")
	if got := alertDescFor(inner); got != alertBadCertificate {
		t.Fatalf("alertDescFor = %d, want %d", got, alertBadCertificate)
	}

	wrapped := withAlert(alertInternalError, inner)
	if got := alertDescFor(wrapped); got != alertBadCertificate {
		t.Fatalf("outer tag overrode inner: got %s", alertName(got))
	}

	// An untagged failure is a generic negotiation abort.
	if got := alertDescFor(errors.New("something went wrong")); got != alertHandshakeFailure {
		t.Fatalf("untagged alertDescFor = %s, want handshake_failure", alertName(got))
	}
}

// TestHandshakeSendsFatalAlertOnBadCertificate is the end-to-end proof that a
// failing handshake tells the server why before hanging up.
//
// RFC 8446 §6 asks for the alert, but the reason it matters here is emulation:
// every browser answers an untrusted certificate with one, so a client that
// instead drops the TCP connection mid-flight is doing something no shipping
// browser does — visible to the peer, and logged by it.
//
// The server side is hand-rolled rather than crypto/tls because the point is to
// read the client's raw reaction to a chain it cannot verify.
func TestHandshakeSendsFatalAlertOnBadCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "localhost", key)

	// An empty pool trusts nothing, so verifyChain rejects the chain the
	// crypto/tls server presents and the handshake aborts after the server has
	// installed handshake keys — the encrypted-alert path.
	addr := startTestTLSServer(t, cert, key, "hello")

	raw, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	// Wrap the connection so the bytes the client writes can be inspected after
	// the handshake fails.
	rec := &recordingConn{Conn: raw}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = WrapConn(ctx, rec, "localhost", []string{"h2"}, false, x509.NewCertPool(), BrowserChrome)
	if err == nil {
		t.Fatal("handshake against an untrusted chain succeeded")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("unexpected failure: %v", err)
	}

	// The client must have written something after its ClientHello, and the
	// last record has to be the alert. Handshake keys already exist at the
	// point the chain is rejected, so it goes out encrypted and appears as an
	// application_data record rather than a type-21 one — which is what a real
	// client sends and what a server holding those keys expects.
	if len(rec.records) < 2 {
		t.Fatalf("client wrote %d records; the alert never went out", len(rec.records))
	}
	if last := rec.records[len(rec.records)-1].typ; last != recordTypeApplicationData {
		t.Fatalf("client's final record was type %d, want an encrypted alert", last)
	}
}

// TestHandshakeFatalAlertReachesTheServer confirms the alert is not merely
// written but arrives as a well-formed record the peer can parse.
//
// The server here answers the ClientHello with a plaintext record the client
// cannot use, so the failure happens before any keys exist and the alert goes
// out in the clear, where the test can read it byte for byte.
func TestHandshakeFatalAlertReachesTheServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		level, desc uint8
		err         error
	}
	got := make(chan result, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- result{err: err}
			return
		}
		defer conn.Close()

		// Read the ClientHello record off the wire.
		var hdr [recordHeaderLen]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			got <- result{err: err}
			return
		}
		clientHello := make([]byte, int(binary.BigEndian.Uint16(hdr[3:])))
		if _, err := io.ReadFull(conn, clientHello); err != nil {
			got <- result{err: err}
			return
		}
		// The session id has to be echoed, or the client rejects the hello for
		// that instead and the version check never runs.
		sessionID, err := clientHelloSessionID(clientHello)
		if err != nil {
			got <- result{err: err}
			return
		}

		// Answer with a ServerHello that negotiates TLS 1.2. The client offers
		// 1.3 only, so it aborts with protocol_version.
		random := make([]byte, 32)
		sh := serverHelloBytes(random, sessionID, cipherTLS_AES_128_GCM_SHA256,
			tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS12)))
		if err := writeRawRecord(conn, recordTypeHandshake, sh); err != nil {
			got <- result{err: err}
			return
		}

		// Read whatever the client says back.
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			got <- result{err: err}
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint16(hdr[3:])))
		if _, err := io.ReadFull(conn, body); err != nil {
			got <- result{err: err}
			return
		}
		if hdr[0] != recordTypeAlert {
			got <- result{err: errors.New("client replied with record type " + alertName(hdr[0]))}
			return
		}
		if len(body) < 2 {
			got <- result{err: errors.New("short alert record")}
			return
		}
		got <- result{level: body[0], desc: body[1]}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := WrapConn(ctx, raw, "localhost", []string{"h2"}, true, nil, BrowserSafari); err == nil {
		t.Fatal("handshake against a TLS 1.2 ServerHello succeeded")
	}

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("server side: %v", r.err)
		}
		// §6.2: error alerts are sent at fatal level even though the receiver
		// must not depend on that.
		if r.level != alertLevelFatal {
			t.Errorf("alert level = %d, want %d (fatal)", r.level, alertLevelFatal)
		}
		if r.desc != alertProtocolVersion {
			t.Errorf("alert = %s, want protocol_version", alertName(r.desc))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no alert reached the server")
	}
}

// TestNoAlertOnNetworkFailure checks the other half of the rule: when the
// connection itself died there is nobody to tell, and a read that timed out
// leaves an expired deadline behind, so attempting the write would only add a
// pointless syscall to every failed dial.
func TestNoAlertOnNetworkFailure(t *testing.T) {
	for name, err := range map[string]error{
		"eof":            io.EOF,
		"unexpected eof": io.ErrUnexpectedEOF,
		"closed":         net.ErrClosed,
		"timeout":        &net.OpError{Op: "read", Err: timeoutError{}},
		"handshake shut": errHandshakeClosed,
	} {
		if !isNetworkFailure(err) {
			t.Errorf("%s: treated as a protocol failure", name)
		}
	}
	if isNetworkFailure(alertErrf(alertIllegalParameter, "bad field")) {
		t.Error("a protocol failure was treated as a network failure")
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
