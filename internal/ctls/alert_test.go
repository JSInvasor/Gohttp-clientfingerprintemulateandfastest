package ctls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAlertText(t *testing.T) {
	cases := []struct {
		desc uint8
		want string
	}{
		{alertHandshakeFailure, "handshake_failure (40)"},
		{alertProtocolVersion, "protocol_version (70)"},
		{alertUnrecognizedName, "unrecognized_name (112)"},
		{alertCertificateRequired, "certificate_required (116)"},
		{alertNoApplicationProtocol, "no_application_protocol (120)"},
		{alertCloseNotify, "close_notify (0)"},
		{200, "unknown (200)"},
	}
	for _, tc := range cases {
		if got := alertText(tc.desc); got != tc.want {
			t.Errorf("alertText(%d) = %q, want %q", tc.desc, got, tc.want)
		}
	}
}

func TestParseAlertLevels(t *testing.T) {
	// TLS 1.3 §6.1: everything except close_notify/user_canceled is fatal,
	// whatever the level byte claims.
	if fatal, _, _ := parseAlert([]byte{alertLevelWarning, alertUnrecognizedName}); !fatal {
		t.Error("warning-level unrecognized_name should be treated as fatal")
	}
	if fatal, _, _ := parseAlert([]byte{alertLevelWarning, alertCloseNotify}); fatal {
		t.Error("close_notify should not be fatal")
	}
	if _, _, ok := parseAlert([]byte{alertLevelFatal}); ok {
		t.Error("1-byte alert body should not parse")
	}
}

// alertRecord builds a plaintext alert record.
func alertRecord(level, desc uint8) []byte {
	rec := []byte{recordTypeAlert, 0x03, 0x03, 0x00, 0x02, level, desc}
	return rec
}

// serveAlert reads one ClientHello record off conn, writes the given bytes back,
// then closes. Returns the client half of the pipe.
func serveAlert(t *testing.T, reply []byte, closeAfter bool) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := readRawRecord(server); err != nil {
			return
		}
		server.Write(reply)
		if !closeAfter {
			// Hold the pipe open briefly so the client sees the record first.
			time.Sleep(50 * time.Millisecond)
		}
	}()
	t.Cleanup(func() { client.Close() })
	return client
}

func TestHandshakeFatalAlertNamed(t *testing.T) {
	conn := serveAlert(t, alertRecord(alertLevelFatal, alertHandshakeFailure), true)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err := handshake(conn, "example.com", []string{"h2"}, false, nil, BrowserChrome146)
	if err == nil {
		t.Fatal("expected handshake error, got nil")
	}
	if !strings.Contains(err.Error(), "server alert: handshake_failure (40)") {
		t.Fatalf("want named alert, got %q", err)
	}
	if strings.Contains(err.Error(), "expected handshake record") {
		t.Fatalf("record-type message should not mask the alert: %q", err)
	}
}

func TestHandshakeWarningAlertSurvivesEOF(t *testing.T) {
	// unrecognized_name as a warning, then the server just drops the socket -
	// the reason must not disappear behind the trailing EOF.
	conn := serveAlert(t, alertRecord(alertLevelWarning, alertUnrecognizedName), true)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err := handshake(conn, "example.com", []string{"h2"}, false, nil, BrowserChrome146)
	if err == nil {
		t.Fatal("expected handshake error, got nil")
	}
	if !strings.Contains(err.Error(), "unrecognized_name (112)") {
		t.Fatalf("warning alert lost, got %q", err)
	}
}

func TestHandshakeNonTLSReply(t *testing.T) {
	// A proxy answering CONNECT in cleartext used to surface as
	// "record too large: 20527 bytes" (the ASCII of "P/" in "HTTP/1.1").
	conn := serveAlert(t, []byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"), true)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err := handshake(conn, "example.com", []string{"h2"}, false, nil, BrowserChrome146)
	if err == nil {
		t.Fatal("expected handshake error, got nil")
	}
	if !strings.Contains(err.Error(), `not a TLS record: header 48 54 54 50 2f ("HTTP/")`) {
		t.Fatalf("want raw header in error, got %q", err)
	}
	if strings.Contains(err.Error(), "record too large") {
		t.Fatalf("length field should not be trusted for a non-TLS header: %q", err)
	}
}

func TestReadRawRecordAcceptsValidRecord(t *testing.T) {
	body := []byte{0x01, 0x02, 0x03}
	rec := []byte{recordTypeHandshake, 0x03, 0x01, 0x00, byte(len(body))}
	rec = append(rec, body...)

	got, err := readRawRecord(bytes.NewReader(rec))
	if err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if got.typ != recordTypeHandshake || !bytes.Equal(got.data, body) {
		t.Fatalf("got typ=%d data=%x, want typ=%d data=%x", got.typ, got.data, recordTypeHandshake, body)
	}
}

// selfSignedCert builds a throwaway leaf for the in-process test servers.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshakeAgainst runs one handshake against a local crypto/tls server, so the
// alert bytes come from a real TLS stack rather than a hand-built record.
func handshakeAgainst(t *testing.T, cfg *tls.Config) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		srv := tls.Server(conn, cfg)
		srv.Handshake()
		srv.Close()
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = handshake(raw, "localhost", []string{"h2", "http/1.1"}, true, nil, BrowserChrome146)
	return err
}

func TestRealServerAlertIsNamed(t *testing.T) {
	// Server cannot produce a certificate: it answers the ClientHello with a
	// fatal alert instead of a ServerHello.
	err := handshakeAgainst(t, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("no certificate for this name")
		},
	})
	if err == nil {
		t.Fatal("expected handshake error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "server alert: ") {
		t.Fatalf("alert not reported as such: %q", msg)
	}
	// The description must be named, not a bare number - that is the point of
	// the change. The exact code is the server's choice, so only assert shape.
	name := msg[strings.Index(msg, "server alert: ")+len("server alert: "):]
	if !strings.Contains(name, "(") || !strings.Contains(name, ")") {
		t.Fatalf("alert description not named: %q", msg)
	}
	t.Logf("server rejected with %s", name)
}

func TestRealServerHandshakeStillSucceeds(t *testing.T) {
	// Guards the tightened record header against false positives: a healthy
	// TLS 1.3 server must still complete the handshake.
	if err := handshakeAgainst(t, &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS13,
	}); err != nil {
		t.Fatalf("healthy TLS 1.3 handshake failed: %v", err)
	}
}

func TestReadRawRecordRejectsOversizeLength(t *testing.T) {
	rec := make([]byte, 5)
	rec[0] = recordTypeApplicationData
	binary.BigEndian.PutUint16(rec[1:], versionTLS12)
	binary.BigEndian.PutUint16(rec[3:], 16384+257)

	if _, err := readRawRecord(bytes.NewReader(rec)); err == nil ||
		!strings.Contains(err.Error(), "record too large") {
		t.Fatalf("want record too large, got %v", err)
	}
}
