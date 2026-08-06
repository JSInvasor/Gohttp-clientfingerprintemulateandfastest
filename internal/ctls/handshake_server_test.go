package ctls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// The alert tests in handshake_alert_test.go hand-build the records they feed
// the client, which pins the parsing but proves nothing about what a real
// server puts on the wire. These two run against crypto/tls instead, so the
// alert bytes and the ServerHello flight are produced by a TLS stack that is
// not ours.
//
// They deliberately do not reach the network. A handshake against a public
// host looks like the strongest possible check and is the weakest available
// one: any sandbox, CI runner or corporate network that terminates TLS answers
// with its own certificate, so the test passes without the intended server
// ever seeing the ClientHello.

// selfSignedCert builds a throwaway localhost leaf for the test servers.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
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
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshakeAgainst runs one handshake against a local crypto/tls server.
func handshakeAgainst(t *testing.T, cfg *tls.Config) error {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		srv := tls.Server(conn, cfg)
		srv.Handshake()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tlsConn, err := WrapConn(ctx, conn, "localhost", []string{"h2"}, true, nil, BrowserChrome)
	if err == nil {
		tlsConn.Close()
	}
	<-served
	return err
}

// TestRealServerAlertIsNamed pins the naming against alert bytes this package
// did not write. describeAlert is only useful if the description it is handed
// is the one the server actually sent, which a hand-built record cannot show.
func TestRealServerAlertIsNamed(t *testing.T) {
	// A server that cannot produce a certificate refuses the ClientHello with
	// a fatal alert rather than a ServerHello.
	err := handshakeAgainst(t, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("no certificate for this name")
		},
	})
	if err == nil {
		t.Fatal("handshake succeeded against a server with no certificate")
	}

	msg := err.Error()
	const prefix = "server alert: "
	i := strings.Index(msg, prefix)
	if i < 0 {
		t.Fatalf("rejection not reported as an alert: %q", msg)
	}

	// Which description the server picks is its own business; that it arrives
	// named rather than as a bare integer is this package's.
	desc := msg[i+len(prefix):]
	if !strings.Contains(desc, "(") || !strings.Contains(desc, ")") {
		t.Fatalf("alert description is not named: %q", msg)
	}
	t.Logf("server rejected with %s", desc)
}

// TestRealServerHandshakeCompletes is the false-positive half: readRawRecord
// rejects headers that are not TLS, and a rule that strict has to be shown not
// to reject a server that is behaving.
func TestRealServerHandshakeCompletes(t *testing.T) {
	if err := handshakeAgainst(t, &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}); err != nil {
		t.Fatalf("healthy TLS 1.3 handshake failed: %v", err)
	}
}
