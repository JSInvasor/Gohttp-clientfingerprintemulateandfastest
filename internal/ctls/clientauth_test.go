package ctls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"
)

// startClientAuthServer runs a crypto/tls 1.3 server that asks every client for
// a certificate under the given policy.
func startClientAuthServer(t *testing.T, cert *x509.Certificate, key crypto.PrivateKey, auth tls.ClientAuthType, reply string) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   auth,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc := tls.Server(raw, cfg)
				defer sc.Close()
				if err := sc.Handshake(); err != nil {
					return
				}
				sc.Write([]byte(reply))
			}()
		}
	}()
	return ln.Addr()
}

// TestCertificateRequestAnsweredWithEmptyCertificate covers optional mTLS.
//
// A server set to RequestClientCert sends a CertificateRequest and is perfectly
// happy with an anonymous client — but only if that client answers. RFC 8446
// §4.4.2 makes the Certificate message mandatory once the request was sent, so
// a client that just sends Finished gets an unexpected_message alert. Ignoring
// the request is what the handshake used to do, and it broke every one of these
// sites even though none of them actually wanted a certificate.
func TestCertificateRequestAnsweredWithEmptyCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "localhost", key)
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	for _, browser := range []struct {
		name string
		b    BrowserType
	}{{"chrome", BrowserChrome}, {"safari", BrowserSafari}} {
		t.Run(browser.name, func(t *testing.T) {
			addr := startClientAuthServer(t, cert, key, tls.RequestClientCert, "anonymous-ok")

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			raw, err := net.Dial("tcp", addr.String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			conn, err := WrapConn(ctx, raw, "localhost", []string{"h2", "http/1.1"}, false, roots, browser.b)
			if err != nil {
				t.Fatalf("handshake against an optional-mTLS server failed: %v", err)
			}
			defer conn.Close()

			// Reading real data proves the Finished MAC agreed, which is the
			// part that breaks if the client's Certificate was left out of the
			// transcript rather than merely off the wire.
			got, err := io.ReadAll(conn)
			if err != nil && err != io.EOF {
				t.Fatalf("read: %v", err)
			}
			if string(got) != "anonymous-ok" {
				t.Fatalf("payload = %q, want %q", got, "anonymous-ok")
			}
		})
	}
}

// TestCertificateRequestWithHelloRetryRequest exercises both added flights at
// once: the retry rewrites the transcript with a synthetic message_hash, and the
// client Certificate is appended to that same transcript before Finished. A
// mistake in either shows up as a Finished MAC mismatch.
func TestCertificateRequestWithHelloRetryRequest(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "localhost", key)
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	cfg := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}},
		MinVersion:       tls.VersionTLS13,
		ClientAuth:       tls.RequestClientCert,
		CurvePreferences: []tls.CurveID{tls.CurveP384},
		NextProtos:       []string{"h2"},
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc := tls.Server(raw, cfg)
				defer sc.Close()
				if err := sc.Handshake(); err != nil {
					return
				}
				sc.Write([]byte("both"))
			}()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := WrapConn(ctx, raw, "localhost", []string{"h2"}, false, roots, BrowserChrome)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	got, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "both" {
		t.Fatalf("payload = %q, want %q", got, "both")
	}
}

// TestEmptyCertificateMessage pins the message layout, including the echoed
// certificate_request_context. Servers match the context to the request they
// sent, so a dropped or invented one is rejected.
func TestEmptyCertificateMessage(t *testing.T) {
	cases := map[string][]byte{
		"empty context":    {},
		"nonempty context": {0xDE, 0xAD, 0xBE, 0xEF},
	}

	for name, reqCtx := range cases {
		t.Run(name, func(t *testing.T) {
			msg := emptyCertificateMessage(reqCtx)

			if msg[0] != handshakeTypeCertificate {
				t.Fatalf("type = %d, want %d", msg[0], handshakeTypeCertificate)
			}
			bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
			if bodyLen != len(msg)-4 {
				t.Fatalf("header length %d does not match body %d", bodyLen, len(msg)-4)
			}

			body := msg[4:]
			if int(body[0]) != len(reqCtx) {
				t.Fatalf("context length = %d, want %d", body[0], len(reqCtx))
			}
			if !bytes.Equal(body[1:1+len(reqCtx)], reqCtx) {
				t.Fatal("context not echoed verbatim")
			}
			list := body[1+len(reqCtx):]
			if len(list) != 3 || list[0] != 0 || list[1] != 0 || list[2] != 0 {
				t.Fatalf("certificate_list = %x, want a zero length", list)
			}

			// It must also read back as a chain of zero certificates.
			certs, err := parseCertificate(body)
			if err != nil {
				t.Fatalf("parseCertificate: %v", err)
			}
			if len(certs) != 0 {
				t.Fatalf("parsed %d certificates, want 0", len(certs))
			}
		})
	}
}

// TestParseCertificateRequestContextRejectsMalformed keeps a hostile length from
// slicing out of range on the dial goroutine, which runs with no recover.
func TestParseCertificateRequestContextRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"context overruns": {0x10, 0x01, 0x02},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			if _, err := parseCertificateRequestContext(body); err == nil {
				t.Fatal("malformed certificate_request accepted")
			}
		})
	}
}
