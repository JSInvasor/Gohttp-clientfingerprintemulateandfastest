package ctls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// newTestCert issues a self-signed leaf for host, usable both as the presented
// certificate and as its own trust root.
func newTestCert(t *testing.T, host string, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{host},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// ecdsaCertVerify assembles a CertificateVerify body signing transcriptHash
// with key under ecdsa_secp256r1_sha256.
func ecdsaCertVerify(t *testing.T, key *ecdsa.PrivateKey, transcriptHash []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(certificateVerifyPayload(transcriptHash))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body := make([]byte, 4+len(sig))
	binary.BigEndian.PutUint16(body[0:2], sigECDSAP256SHA256)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(sig)))
	copy(body[4:], sig)
	return body
}

// TestCertificateVerifyAcceptsGenuineSignature is the positive control for the
// checks below: the same construction with the matching key must pass.
func TestCertificateVerifyAcceptsGenuineSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "example.com", key)
	transcript := sha256.Sum256([]byte("handshake transcript"))

	body := ecdsaCertVerify(t, key, transcript[:])
	if err := verifyCertificateVerify(body, cert, transcript[:]); err != nil {
		t.Fatalf("genuine signature rejected: %v", err)
	}
}

// TestCertificateVerifyRejectsAttackerWithoutPrivateKey covers the full-MITM
// case. A server's certificate chain is public, so an attacker in path can
// present the genuine chain for the requested name; what it cannot do is
// produce this signature. Chain validation and hostname matching both still
// succeed in this scenario, so this check is the only thing standing between
// the client and a transparently intercepted connection.
func TestCertificateVerifyRejectsAttackerWithoutPrivateKey(t *testing.T) {
	realKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	realCert := newTestCert(t, "example.com", realKey)

	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}

	transcript := sha256.Sum256([]byte("handshake transcript"))
	body := ecdsaCertVerify(t, attackerKey, transcript[:])

	if err := verifyCertificateVerify(body, realCert, transcript[:]); err == nil {
		t.Fatal("signature made with a key the certificate does not belong to was accepted")
	}
}

// TestCertificateVerifyRejectsReplayedSignature checks the transcript binding:
// a signature captured from one handshake must not validate in another.
func TestCertificateVerifyRejectsReplayedSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "example.com", key)

	captured := sha256.Sum256([]byte("transcript of an earlier handshake"))
	current := sha256.Sum256([]byte("transcript of this handshake"))

	body := ecdsaCertVerify(t, key, captured[:])
	if err := verifyCertificateVerify(body, cert, current[:]); err == nil {
		t.Fatal("signature over a different transcript was accepted")
	}
}

// TestCertificateVerifyRejectsPKCS1 pins the RFC 8446 §4.4.3 rule that
// RSASSA-PKCS1-v1_5 is not a legal scheme for signed handshake messages, even
// though it stays legal inside certificates.
func TestCertificateVerifyRejectsPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "example.com", key)
	transcript := sha256.Sum256([]byte("handshake transcript"))

	digest := sha256.Sum256(certificateVerifyPayload(transcript[:]))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body := make([]byte, 4+len(sig))
	binary.BigEndian.PutUint16(body[0:2], 0x0401) // rsa_pkcs1_sha256
	binary.BigEndian.PutUint16(body[2:4], uint16(len(sig)))
	copy(body[4:], sig)

	if err := verifyCertificateVerify(body, cert, transcript[:]); err == nil {
		t.Fatal("rsa_pkcs1_sha256 CertificateVerify was accepted")
	}
}

// TestCertificateVerifyRejectsCurveSubstitution pins the §4.2.3 rule that each
// ECDSA scheme is bound to one curve.
func TestCertificateVerifyRejectsCurveSubstitution(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "example.com", key)
	transcript := sha256.Sum256([]byte("handshake transcript"))

	body := ecdsaCertVerify(t, key, transcript[:])
	// Relabel the P-256 signature as the P-384 scheme.
	binary.BigEndian.PutUint16(body[0:2], sigECDSAP384SHA384)

	if err := verifyCertificateVerify(body, cert, transcript[:]); err == nil {
		t.Fatal("P-256 key was accepted under the P-384 scheme")
	}
}

// serverHelloBytes assembles a ServerHello handshake message.
func serverHelloBytes(random, sessionID []byte, suite uint16, exts []byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, random...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	msg := []byte{
		handshakeTypeServerHello,
		byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)),
	}
	return append(msg, body...)
}

func tlsExt(extType uint16, data []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, extType)
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	return append(out, data...)
}

// TestServerHelloParserRejectsHostileInput feeds ServerHello messages whose
// length fields point past the end of the buffer. Every one of these used to
// slice out of range, and because the handshake runs on the dial goroutine with
// no recover, a single malicious or corrupted server response took the whole
// process down with it.
func TestServerHelloParserRejectsHostileInput(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	random := make([]byte, 32)

	tls13 := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))

	// msgLen far beyond the buffer.
	oversizedMsgLen := serverHelloBytes(random, nil, cipherTLS_AES_128_GCM_SHA256, tls13)
	oversizedMsgLen[1], oversizedMsgLen[2], oversizedMsgLen[3] = 0xFF, 0xFF, 0xFF

	// Extensions block claiming more bytes than the message holds.
	oversizedExts := serverHelloBytes(random, nil, cipherTLS_AES_128_GCM_SHA256, tls13)
	binary.BigEndian.PutUint16(oversizedExts[len(oversizedExts)-len(tls13)-2:], 0xFFFF)

	// A single extension claiming more bytes than the block holds.
	badExtLen := serverHelloBytes(random, nil, cipherTLS_AES_128_GCM_SHA256,
		append(tls13, tlsExt(extKeyShare, nil)...))
	badExtLen[len(badExtLen)-1] = 0xFF // key_share length low byte

	// key_share whose key length runs past the extension.
	keyShare := tlsExt(extKeyShare, []byte{0x00, 0x1D, 0x04, 0x00})
	oversizedKeyShare := serverHelloBytes(random, nil, cipherTLS_AES_128_GCM_SHA256,
		append(append([]byte{}, tls13...), keyShare...))

	// session_id length pointing past the body.
	longSessionID := serverHelloBytes(random, nil, cipherTLS_AES_128_GCM_SHA256, tls13)
	longSessionID[4+2+32] = 0xFF

	cases := map[string][]byte{
		"empty":               {},
		"header only":         {handshakeTypeServerHello, 0, 0, 0},
		"oversized msgLen":    oversizedMsgLen,
		"oversized exts":      oversizedExts,
		"oversized ext":       badExtLen,
		"oversized key_share": oversizedKeyShare,
		"long session id":     longSessionID,
		"truncated body":      serverHelloBytes(random, nil, cipherTLS_AES_128_GCM_SHA256, tls13)[:20],
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			hs := &handshakeState{km: km, serverName: "example.com"}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseServerHello panicked: %v", r)
				}
			}()
			if _, _, _, err := hs.parseServerHello(data); err == nil {
				t.Fatal("malformed ServerHello accepted")
			}
		})
	}
}

// TestHelloRetryRequestDetected ensures an HRR is reported as such rather than
// parsed as an ordinary ServerHello, whose key_share layout it does not share.
func TestHelloRetryRequestDetected(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	hs := &handshakeState{km: km, serverName: "example.com"}

	tls13 := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))
	// An HRR key_share carries a bare group id, not a key.
	hrrKeyShare := tlsExt(extKeyShare, []byte{0x00, 0x17})
	msg := serverHelloBytes(helloRetryRequestRandom, nil, cipherTLS_AES_128_GCM_SHA256,
		append(append([]byte{}, tls13...), hrrKeyShare...))

	_, _, _, err = hs.parseServerHello(msg)
	if err == nil {
		t.Fatal("HelloRetryRequest parsed as a ServerHello")
	}
	if !strings.Contains(err.Error(), "HelloRetryRequest") {
		t.Fatalf("want a HelloRetryRequest diagnosis, got %v", err)
	}
}

// TestHandshakeReaderReassembles covers the record/message boundary mismatch
// RFC 8446 §5.1 allows. Certificate chains regularly exceed the 16 KiB record
// limit, so a message arriving in pieces has to be joined rather than rejected
// as truncated, and several messages sharing one record all have to be read.
func TestHandshakeReaderReassembles(t *testing.T) {
	t.Run("split across records", func(t *testing.T) {
		var hr handshakeReader
		payload := make([]byte, 100)
		msg := append([]byte{handshakeTypeCertificate, 0, 0, byte(len(payload))}, payload...)

		if err := hr.add(msg[:30]); err != nil {
			t.Fatalf("add: %v", err)
		}
		got, err := hr.next()
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if got != nil {
			t.Fatal("returned a message before all of its bytes arrived")
		}

		if err := hr.add(msg[30:]); err != nil {
			t.Fatalf("add: %v", err)
		}
		got, err = hr.next()
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if len(got) != len(msg) {
			t.Fatalf("reassembled %d bytes, want %d", len(got), len(msg))
		}
	})

	t.Run("coalesced in one record", func(t *testing.T) {
		var hr handshakeReader
		a := []byte{handshakeTypeEncryptedExtensions, 0, 0, 2, 0x00, 0x00}
		b := []byte{handshakeTypeFinished, 0, 0, 3, 0x01, 0x02, 0x03}
		if err := hr.add(append(append([]byte{}, a...), b...)); err != nil {
			t.Fatalf("add: %v", err)
		}
		for i, want := range [][]byte{a, b} {
			got, err := hr.next()
			if err != nil {
				t.Fatalf("next %d: %v", i, err)
			}
			if len(got) != len(want) || got[0] != want[0] {
				t.Fatalf("message %d = %v, want %v", i, got, want)
			}
		}
		got, err := hr.next()
		if err != nil || got != nil {
			t.Fatalf("next after last = %v, %v; want nil, nil", got, err)
		}
	})

	t.Run("rejects oversized message", func(t *testing.T) {
		var hr handshakeReader
		if err := hr.add([]byte{handshakeTypeCertificate, 0xFF, 0xFF, 0xFF}); err != nil {
			t.Fatalf("add: %v", err)
		}
		if _, err := hr.next(); err == nil {
			t.Fatal("a 16 MiB message length was accepted")
		}
	})
}

// startTestTLSServer runs a crypto/tls 1.3 server that writes reply and then
// closes cleanly with a close_notify.
func startTestTLSServer(t *testing.T, cert *x509.Certificate, key crypto.PrivateKey, reply string) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}},
		MinVersion:   tls.VersionTLS13,
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

// TestHandshakeEndToEnd drives the whole handshake against a real crypto/tls
// server, which is the only way to confirm the CertificateVerify signature is
// checked against a genuine signer rather than merely computed over the right
// bytes. It also pins that a clean close surfaces as io.EOF.
func TestHandshakeEndToEnd(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "localhost", key)
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	addr := startTestTLSServer(t, cert, key, "hello")

	for _, browser := range []struct {
		name string
		typ  BrowserType
	}{{"safari", BrowserSafari}, {"chrome", BrowserChrome}} {
		t.Run(browser.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			conn, err := DialWithConfig(ctx, "tcp", addr.String(), "localhost",
				[]string{"h2", "http/1.1"}, false, roots, browser.typ)
			if err != nil {
				t.Fatalf("handshake against a genuine server failed: %v", err)
			}
			defer conn.Close()

			if got := conn.ConnectionState().CipherSuite; got == 0 {
				t.Error("ConnectionState reports no cipher suite")
			}
			if len(conn.ConnectionState().PeerCertificates) == 0 {
				t.Error("ConnectionState reports no peer certificates")
			}

			buf := make([]byte, 64)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(buf[:n]) != "hello" {
				t.Fatalf("read %q, want %q", buf[:n], "hello")
			}

			// The server closed cleanly. net/http ends a
			// Content-Length-less body on io.EOF and treats anything else as
			// a truncated response.
			if _, err := conn.Read(buf); err != io.EOF {
				t.Fatalf("read after close_notify = %v, want io.EOF", err)
			}
		})
	}
}

// TestHandshakeRejectsUntrustedAndMismatchedNames confirms the verification
// path is actually reached and enforced.
func TestHandshakeRejectsUntrustedAndMismatchedNames(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "localhost", key)
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	addr := startTestTLSServer(t, cert, key, "hello")

	t.Run("untrusted root", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := DialWithConfig(ctx, "tcp", addr.String(), "localhost",
			[]string{"h2"}, false, x509.NewCertPool(), BrowserChrome)
		if err == nil {
			conn.Close()
			t.Fatal("certificate from an untrusted root was accepted")
		}
	})

	t.Run("wrong host", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := DialWithConfig(ctx, "tcp", addr.String(), "wrong.example",
			[]string{"h2"}, false, roots, BrowserChrome)
		if err == nil {
			conn.Close()
			t.Fatal("certificate for the wrong host was accepted")
		}
	})

	t.Run("skipVerify still connects", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := DialWithConfig(ctx, "tcp", addr.String(), "wrong.example",
			[]string{"h2"}, true, nil, BrowserChrome)
		if err != nil {
			t.Fatalf("skipVerify handshake failed: %v", err)
		}
		conn.Close()
	})
}

// TestConcurrentWriteAndClose exercises the clientWriter lock. http2 can call
// Close from a goroutine other than the one running the write loop, and the
// AEAD sequence number must advance exactly once per record: two records sealed
// under the same nonce both corrupt the stream and void the cipher's security.
// Run with -race.
func TestConcurrentWriteAndClose(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "localhost", key)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	addr := startTestTLSServer(t, cert, key, "hello")

	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		conn, err := DialWithConfig(ctx, "tcp", addr.String(), "localhost",
			[]string{"h2"}, false, roots, BrowserChrome)
		cancel()
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			for j := 0; j < 8; j++ {
				if _, err := conn.Write([]byte("payload")); err != nil {
					return
				}
			}
		}()
		conn.Close()
		<-done
	}
}
