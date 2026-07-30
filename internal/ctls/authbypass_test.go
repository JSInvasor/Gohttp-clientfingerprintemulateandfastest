package ctls

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestCertificateVerifySignatureIsChecked proves the client authenticates the
// server, not merely that the server presented a chain that happens to be valid.
//
// The rogue server below presents a genuine, correctly-chaining certificate for
// example.com but signs CertificateVerify with 64 random bytes. Certificates are
// public data — anyone can fetch a site's leaf from a CT log or by connecting to
// it — so possession of the chain proves nothing. CertificateVerify is the only
// step that proves the peer holds the matching private key. A client that skips
// it accepts any attacker who can route the traffic.
func TestCertificateVerifySignatureIsChecked(t *testing.T) {
	const host = "example.com"
	pool, leafDER, leafKey := testCertChain(t, host)

	// The genuine case guards the other direction: a signature-checking client
	// is worthless if the check is wrong and rejects real servers too.
	t.Run("genuine signature is accepted", func(t *testing.T) {
		conn, err := dialRogue(t, host, pool, leafDER, leafKey)
		if err != nil {
			t.Fatalf("handshake rejected a correctly signed CertificateVerify: %v", err)
		}
		conn.Close()
	})

	t.Run("forged signature is rejected", func(t *testing.T) {
		conn, err := dialRogue(t, host, pool, leafDER, nil)
		if err == nil {
			conn.Close()
			t.Fatal("SECURITY: handshake succeeded against a server that signed " +
				"CertificateVerify with random bytes. The server proved no possession " +
				"of the certificate's private key, so any party holding a public " +
				"certificate chain for the target host can complete a full MITM.")
		}
		t.Logf("rejected as expected: %v", err)
	})
}

// dialRogue runs one handshake against rogueServerHandshake. A nil signer makes
// the server forge the CertificateVerify signature.
func dialRogue(t *testing.T, host string, pool *x509.CertPool, leafDER []byte, signer *ecdsa.PrivateKey) (*Conn, error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		rogueServerHandshake(c, leafDER, signer)
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	raw.SetDeadline(time.Now().Add(15 * time.Second))

	conn, err := handshake(raw, &Config{
		ServerName: host,
		ALPN:       []string{"h2", "http/1.1"},
		RootCAs:    pool,
		Browser:    BrowserSafari,
	})
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// rogueServerHandshake speaks just enough TLS 1.3 to reach the point where the
// client decides whether to trust the peer. Everything is correct except the
// CertificateVerify signature, which is random.
func rogueServerHandshake(conn net.Conn, leafDER []byte, signer *ecdsa.PrivateKey) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	rec, err := readRawRecord(conn)
	if err != nil || rec.typ != recordTypeHandshake {
		return
	}
	chMsg := rec.data

	ksExt, ok := findExtension(chMsg, extKeyShare)
	if !ok {
		return
	}
	clientPub := clientX25519Share(ksExt)
	if clientPub == nil {
		return
	}

	// session_id sits right after legacy_version(2) + random(32).
	body := chMsg[4:]
	sidLen := int(body[34])
	sessionID := body[35 : 35+sidLen]

	srvPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	cPub, err := ecdh.X25519().NewPublicKey(clientPub)
	if err != nil {
		return
	}
	shared, err := srvPriv.ECDH(cPub)
	if err != nil {
		return
	}

	// --- ServerHello ---
	var srvRandom [32]byte
	if _, err := rand.Read(srvRandom[:]); err != nil {
		return
	}
	var sh []byte
	sh = appendUint16(sh, versionTLS12)
	sh = append(sh, srvRandom[:]...)
	sh = append(sh, byte(len(sessionID)))
	sh = append(sh, sessionID...)
	sh = appendUint16(sh, cipherTLS_AES_128_GCM_SHA256)
	sh = append(sh, 0x00) // compression: null

	var exts []byte
	exts = appendExt(exts, extSupportedVersions, []byte{0x03, 0x04})
	var kse []byte
	kse = appendUint16(kse, groupX25519)
	kse = appendUint16(kse, 32)
	kse = append(kse, srvPriv.PublicKey().Bytes()...)
	exts = appendExt(exts, extKeyShare, kse)

	sh = appendUint16(sh, uint16(len(exts)))
	sh = append(sh, exts...)

	shMsg := hsMsg(handshakeTypeServerHello, sh)
	if err := writeRawRecord(conn, recordTypeHandshake, shMsg); err != nil {
		return
	}

	// --- key schedule ---
	ks := newKeySchedule(cipherTLS_AES_128_GCM_SHA256)
	tr := ks.h()
	tr.Write(chMsg)
	tr.Write(shMsg)
	ks.deriveHandshakeSecrets(shared, tr.Sum(nil))

	aead, iv, err := ks.makeTrafficKeys(ks.serverHSTraffic)
	if err != nil {
		return
	}
	er := newEncryptedRecord(aead, iv)

	// --- EncryptedExtensions (empty list) ---
	ee := hsMsg(handshakeTypeEncryptedExtensions, []byte{0x00, 0x00})
	tr.Write(ee)

	// --- Certificate: a real, correctly-chaining leaf for the target host ---
	entry := make([]byte, 0, 3+len(leafDER)+2)
	entry = append(entry, byte(len(leafDER)>>16), byte(len(leafDER)>>8), byte(len(leafDER)))
	entry = append(entry, leafDER...)
	entry = append(entry, 0x00, 0x00) // per-cert extensions: none
	certBody := make([]byte, 0, 4+len(entry))
	certBody = append(certBody, 0x00) // certificate_request_context: empty
	certBody = append(certBody, byte(len(entry)>>16), byte(len(entry)>>8), byte(len(entry)))
	certBody = append(certBody, entry...)
	certMsg := hsMsg(handshakeTypeCertificate, certBody)
	tr.Write(certMsg)

	// --- CertificateVerify ---
	// With a signer we produce a real signature over the RFC 8446 §4.4.3
	// payload. Without one we emit 64 random bytes: the attacker holds the
	// public certificate but not its key.
	var sig []byte
	if signer != nil {
		digest := sha256.Sum256(certVerifyPayload(tr.Sum(nil)))
		sig, err = ecdsa.SignASN1(rand.Reader, signer, digest[:])
		if err != nil {
			return
		}
	} else {
		sig = make([]byte, 64)
		if _, err := rand.Read(sig); err != nil {
			return
		}
	}
	var cv []byte
	cv = appendUint16(cv, sigECDSAP256SHA256)
	cv = appendUint16(cv, uint16(len(sig)))
	cv = append(cv, sig...)
	cvMsg := hsMsg(handshakeTypeCertificateVerify, cv)
	tr.Write(cvMsg)

	// --- Finished: correct, an attacker can always compute this ---
	fk := ks.finishedKey(ks.serverHSTraffic)
	mac := computeFinishedMAC(ks.h, fk, tr.Sum(nil))
	finMsg := hsMsg(handshakeTypeFinished, mac)
	tr.Write(finMsg)

	blob := make([]byte, 0, len(ee)+len(certMsg)+len(cvMsg)+len(finMsg))
	blob = append(blob, ee...)
	blob = append(blob, certMsg...)
	blob = append(blob, cvMsg...)
	blob = append(blob, finMsg...)

	ct, err := er.encrypt(blob, recordTypeHandshake)
	if err != nil {
		return
	}
	writeRawRecord(conn, recordTypeApplicationData, ct)

	// Drain whatever the client sends back (CCS + client Finished) so its
	// writes don't block on a full socket buffer.
	buf := make([]byte, 4096)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

// hsMsg wraps body in a TLS handshake header.
func hsMsg(typ byte, body []byte) []byte {
	m := make([]byte, 4+len(body))
	m[0] = typ
	m[1] = byte(len(body) >> 16)
	m[2] = byte(len(body) >> 8)
	m[3] = byte(len(body))
	copy(m[4:], body)
	return m
}

// clientX25519Share pulls the X25519 entry out of a ClientHello key_share.
func clientX25519Share(ext []byte) []byte {
	if len(ext) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(ext))
	p := ext[2:]
	if n > len(p) {
		return nil
	}
	p = p[:n]
	for len(p) >= 4 {
		g := binary.BigEndian.Uint16(p)
		l := int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if l > len(p) {
			return nil
		}
		if g == groupX25519 && l == 32 {
			return p[:32]
		}
		p = p[l:]
	}
	return nil
}

// testCertChain returns a CA pool, a leaf certificate valid for host, and the
// leaf's private key. Tests that model an attacker take the DER and discard the
// key: certificates are public, private keys are what authentication rests on.
func testCertChain(t *testing.T, host string) (*x509.CertPool, []byte, *ecdsa.PrivateKey) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ctls test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, leafDER, leafKey
}
