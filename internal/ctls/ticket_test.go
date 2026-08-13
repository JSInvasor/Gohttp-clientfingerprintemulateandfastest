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
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// buildNST assembles a NewSessionTicket body the way a server would.
func buildNST(lifetime uint32, ageAdd uint32, nonce, ticket []byte, exts []byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, lifetime)
	b = binary.BigEndian.AppendUint32(b, ageAdd)
	b = append(b, byte(len(nonce)))
	b = append(b, nonce...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(ticket)))
	b = append(b, ticket...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(exts)))
	b = append(b, exts...)
	return b
}

func TestParseNewSessionTicket(t *testing.T) {
	nonce := []byte{1, 2, 3}
	ticket := bytes.Repeat([]byte{0xAB}, 64)
	body := buildNST(7200, 0xDEADBEEF, nonce, ticket, nil)

	lifetime, ageAdd, gotNonce, gotTicket, early, err := parseNewSessionTicket(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if lifetime != 2*time.Hour {
		t.Errorf("lifetime = %s, want 2h", lifetime)
	}
	if ageAdd != 0xDEADBEEF {
		t.Errorf("ageAdd = %#x", ageAdd)
	}
	if !bytes.Equal(gotNonce, nonce) || !bytes.Equal(gotTicket, ticket) {
		t.Error("nonce or ticket did not round trip")
	}
	if early {
		t.Error("early_data reported without the extension")
	}
}

// §4.6.1 caps ticket_lifetime at a week. A server claiming more is claiming
// something the protocol does not allow, and believing it would keep a dead
// credential in the cache for as long as the server felt like saying.
func TestParseNewSessionTicketCapsLifetime(t *testing.T) {
	body := buildNST(30*24*3600, 0, []byte{0}, []byte{1}, nil)
	lifetime, _, _, _, _, err := parseNewSessionTicket(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if lifetime != ticketLifetimeCap {
		t.Errorf("lifetime = %s, want the %s cap", lifetime, ticketLifetimeCap)
	}
}

func TestParseNewSessionTicketDetectsEarlyData(t *testing.T) {
	ext := binary.BigEndian.AppendUint16(nil, extEarlyData)
	ext = binary.BigEndian.AppendUint16(ext, 4)
	ext = binary.BigEndian.AppendUint32(ext, 16384)

	_, _, _, _, early, err := parseNewSessionTicket(buildNST(100, 0, nil, []byte{1}, ext))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !early {
		t.Error("early_data extension was not noticed")
	}
}

// A truncated ticket must be an error, never a partially-filled credential.
func TestParseNewSessionTicketRejectsMalformed(t *testing.T) {
	good := buildNST(100, 0, []byte{1, 2}, bytes.Repeat([]byte{9}, 16), nil)
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"header only", good[:6]},
		{"truncated nonce", good[:10]},
		{"truncated ticket", good[:len(good)-8]},
		{"no extensions length", good[:len(good)-2]},
		{"empty ticket", buildNST(100, 0, []byte{1}, nil, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, _, err := parseNewSessionTicket(tc.body); err == nil {
				t.Error("malformed ticket was accepted")
			}
		})
	}
}

func TestSessionCacheIsSingleUse(t *testing.T) {
	c := NewSessionCache(4)
	now := time.Now()
	tk := &sessionTicket{psk: []byte{1}, identity: []byte{2}, received: now, lifetime: time.Hour, suite: 0x1301}
	c.put("site.test", tk)

	if got := c.take("site.test", 0x1301, now); got == nil {
		t.Fatal("the ticket just stored was not returned")
	}
	// Offering the same ticket twice is a replay, which a server may refuse and
	// which looks like exactly what it is.
	if got := c.take("site.test", 0x1301, now); got != nil {
		t.Error("the same ticket was handed out twice")
	}
}

// A ticket carries a PSK derived under one hash. Offering it to a handshake
// that negotiates the other produces a binder the server cannot verify.
func TestSessionCacheKeyedBySuiteAndHost(t *testing.T) {
	c := NewSessionCache(4)
	now := time.Now()
	c.put("site.test", &sessionTicket{psk: []byte{1}, received: now, lifetime: time.Hour, suite: 0x1301})

	if c.take("site.test", 0x1302, now) != nil {
		t.Error("a ticket was reused under a different cipher suite")
	}
	if c.take("other.test", 0x1301, now) != nil {
		t.Error("a ticket was reused for a different host")
	}
	if c.take("site.test", 0x1301, now) == nil {
		t.Error("the matching lookup missed")
	}
}

func TestSessionCacheDropsExpired(t *testing.T) {
	c := NewSessionCache(4)
	now := time.Now()
	c.put("site.test", &sessionTicket{psk: []byte{1}, received: now.Add(-2 * time.Hour), lifetime: time.Hour, suite: 0x1301})

	if c.take("site.test", 0x1301, now) != nil {
		t.Error("an expired ticket was offered")
	}
	if n := c.Len(); n != 0 {
		t.Errorf("Len = %d after expiry, want 0", n)
	}
}

// A peer that sends thousands of tickets must not be handed unbounded memory.
func TestSessionCacheBounded(t *testing.T) {
	c := NewSessionCache(3)
	now := time.Now()
	for i := 0; i < 50; i++ {
		c.put("site.test", &sessionTicket{psk: []byte{byte(i)}, received: now, lifetime: time.Hour, suite: 0x1301})
	}
	if n := c.Len(); n != 3 {
		t.Errorf("held %d tickets, want the 3 the cache was sized for", n)
	}
	// Newest first: the most recent put must be the one handed back.
	if got := c.take("site.test", 0x1301, now); got == nil || got.psk[0] != 49 {
		t.Errorf("take returned %v, want the newest ticket", got)
	}
}

func TestObfuscatedAge(t *testing.T) {
	now := time.Now()
	tk := &sessionTicket{received: now.Add(-1500 * time.Millisecond), ageAdd: 1000}
	// 1500ms since receipt, plus the server's ageAdd.
	if got := tk.obfuscatedAge(now); got < 2400 || got > 2600 {
		t.Errorf("obfuscatedAge = %d, want ~2500", got)
	}
	// A clock that moved backwards must not underflow into a huge age.
	future := &sessionTicket{received: now.Add(time.Hour), ageAdd: 7}
	if got := future.obfuscatedAge(now); got != 7 {
		t.Errorf("obfuscatedAge with a backwards clock = %d, want the ageAdd alone", got)
	}
}

// End to end against a real TLS 1.3 server: the tickets it sends must land in
// the cache with a PSK derived from this connection's own transcript.
func TestTicketsArriveFromARealServer(t *testing.T) {
	cert, pool := testCert(t)
	srv := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				c.Read(buf)
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				// Hold the connection open long enough for the client to read
				// the tickets that follow the response.
				time.Sleep(300 * time.Millisecond)
			}(c)
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := WrapConn(t.Context(), raw, "127.0.0.1", []string{"http/1.1"}, false, pool, BrowserChrome)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	cache := NewSessionCache(8)
	conn.SetSessionCache(cache)

	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Read until the server closes; tickets ride the same stream as the body.
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && cache.Len() == 0 {
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}

	if cache.Len() == 0 {
		t.Fatal("no session ticket was stored from a server that sends them")
	}

	tk := cache.take("127.0.0.1", conn.suite, time.Now())
	if tk == nil {
		t.Fatal("the stored ticket was not retrievable under the negotiated suite")
	}
	if len(tk.psk) == 0 {
		t.Error("ticket stored without a derived PSK")
	}
	if len(tk.identity) == 0 {
		t.Error("ticket stored without an identity to send back")
	}
	if tk.lifetime <= 0 {
		t.Error("ticket stored with no lifetime")
	}
}

// testCert makes a self-signed cert for host and a pool that trusts it, so the
// end-to-end test exercises real certificate verification rather than skipping
// it — the handshake path under test is the verifying one.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
