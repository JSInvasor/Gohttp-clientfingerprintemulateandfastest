package ctls

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// TestSessionResumptionAgainstGoServer validates resumption against Go's
// crypto/tls server rather than a server written here.
//
// That distinction is the whole point. A PSK binder is an HMAC over a precisely
// specified transcript; if this package's understanding of that transcript were
// wrong, a server built from the same misunderstanding would happily agree and
// the test would prove nothing. crypto/tls is an independent implementation
// that validates binders strictly and aborts with decrypt_error on a mismatch,
// so a resumption it accepts is a resumption a real server accepts.
func TestSessionResumptionAgainstGoServer(t *testing.T) {
	const host = "localhost"
	pool, leafDER, leafKey := testCertChain(t, host)

	resumed := make(chan bool, 8)
	ln := startGoTLSServer(t, tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
	}, resumed)

	cache := NewSessionCache()
	cfg := func() *Config {
		return &Config{
			ServerName: host,
			ALPN:       []string{"h2"},
			RootCAs:    pool,
			Browser:    BrowserSafari,
			Sessions:   cache,
			SessionKey: host,
		}
	}

	// First connection: full handshake, and the server hands out tickets right
	// after its Finished. Reading is what absorbs them.
	c1 := dialCtls(t, ln.Addr().String(), cfg())
	if c1.DidResume() {
		t.Fatal("first connection reported resumption with an empty cache")
	}
	drain(t, c1)
	c1.Close()

	if got := <-resumed; got {
		t.Fatal("server reported the first connection as resumed")
	}

	// Second connection: the cache now holds a ticket, so this must resume.
	c2 := dialCtls(t, ln.Addr().String(), cfg())
	if !c2.DidResume() {
		t.Fatal("client did not resume despite a cached ticket")
	}
	drain(t, c2)
	c2.Close()

	if got := <-resumed; !got {
		t.Fatal("crypto/tls server did not accept the resumption: the PSK binder " +
			"or the transcript it covers is wrong")
	}
}

// TestResumptionIsScopedByCacheKey guards the anti-correlation property.
//
// Presenting the same ticket over two different proxies tells the server both
// connections are one client, which is exactly what rotating proxies is meant
// to prevent. Tickets must never cross a cache key.
func TestResumptionIsScopedByCacheKey(t *testing.T) {
	const host = "localhost"
	pool, leafDER, leafKey := testCertChain(t, host)

	resumed := make(chan bool, 8)
	ln := startGoTLSServer(t, tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
	}, resumed)

	cache := NewSessionCache()
	cfg := func(key string) *Config {
		return &Config{
			ServerName: host,
			ALPN:       []string{"h2"},
			RootCAs:    pool,
			Browser:    BrowserSafari,
			Sessions:   cache,
			SessionKey: key,
		}
	}

	c1 := dialCtls(t, ln.Addr().String(), cfg("host|proxy-A"))
	drain(t, c1)
	c1.Close()
	<-resumed

	// A different proxy scope must not reach proxy-A's ticket.
	c2 := dialCtls(t, ln.Addr().String(), cfg("host|proxy-B"))
	if c2.DidResume() {
		t.Fatal("a ticket issued under one proxy scope was replayed under another; " +
			"the server can now link the two as the same client")
	}
	drain(t, c2)
	c2.Close()
	<-resumed
}

// TestFullHandshakeStillRequiresCertificate pins the security boundary that
// resumption introduces. Skipping certificate checks is legitimate only when
// the server actually selected our PSK; a non-resumed handshake must still
// prove possession of the certificate key.
func TestFullHandshakeStillRequiresCertificate(t *testing.T) {
	const host = "example.com"
	pool, leafDER, _ := testCertChain(t, host)

	// A rogue server with no signer forges CertificateVerify. Offering a
	// session cache must not create a path around that check.
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
		rogueServerHandshake(c, leafDER, nil)
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(15 * time.Second))

	conn, err := handshake(raw, &Config{
		ServerName: host,
		ALPN:       []string{"h2"},
		RootCAs:    pool,
		Browser:    BrowserSafari,
		Sessions:   NewSessionCache(),
		SessionKey: host,
	})
	if err == nil {
		conn.Close()
		t.Fatal("SECURITY: a non-resumed handshake with a forged CertificateVerify " +
			"was accepted once a session cache was configured")
	}
}

// startGoTLSServer runs a TLS 1.3 listener backed by crypto/tls, reporting each
// connection's server-side DidResume on the channel.
func startGoTLSServer(t *testing.T, cert tls.Certificate, resumed chan<- bool) net.Listener {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					return
				}
				resumed <- tc.ConnectionState().DidResume
				// Something to read keeps the client's Read call going long
				// enough to absorb the tickets that precede it.
				tc.Write([]byte("ok"))
				io.Copy(io.Discard, tc)
			}(c)
		}
	}()
	return ln
}

func dialCtls(t *testing.T, addr string, cfg *Config) *Conn {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	c, err := handshake(raw, cfg)
	if err != nil {
		raw.Close()
		t.Fatalf("handshake: %v", err)
	}
	return c
}

// drain reads the server's payload, which also walks the NewSessionTicket
// records crypto/tls emits ahead of it.
func drain(t *testing.T, c *Conn) {
	t.Helper()
	buf := make([]byte, 64)
	if _, err := c.Read(buf); err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
}

// TestResumedChromeHelloAddsOnlyPSK pins the shape of the resumed ClientHello.
//
// The expected JA4 is derived, not guessed. chrome_hello.go documents
// t13d1517h2_8daaf6152771_b6f405a00624 from a real resumed Chrome capture, and
// that value is reproduced exactly by taking this builder's fresh extension set,
// adding pre_shared_key, and hashing with the *Chrome 146* signature algorithms
// — the profile in use when that capture was taken. Running the same derivation
// with the current Chrome 150 signature algorithms gives the constant below.
//
// So the real-device relationship "resumed hello = fresh hello + 0x0029, nothing
// else" is confirmed against a capture; this test pins that relationship for the
// current profile. The structural assertion below states it directly, so a
// change that swapped one extension for another while keeping the count would
// still fail.
func TestResumedChromeHelloAddsOnlyPSK(t *testing.T) {
	const resumedChrome150JA4 = "t13d1517h2_8daaf6152771_a87ad97598a9"

	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	sess := &Session{
		psk:       make([]byte, 32),
		ticket:    make([]byte, 128),
		suite:     cipherTLS_AES_128_GCM_SHA256,
		lifetime:  7200,
		createdAt: time.Now(),
	}

	freshRaw, err := buildChromeClientHello("tls.peet.ws", []string{"h2", "http/1.1"}, km, nil)
	if err != nil {
		t.Fatalf("fresh hello: %v", err)
	}
	resumedRaw, err := buildChromeClientHello("tls.peet.ws", []string{"h2", "http/1.1"}, km, sess)
	if err != nil {
		t.Fatalf("resumed hello: %v", err)
	}

	fresh, err := parseClientHello(freshRaw)
	if err != nil {
		t.Fatalf("parse fresh: %v", err)
	}
	resumed, err := parseClientHello(resumedRaw)
	if err != nil {
		t.Fatalf("parse resumed: %v", err)
	}

	// Structural check: the resumed set is the fresh set plus pre_shared_key.
	freshSet := map[uint16]bool{}
	for _, e := range dropGrease(fresh.extTypes) {
		freshSet[e] = true
	}
	added := []uint16{}
	resumedSet := map[uint16]bool{}
	for _, e := range dropGrease(resumed.extTypes) {
		resumedSet[e] = true
		if !freshSet[e] {
			added = append(added, e)
		}
	}
	for e := range freshSet {
		if !resumedSet[e] {
			t.Errorf("resuming dropped extension 0x%04x", e)
		}
	}
	if len(added) != 1 || added[0] != extPreSharedKey {
		t.Errorf("resuming added %v, want exactly [0x0029]", added)
	}

	// pre_shared_key must be the final extension (RFC 8446 §4.2.11).
	all := resumed.extTypes
	if len(all) == 0 || all[len(all)-1] != extPreSharedKey {
		t.Errorf("pre_shared_key is not the last extension; got trailing 0x%04x", all[len(all)-1])
	}

	if got := resumed.ja4(); got != resumedChrome150JA4 {
		t.Errorf("resumed Chrome JA4\n got: %s\nwant: %s", got, resumedChrome150JA4)
	}
}
