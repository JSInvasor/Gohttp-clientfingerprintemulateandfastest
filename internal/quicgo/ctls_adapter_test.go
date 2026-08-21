package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	quicprofile "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quic"
)

// FORK DELTA. Not present upstream.
//
// A whole QUIC connection over a real socket, with this repository's TLS stack
// on the client and crypto/tls on the server.
//
// internal/ctls already proves the handshake completes against crypto/tls, and
// internal/quic already proves the ClientHello is Chrome's byte for byte. This
// proves the third thing neither can: that the two fit together inside a
// transport written for neither of them. A handshake that completes in
// isolation can still deadlock here — the adapter has to hand quic-go its
// events in an order quic-go accepts, announce the peer's transport parameters
// before they are needed, and install four sets of keys at the moments the
// packet protection expects them.
//
// The server is upstream quic-go on crypto/tls, so it agrees with nothing this
// repository wrote.

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "quic.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"quic.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func TestCTLSClientTalksToAQUICServer(t *testing.T) {
	cert, pool := testCert(t)

	ln, err := ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const payload = "the handshake this repository builds, carried by a transport it did not"

	served := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			served <- err
			return
		}
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			served <- err
			return
		}
		got, err := io.ReadAll(str)
		if err != nil {
			served <- err
			return
		}
		if string(got) != payload {
			served <- errPayloadMismatch
			return
		}
		if _, err := str.Write(got); err != nil {
			served <- err
			return
		}
		served <- str.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := DialAddr(ctx, ln.Addr().String(), &tls.Config{
		ServerName: "quic.test",
		RootCAs:    pool,
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if got := conn.ConnectionState().TLS.NegotiatedProtocol; got != "h3" {
		t.Errorf("negotiated protocol = %q, want h3", got)
	}

	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := str.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := str.Close(); err != nil {
		t.Fatalf("close write side: %v", err)
	}

	echo, err := io.ReadAll(str)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(echo) != payload {
		t.Errorf("echo = %q, want %q", echo, payload)
	}

	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("server never finished")
	}
}

// TestCTLSClientRejectsAWrongCertificate confirms verification survives the
// trip through the adapter. A client that lost its root pool on the way in
// would pass every other test in this file.
func TestCTLSClientRejectsAWrongCertificate(t *testing.T) {
	cert, _ := testCert(t)
	_, otherPool := testCert(t)

	ln, err := ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept(context.Background())
		if err == nil {
			conn.CloseWithError(0, "")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := DialAddr(ctx, ln.Addr().String(), &tls.Config{
		ServerName: "quic.test",
		RootCAs:    otherPool, // trusts a different self-signed root
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}, nil)
	if err == nil {
		conn.CloseWithError(0, "")
		t.Fatal("dial succeeded against a certificate signed by an untrusted root")
	}
}

var errPayloadMismatch = &payloadMismatchError{}

type payloadMismatchError struct{}

func (*payloadMismatchError) Error() string { return "server received the wrong payload" }

// recordingConn is a net.PacketConn that keeps every datagram written.
//
// It is how the test below gets at what actually left the machine, rather than
// at what some layer believes it asked for. All of them, not just the first:
// this profile's ClientHello does not fit in one Initial, so a recorder that
// kept only the first datagram would see a handshake stream with a hole in it —
// which is exactly how this was found.
type recordingConn struct {
	net.PacketConn
	mu   sync.Mutex
	sent [][]byte
}

func (c *recordingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, append([]byte(nil), p...))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

func (c *recordingConn) datagrams() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.sent...)
}

// TestWireCarriesChromesHello reads the first packet off the socket
// and decodes it with this repository's own QUIC decoder — the one that was
// written against captures of Chrome and independently agreed with by
// browserleaks. What comes back has to be Chrome's ClientHello.
//
// This is the end of the chain the other tests each cover a link of: the hello
// is built by internal/ctls, handed to quic-go through the adapter, packed into
// an Initial by quic-go, protected, and put on a UDP socket. Everything in
// between has to be right for the JA4 at the far end to come out unchanged.
//
// What it deliberately does NOT assert yet is the shape of the datagram around
// the hello. quic-go pads an Initial to the RFC's 1200 bytes and sends the
// ClientHello as one CRYPTO frame; Chrome pads to 1250 and cuts the message
// into shuffled fragments interleaved with PING and PADDING. internal/quic has
// the builder for that (packet.go, chaos.go) and wiring it in is the next fork
// delta, so the gap is named here rather than left for someone to discover.
func TestWireCarriesChromesHello(t *testing.T) {
	cert, pool := testCert(t)

	ln, err := ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if conn, err := ln.Accept(context.Background()); err == nil {
			conn.CloseWithError(0, "")
		}
	}()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	rec := &recordingConn{PacketConn: pc}
	defer rec.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := Dial(ctx, rec, ln.Addr(), &tls.Config{
		ServerName: "quic.test",
		RootCAs:    pool,
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.CloseWithError(0, "")

	sent := rec.datagrams()
	if len(sent) == 0 {
		t.Fatal("nothing was written to the socket")
	}

	// The Initial keys come from the Connection ID the client chose for its
	// very first packet, and every Initial of the connection is protected under
	// it however the header's own field later changes.
	first, err := quicprofile.ParseLongHeader(sent[0])
	if err != nil {
		t.Fatalf("first datagram is not a long header: %v", err)
	}
	orig := first.DCID

	frags := map[uint64][]byte{}
	for _, dg := range sent {
		h, err := quicprofile.ParseLongHeader(dg)
		if err != nil || h.PacketType() != "Initial" {
			continue // a Handshake packet, or something we cannot read yet
		}
		pkt, err := quicprofile.Unprotect(dg, orig)
		if err != nil {
			continue // protected under keys this test does not hold
		}
		f, err := quicprofile.ParseFrames(pkt.Payload)
		if err != nil {
			continue
		}
		for off, d := range f.Crypto {
			frags[off] = d
		}
	}
	stream, err := quicprofile.Assemble(frags)
	if err != nil {
		t.Fatalf("assemble the hello off the wire: %v", err)
	}
	ch, err := quicprofile.ParseClientHello(stream)
	if err != nil {
		t.Fatalf("parse the hello we put on the wire: %v", err)
	}

	ja4, _ := ch.JA4()
	if ja4 != quicprofile.Chrome151QUIC.JA4 {
		t.Errorf("JA4 on the wire = %s\n       Chrome's = %s",
			ja4, quicprofile.Chrome151QUIC.JA4)
	}
	if ch.SNI != "quic.test" {
		t.Errorf("SNI = %q, want quic.test", ch.SNI)
	}
	if !slices.Equal(ch.ALPN, []string{"h3"}) {
		t.Errorf("ALPN = %v, want [h3]", ch.ALPN)
	}
}
