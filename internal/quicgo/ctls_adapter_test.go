package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
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

// recordedInitial is one Initial datagram and what it decoded to.
//
// The two travel together on purpose. An earlier version kept the datagrams in
// one slice and the decoded Initials in another and paired them by index, which
// is only right while every datagram is an Initial — and a Handshake datagram
// that lands among them makes the size check measure the wrong packet. It
// failed about one run in ten, saying an Initial was 1266 bytes when the
// datagram it had actually measured was not an Initial at all.
type recordedInitial struct {
	datagram []byte
	frames   *quicprofile.Frames
}

// recordedFlight is one connection's first flight, as it left the socket and as
// this repository's own decoder reads it back.
type recordedFlight struct {
	// datagrams is everything written, Initials and Handshake packets alike.
	datagrams [][]byte
	// initials is each Initial, in the order it was sent.
	initials []recordedInitial
	// hello is the ClientHello reassembled from every fragment in initials.
	hello *quicprofile.ClientHello
}

// dialAndRecordFlight opens one connection, records the datagrams that leave the
// socket, and decodes them with internal/quic — the decoder written against
// captures of Chrome and independently agreed with by browserleaks.
//
// It is what makes these tests measurements rather than assertions about
// intent: nothing here asks any layer what it meant to send. An Initial is
// protected under keys derived from a salt published in RFC 9001, so the
// decoder needs nothing from the client to read one, exactly as a middlebox
// would not.
func dialAndRecordFlight(t *testing.T) *recordedFlight {
	t.Helper()
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

	out := &recordedFlight{datagrams: sent}
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
		out.initials = append(out.initials, recordedInitial{datagram: dg, frames: f})
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
	out.hello = ch
	return out
}

func dialAndDecodeHello(t *testing.T) *quicprofile.ClientHello {
	t.Helper()
	return dialAndRecordFlight(t).hello
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
// The shape of the datagrams around the hello is measured separately, below.
func TestWireCarriesChromesHello(t *testing.T) {
	ch := dialAndDecodeHello(t)

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

// TestWireCarriesChromesTransportParameters reads extension 0x0039 back off the
// socket and holds it to the same reference the captures produced.
//
// The values are checked as well as the set, because the two halves of this
// delta have to agree: connection.go sets the limits quic-go enforces and
// wire/chrome_transport_parameters.go encodes them. Advertising Chrome's
// numbers while keeping quic-go's internally would tell the peer one thing and
// do another, and only a test that reads the wire can tell the difference.
func TestWireCarriesChromesTransportParameters(t *testing.T) {
	ch := dialAndDecodeHello(t)
	ref := quicprofile.Chrome151QUIC

	params, err := ch.TransportParams()
	if err != nil {
		t.Fatalf("transport parameters: %v", err)
	}

	got := map[uint64]uint64{}
	var greased int
	var sawSourceCID, sawVersionInfo bool
	var connOpts string

	for _, p := range params {
		switch {
		case quicprofile.IsGREASETransportParam(p.ID):
			greased++
			if n := len(p.Value); n < 11 || n > 15 {
				t.Errorf("GREASE parameter value is %d bytes; Chrome's are 11 to 15", n)
			}
		case p.ID == quicprofile.TPInitialSourceConnectionID:
			sawSourceCID = true
		case p.ID == quicprofile.TPVersionInformation:
			sawVersionInfo = true
			if len(p.Value) != 12 {
				t.Errorf("version_information is %d bytes, want 12", len(p.Value))
			}
		case p.ID == quicprofile.TPGoogleConnectionOptions:
			connOpts = string(p.Value)
		default:
			if v, ok := p.Uint(); ok {
				got[p.ID] = v
			}
		}
	}

	if !sawSourceCID {
		t.Error("no initial_source_connection_id")
	}
	if !sawVersionInfo {
		t.Error("no version_information; upstream quic-go does not send it")
	}
	if greased != 1 {
		t.Errorf("GREASE parameters = %d, want exactly 1", greased)
	}
	if connOpts != ref.ConnectionOptions {
		t.Errorf("google connection options = %q, want %q", connOpts, ref.ConnectionOptions)
	}
	for id, want := range ref.TransportParams {
		if got[id] != want {
			t.Errorf("transport parameter 0x%02x = %d, want %d", id, got[id], want)
		}
	}
	for id, v := range got {
		if _, known := ref.TransportParams[id]; !known {
			t.Errorf("we send an unpinned transport parameter 0x%02x = %d; "+
				"Chrome sends neither ack_delay_exponent, max_ack_delay, "+
				"disable_active_migration nor active_connection_id_limit", id, v)
		}
	}
}

// TestWireTransportParameterOrderMoves is the negative half. Upstream quic-go
// emits a fixed order with its greased value always first, which is a constant
// on the wire; Chrome shuffles. If this ever stops varying, the fixed order
// belongs in the reference and this delta was unnecessary.
func TestWireTransportParameterOrderMoves(t *testing.T) {
	ids := func() []uint64 {
		ch := dialAndDecodeHello(t)
		params, err := ch.TransportParams()
		if err != nil {
			t.Fatalf("transport parameters: %v", err)
		}
		out := make([]uint64, 0, len(params))
		for _, p := range params {
			if quicprofile.IsGREASETransportParam(p.ID) {
				continue // its id is random, so it would prove nothing
			}
			out = append(out, p.ID)
		}
		return out
	}
	first := ids()
	for i := 0; i < 8; i++ {
		if !slices.Equal(ids(), first) {
			return
		}
	}
	t.Error("eight connections put the transport parameters in the same order")
}

// TestWireCarriesChromesInitialShape measures the flight around the hello.
//
// Everything here is readable to anyone on the path — an Initial is protected
// under keys derived from a published salt — so the arrangement of the frames is
// as much a fingerprint as the ClientHello inside them, and it is one two stacks
// that agree on the hello can still differ on. Upstream quic-go sends 1280-byte
// datagrams with the hello in one CRYPTO frame and one run of padding at the
// end; Chrome sends 1250-byte datagrams with the hello cut into shuffled pieces
// among PINGs and several runs of padding.
//
// The counts are checked loosely on purpose. The point of the randomisation is
// that there is nothing to match, so a test that pinned a fragment count would
// be asserting the very constant this delta removes; what it holds is the shape.
func TestWireCarriesChromesInitialShape(t *testing.T) {
	flight := dialAndRecordFlight(t)
	ref := quicprofile.Chrome151QUIC

	if len(flight.initials) < 2 {
		t.Fatalf("the flight is %d Initial packet(s); this profile's hello does "+
			"not fit in one", len(flight.initials))
	}

	// Datagram size. A client must pad any datagram carrying an Initial (RFC
	// 9000 section 14.1), and this profile pads to 1250 rather than to the
	// minimum, so every one of them is checkable.
	for i, in := range flight.initials {
		if len(in.datagram) != ref.DatagramSize {
			t.Errorf("Initial datagram %d is %d bytes, Chrome sends %d",
				i, len(in.datagram), ref.DatagramSize)
		}
	}

	// The long header. Upstream draws the Destination Connection ID's length at
	// random between 8 and 20 bytes; Chrome's is 8, and its Source Connection ID
	// is empty. Both are in the clear on the first packet, and both move every
	// field after them.
	hdr, err := quicprofile.ParseLongHeader(flight.datagrams[0])
	if err != nil {
		t.Fatalf("first datagram is not a long header: %v", err)
	}
	if len(hdr.DCID) != ref.DCIDLen {
		t.Errorf("destination connection ID is %d bytes, Chrome's is %d",
			len(hdr.DCID), ref.DCIDLen)
	}
	if len(hdr.SCID) != ref.SCIDLen {
		t.Errorf("source connection ID is %d bytes, Chrome's is %d",
			len(hdr.SCID), ref.SCIDLen)
	}
	if len(hdr.Token) != ref.TokenLen {
		t.Errorf("token is %d bytes; a first connection carries %d",
			len(hdr.Token), ref.TokenLen)
	}

	var pings int
	var order []uint64
	for _, in := range flight.initials {
		order = append(order, in.frames.CryptoOrder...)
		pings += in.frames.Pings
	}

	// The captures carry 9, 14, 15 and 18 fragments per flight. Two would mean
	// the hello was merely split across the two datagrams it needs, which is
	// what upstream does without any chaos protector at all.
	if len(order) < 6 {
		t.Errorf("the hello went out in %d CRYPTO fragments; Chrome's captures "+
			"show 9 to 18", len(order))
	}
	if pings == 0 {
		t.Error("no PING frames in the flight; Chrome's captures carry 3 to 17")
	}

	// Out of order, measured across the flight rather than within one packet.
	// A single packet's fragments can come out sorted by chance often enough to
	// make a flaky test; the whole flight sorted is one arrangement out of
	// len(order) factorial, which for eight fragments is one run in forty
	// thousand and for the counts actually seen is far less than that.
	if slices.IsSorted(order) {
		t.Errorf("the fragments went out in ascending stream order: %v\n"+
			"a receiver reassembles either way, so sorted means the shuffle "+
			"did not happen", order)
	}
}

// TestWirePaddingComesInRuns is separate from the shape test because it is a
// claim about a distribution rather than about one connection.
//
// One gap in four carries padding, so a packet whose padding all lands in the
// tail is uncommon but not rare — asserting several runs on a single flight
// would fail perhaps one run in twenty for no reason. What has to hold is that
// the runs happen at all: upstream writes one stretch of zeroes in a fixed place
// ahead of the frames, and never anything else.
func TestWirePaddingComesInRuns(t *testing.T) {
	best := 0
	for i := 0; i < 5; i++ {
		for _, in := range dialAndRecordFlight(t).initials {
			if len(in.frames.CryptoOrder) == 0 {
				continue // an ACK-only Initial has nothing to scatter between
			}
			if in.frames.PadRuns > best {
				best = in.frames.PadRuns
			}
		}
		if best > 1 {
			return
		}
	}
	t.Errorf("across five flights no Initial carried more than %d run(s) of "+
		"padding; Chrome's first capture carries seven", best)
}

// TestWireInitialShapeVaries is the negative half, and the one that would catch
// a chaos protector that had quietly stopped being random — a fixed seed, a plan
// built once and reused, a cut that always lands in the same place.
//
// A constant here would be worse than sending one tidy CRYPTO frame: a stack
// that scrambles its hello the same way every time has replaced a common pattern
// with a unique one.
//
// It takes the protector being on as given — with it off there is no plan to
// freeze, and upstream's own frame shuffle would carry this test — so this
// checks variation and TestWireCarriesChromesInitialShape checks presence.
func TestWireInitialShapeVaries(t *testing.T) {
	// A flight's shape as one comparable value: how many fragments landed in
	// each packet, how long each was, and where the PINGs fell.
	shape := func() string {
		flight := dialAndRecordFlight(t)
		var b strings.Builder
		for _, in := range flight.initials {
			f := in.frames
			fmt.Fprintf(&b, "|%d,%d,%d:", f.Pings, f.PadRuns, len(f.CryptoOrder))
			for _, off := range f.CryptoOrder {
				fmt.Fprintf(&b, "%d/%d,", off, len(f.Crypto[off]))
			}
		}
		return b.String()
	}

	first := shape()
	for i := 0; i < 4; i++ {
		if shape() != first {
			return
		}
	}
	t.Errorf("five connections laid out their first flight identically:\n  %s", first)
}

// TestChaosProtectorSurvivesAPlainHandshake is the guard on the fallback path.
//
// The scrambling is planned from a complete TLS handshake message, and it is
// switched off once the flight is out so that anything written afterwards is
// framed the ordinary way. QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING turns the
// whole thing off, which is worth keeping working: a handshake that will not
// complete is worse than one that is recognisable, and being able to send the
// flight plainly is how you tell which of the two you are looking at.
func TestChaosProtectorSurvivesAPlainHandshake(t *testing.T) {
	t.Setenv(disableClientHelloScramblingEnv, "true")

	ch := dialAndDecodeHello(t)
	ja4, _ := ch.JA4()
	if ja4 != quicprofile.Chrome151QUIC.JA4 {
		t.Errorf("JA4 with scrambling off = %s\n                    Chrome's = %s",
			ja4, quicprofile.Chrome151QUIC.JA4)
	}
}
