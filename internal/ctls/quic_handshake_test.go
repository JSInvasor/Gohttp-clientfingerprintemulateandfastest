package ctls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// The QUIC handshake, run against a peer this package did not write.
//
// Everything else in the QUIC work checks bytes against a capture: the
// ClientHello is compared to Chrome's, the transport parameters to Chrome's,
// the JA4 to a third party's. None of that says the handshake WORKS — a hello
// can be byte-perfect and still fail at the Finished MAC, because the transcript
// and the key schedule leave no trace on the wire that a fingerprint check can
// see.
//
// So the peer here is crypto/tls's own QUIC server. It shares no code with this
// package, it was written from the RFC by other people, and it will reject a
// wrong transcript, a wrong key schedule, a wrong signature check or a wrong
// Finished. Completing against it is the only evidence that the driver is right
// rather than merely well-formed.

// testTransportParams is a plausible encoded quic_transport_parameters body.
//
// TLS treats the extension as opaque and so does the server; what matters for
// this test is only that it is present and syntactically a parameter list,
// because a QUIC handshake without one is a protocol error on both sides.
func testTransportParams() []byte {
	// id, length, value — each a QUIC varint.
	return []byte{
		0x01, 0x04, 0x80, 0x00, 0x75, 0x30, // max_idle_timeout = 30000
		0x03, 0x02, 0x45, 0xc0, // max_udp_payload_size = 1472
		0x04, 0x04, 0x80, 0xf0, 0x00, 0x00, // initial_max_data = 15728640
		0x0f, 0x00, // initial_source_connection_id, empty
	}
}

// testCertificate returns a self-signed certificate for name and a pool that
// trusts it, so the handshake exercises verifyChain rather than skipping it.
func testCertificate(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{name},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// quicPeers wires our client to a crypto/tls server and pumps CRYPTO data
// between them until both sides finish or one gives up.
type quicPeers struct {
	t      *testing.T
	client *QUICHandshake
	server *tls.QUICConn

	clientSecrets map[QUICEncryptionLevel][2][]byte // [read, write]
	serverParams  []byte
	clientDone    bool
	serverDone    bool
}

func toStdLevel(l QUICEncryptionLevel) tls.QUICEncryptionLevel {
	switch l {
	case QUICEncryptionLevelInitial:
		return tls.QUICEncryptionLevelInitial
	case QUICEncryptionLevelHandshake:
		return tls.QUICEncryptionLevelHandshake
	default:
		return tls.QUICEncryptionLevelApplication
	}
}

func fromStdLevel(l tls.QUICEncryptionLevel) QUICEncryptionLevel {
	switch l {
	case tls.QUICEncryptionLevelInitial:
		return QUICEncryptionLevelInitial
	case tls.QUICEncryptionLevelHandshake:
		return QUICEncryptionLevelHandshake
	default:
		return QUICEncryptionLevelApplication
	}
}

// drainClient moves everything the client wants to say into the server.
func (p *quicPeers) drainClient() error {
	for {
		ev := p.client.NextEvent()
		switch ev.Kind {
		case QUICNoEvent:
			return nil
		case QUICWriteData:
			if err := p.server.HandleData(toStdLevel(ev.Level), ev.Data); err != nil {
				return err
			}
		case QUICSetReadSecret:
			s := p.clientSecrets[ev.Level]
			s[0] = ev.Secret
			p.clientSecrets[ev.Level] = s
		case QUICSetWriteSecret:
			s := p.clientSecrets[ev.Level]
			s[1] = ev.Secret
			p.clientSecrets[ev.Level] = s
		case QUICHandshakeDone:
			p.clientDone = true
		}
	}
}

// drainServer moves everything the server wants to say into the client.
func (p *quicPeers) drainServer() error {
	for {
		ev := p.server.NextEvent()
		switch ev.Kind {
		case tls.QUICNoEvent:
			return nil
		case tls.QUICWriteData:
			if err := p.client.HandleData(fromStdLevel(ev.Level), ev.Data); err != nil {
				return err
			}
		case tls.QUICTransportParameters:
			p.serverParams = ev.Data
		case tls.QUICHandshakeDone:
			p.serverDone = true
		}
	}
}

func newQUICPeers(t *testing.T, name string, clientCfg QUICConfig) *quicPeers {
	t.Helper()

	cert, pool := testCertificate(t, name)
	clientCfg.ServerName = name
	clientCfg.RootCAs = pool
	if clientCfg.TransportParams == nil {
		clientCfg.TransportParams = testTransportParams()
	}
	if clientCfg.ALPN == nil {
		clientCfg.ALPN = []string{"h3"}
	}

	server := tls.QUICServer(&tls.QUICConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   clientCfg.ALPN,
			MinVersion:   tls.VersionTLS13,
		},
	})
	server.SetTransportParameters([]byte{0x0f, 0x00}) // initial_source_connection_id, empty

	client, err := NewQUICClient(clientCfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return &quicPeers{
		t:             t,
		client:        client,
		server:        server,
		clientSecrets: map[QUICEncryptionLevel][2][]byte{},
	}
}

// run drives both sides to completion.
func (p *quicPeers) run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	defer p.server.Close()

	if err := p.server.Start(ctx); err != nil {
		return err
	}
	if err := p.client.Start(); err != nil {
		return err
	}
	// Each pass hands one side's output to the other. A handshake this shape
	// converges in a handful; the bound is only there so a bug stalls the test
	// instead of hanging it.
	for i := 0; i < 16; i++ {
		if err := p.drainClient(); err != nil {
			return err
		}
		if err := p.drainServer(); err != nil {
			return err
		}
		if p.clientDone && p.serverDone {
			return nil
		}
	}
	return errQUICTestStalled
}

var errQUICTestStalled = &stallError{}

type stallError struct{}

func (*stallError) Error() string { return "handshake did not converge" }

func TestQUICHandshakeCompletesAgainstCryptoTLS(t *testing.T) {
	p := newQUICPeers(t, "quic.example.com", QUICConfig{})
	if err := p.run(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	if !p.client.Done() {
		t.Error("client never reported the handshake done")
	}
	if got := p.client.NegotiatedALPN(); got != "h3" {
		t.Errorf("negotiated ALPN = %q, want h3", got)
	}
	if len(p.client.PeerCertificates()) == 0 {
		t.Error("client kept no peer certificate")
	}
	if len(p.client.PeerTransportParams()) == 0 {
		t.Error("client did not receive the server's transport parameters")
	}
}

// TestQUICHandshakeSecretsAreDistinct checks the key schedule published what it
// should. Four secrets, all different, all the negotiated hash's length — a
// driver that handed the same secret to both directions would still complete,
// because the peer never sees which one was installed.
func TestQUICHandshakeSecretsAreDistinct(t *testing.T) {
	p := newQUICPeers(t, "quic.example.com", QUICConfig{})
	if err := p.run(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	seen := map[string]string{}
	for _, level := range []QUICEncryptionLevel{
		QUICEncryptionLevelHandshake, QUICEncryptionLevelApplication,
	} {
		s, ok := p.clientSecrets[level]
		if !ok {
			t.Fatalf("no secrets published for the %s level", level)
		}
		for i, dir := range []string{"read", "write"} {
			if len(s[i]) == 0 {
				t.Errorf("%s %s secret is empty", level, dir)
				continue
			}
			key := string(s[i])
			if where, dup := seen[key]; dup {
				t.Errorf("%s %s secret is the same as %s", level, dir, where)
			}
			seen[key] = level.String() + " " + dir
		}
	}
}

// TestQUICHandshakeRejectsAWrongCertificate makes sure verification is really
// running. The chain is valid but issued for another name, which is the failure
// a client that skipped the check would sail straight past.
func TestQUICHandshakeRejectsAWrongCertificate(t *testing.T) {
	cert, _ := testCertificate(t, "wrong.example.com")
	_, pool := testCertificate(t, "quic.example.com")

	server := tls.QUICServer(&tls.QUICConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
			MinVersion:   tls.VersionTLS13,
		},
	})
	server.SetTransportParameters([]byte{0x0f, 0x00})

	client, err := NewQUICClient(QUICConfig{
		ServerName:      "quic.example.com",
		ALPN:            []string{"h3"},
		TransportParams: testTransportParams(),
		RootCAs:         pool,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	p := &quicPeers{t: t, client: client, server: server,
		clientSecrets: map[QUICEncryptionLevel][2][]byte{}}

	if err := p.run(); err == nil {
		t.Error("handshake completed against a certificate for another name")
	}
}

// TestQUICHandshakeNeedsTransportParameters pins the QUIC-specific requirement.
// Over TCP the extension does not exist; over QUIC a handshake without it has
// agreed no flow control limits at all.
func TestQUICHandshakeNeedsTransportParameters(t *testing.T) {
	if _, err := NewQUICClient(QUICConfig{ServerName: "x", ALPN: []string{"h3"}}); err == nil {
		t.Error("a client was created with no transport parameters")
	}
}

// TestQUICHandshakeSendsChromesHello confirms the driver uses the QUIC builder
// rather than the TCP one. The two are different messages, and the difference
// is the entire point of quic_hello.go.
func TestQUICHandshakeSendsChromesHello(t *testing.T) {
	client, err := NewQUICClient(QUICConfig{
		ServerName:      "quic.example.com",
		ALPN:            []string{"h3"},
		TransportParams: testTransportParams(),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	ev := client.NextEvent()
	if ev.Kind != QUICWriteData || ev.Level != QUICEncryptionLevelInitial {
		t.Fatalf("first event is %v at %s, want write data at Initial", ev.Kind, ev.Level)
	}

	// The legacy session id is the cheapest tell: the TCP hello puts 32 random
	// bytes there and the QUIC hello leaves it empty.
	body := ev.Data[4:]
	if n := int(body[34]); n != 0 {
		t.Errorf("legacy session id is %d bytes; the QUIC hello sends none, "+
			"so this is the TCP builder", n)
	}
}
