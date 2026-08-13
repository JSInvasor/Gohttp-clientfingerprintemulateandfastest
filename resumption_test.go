package gofire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// A Client that dials the same host repeatedly must resume, the way a browser
// does. Before this every connection was a full handshake — hundreds of them in
// a load run, and a client that never resumes is one no browser reproduces
// whatever its ClientHello looks like.
//
// The test forces HTTP/1.1 and disables keep-alives so each request opens its
// own connection; over h2 the pool would reuse one and there would be nothing
// to resume. Under load the pool opens new connections anyway, which is exactly
// where this matters.
func TestClientResumesAcrossConnections(t *testing.T) {
	cert, pool := e2eCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	resumed := make(chan bool, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := c.(*tls.Conn)
				if tc.HandshakeContext(t.Context()) != nil {
					return
				}
				resumed <- tc.ConnectionState().DidResume
				buf := make([]byte, 1024)
				c.Read(buf)
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
				time.Sleep(200 * time.Millisecond)
			}(c)
		}
	}()

	client, err := Emulate(Chrome151,
		WithRootCAs(pool), WithForceHTTP1(), WithDisableKeepAlives(),
		WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("emulate: %v", err)
	}
	defer client.Close()

	url := "https://" + ln.Addr().String() + "/"
	var sawResume bool
	for i := 0; i < 4; i++ {
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Bytes()
		resp.Close()
		select {
		case r := <-resumed:
			t.Logf("connection %d resumed=%v", i, r)
			if r {
				sawResume = true
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("request %d: server never reported", i)
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !sawResume {
		t.Error("no connection resumed across four requests to the same host")
	}
}

func e2eCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
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
		BasicConstraintsValid: true, IsCA: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
