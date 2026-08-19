package ctls_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/ctls"
)

// A TLS 1.2 peer has to say so, in those words.
//
// This stack is TLS 1.3 only, and the ClientHello still advertises 1.2 in
// supported_versions because that is what the browsers it emulates do — so a
// server is entitled to pick 1.2, and real ones do. The suite check runs before
// the supported_versions check, which makes the clear message further down
// ("server did not negotiate TLS 1.3") unreachable for exactly the case that
// produces it. What the reader got instead was a bare cipher number:
//
//	server selected unsupported cipher suite 0xc030
//
// That reads like a missing algorithm and sends the reader looking for a cipher
// list. The answer is that the connection is not TLS 1.3 at all, and nothing in
// the old text said so.
func TestTLS12PeerNamesTheVersion(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "https://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// skipVerify: the certificate is not what is under test here, and a
	// handshake that dies on the suite never reaches the chain anyway.
	_, err = ctls.WrapConn(ctx, conn, "127.0.0.1", []string{"http/1.1"}, true, nil, ctls.BrowserChrome)
	if err == nil {
		t.Fatal("handshake succeeded against a server that will only speak TLS 1.2")
	}

	msg := err.Error()
	for _, want := range []string{"TLS 1.3 only", "TLS 1.2"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error never mentions %q, so the reader cannot tell a version problem "+
				"from a missing algorithm:\n  %s", want, msg)
		}
	}
	// The number stays: it is the one thing that says which suite the peer
	// picked, and dropping it would trade one unreadable error for another.
	if !strings.Contains(msg, "0x") {
		t.Errorf("error dropped the suite number:\n  %s", msg)
	}
	t.Logf("%s", msg)
}
