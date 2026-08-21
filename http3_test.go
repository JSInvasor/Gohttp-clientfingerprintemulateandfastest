package gofire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo/http3"
)

// Alt-Svc parsing, which is the whole of how a browser comes to be on HTTP/3.
//
// The cases below are real headers. Getting this wrong fails in one of two
// directions and only one of them is visible: refusing a valid offer leaves the
// client on TCP, which works and is merely a different fingerprint from the
// browser it claims to be, and is therefore the failure that survives.

func TestParseAltSvc(t *testing.T) {
	for _, tc := range []struct {
		name      string
		header    string
		authority string
		ttl       time.Duration
		clear     bool
		ok        bool
	}{
		{
			name:      "cloudflare",
			header:    `h3=":443"; ma=86400`,
			authority: ":443",
			ttl:       86400 * time.Second,
			ok:        true,
		},
		{
			name:      "google, with the h2 alternative first",
			header:    `h3=":443"; ma=2592000,h3-29=":443"; ma=2592000`,
			authority: ":443",
			ttl:       2592000 * time.Second,
			ok:        true,
		},
		{
			name: "a draft version only, which a client speaking v1 still takes",
			// h3-29 is close enough to v1 on the wire that Chrome uses it, and
			// an edge advertising only the draft is offering QUIC.
			header:    `h3-29=":8443"; ma=3600`,
			authority: ":8443",
			ttl:       3600 * time.Second,
			ok:        true,
		},
		{
			name:      "no ma, which means the default rather than never",
			header:    `h3=":443"`,
			authority: ":443",
			ttl:       24 * time.Hour,
			ok:        true,
		},
		{
			name:      "a different authority, which is how an edge moves QUIC",
			header:    `h3="quic.example.com:443"; ma=600`,
			authority: "quic.example.com:443",
			ttl:       600 * time.Second,
			ok:        true,
		},
		{
			name:   "clear withdraws the offer",
			header: `clear`,
			clear:  true,
			ok:     true,
		},
		{
			name:   "an offer for something that is not h3",
			header: `h2=":443"; ma=3600`,
			ok:     false,
		},
		{
			name:   "empty",
			header: "",
			ok:     false,
		},
		{
			name: "a comma inside the quoted authority",
			// Splitting on commas without minding the quotes gets this wrong,
			// and gets it wrong almost never, which is the worst kind of bug.
			header:    `h3="a,b.example.com:443"; ma=60`,
			authority: "a,b.example.com:443",
			ttl:       60 * time.Second,
			ok:        true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authority, ttl, clear, ok := parseAltSvc(tc.header)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (header %q)", ok, tc.ok, tc.header)
			}
			if !ok {
				return
			}
			if clear != tc.clear {
				t.Errorf("clear = %v, want %v", clear, tc.clear)
			}
			if clear {
				return
			}
			if authority != tc.authority {
				t.Errorf("authority = %q, want %q", authority, tc.authority)
			}
			if ttl != tc.ttl {
				t.Errorf("ttl = %v, want %v", ttl, tc.ttl)
			}
		})
	}
}

func TestAltSvcAddr(t *testing.T) {
	for _, tc := range []struct{ host, authority, want string }{
		{"example.com:443", ":443", "example.com:443"},
		{"example.com:443", ":8443", "example.com:8443"},
		{"example.com:443", "", "example.com:443"},
		{"example.com:443", "quic.example.com:443", "quic.example.com:443"},
		{"example.com:443", "quic.example.com", "quic.example.com:443"},
	} {
		if got := altSvcAddr(tc.host, tc.authority); got != tc.want {
			t.Errorf("altSvcAddr(%q, %q) = %q, want %q", tc.host, tc.authority, got, tc.want)
		}
	}
}

// TestH3CacheExpires covers the part of an offer that is easy to store and easy
// to forget to honour. An expired offer is an offer the server has stopped
// making, and using it means dialling QUIC at a host that may have stopped
// listening for it.
func TestH3CacheExpires(t *testing.T) {
	c := newH3Cache()
	c.put("example.com:443", altSvcEntry{authority: ":443", expires: time.Now().Add(time.Hour)})
	if _, ok := c.get("example.com:443"); !ok {
		t.Fatal("a live offer was not returned")
	}

	c.put("stale.example.com:443", altSvcEntry{authority: ":443", expires: time.Now().Add(-time.Second)})
	if _, ok := c.get("stale.example.com:443"); ok {
		t.Error("an expired offer was returned")
	}

	c.clear("example.com:443")
	if _, ok := c.get("example.com:443"); ok {
		t.Error("a cleared offer was returned")
	}
}

// TestHTTP3IsNotUsedBeforeItIsOffered is the ordering claim, and it is the one
// that matters most here.
//
// Every byte of the QUIC fingerprint could be perfect and this would still give
// the client away: no browser sends a QUIC Initial to a host it has never
// spoken to. Discovery has to be the default, and it has to be per host.
func TestHTTP3IsNotUsedBeforeItIsOffered(t *testing.T) {
	tr := newTransport(defaultTransportConfig(), Chrome151)
	defer tr.Close()

	if tr.h3Transport == nil {
		t.Fatal("the Chrome profile has no HTTP/3 transport")
	}

	req := mustRequest(t, "https://example.com/thing")
	if _, ok := tr.h3Target(req); ok {
		t.Error("HTTP/3 was chosen for a host that has never offered it")
	}

	// Now the host offers it, the way a real response does.
	tr.h3Cache.put("example.com:443", altSvcEntry{authority: ":443", expires: time.Now().Add(time.Hour)})
	addr, ok := tr.h3Target(req)
	if !ok {
		t.Fatal("HTTP/3 was not chosen for a host that offered it")
	}
	if addr != "example.com:443" {
		t.Errorf("h3 target = %q, want example.com:443", addr)
	}

	// And only that host.
	other := mustRequest(t, "https://other.example.com/thing")
	if _, ok := tr.h3Target(other); ok {
		t.Error("one host's offer was used for another")
	}
}

func TestForceHTTP3SkipsDiscovery(t *testing.T) {
	cfg := defaultTransportConfig()
	cfg.ForceHTTP3 = true
	tr := newTransport(cfg, Chrome151)
	defer tr.Close()

	if _, ok := tr.h3Target(mustRequest(t, "https://example.com/thing")); !ok {
		t.Error("WithForceHTTP3 did not send the first request over QUIC")
	}
}

func TestHTTP3CanBeTurnedOff(t *testing.T) {
	cfg := defaultTransportConfig()
	cfg.DisableHTTP3 = true
	tr := newTransport(cfg, Chrome151)
	defer tr.Close()

	if tr.h3Transport != nil {
		t.Fatal("DisableHTTP3 still built an HTTP/3 transport")
	}
	tr2 := newTransport(func() TransportConfig {
		c := defaultTransportConfig()
		c.ForceHTTP1 = true
		return c
	}(), Chrome151)
	defer tr2.Close()
	if tr2.h3Transport != nil {
		t.Error("ForceHTTP1 still built an HTTP/3 transport; a caller that asked " +
			"for HTTP/1.1 asked for TCP")
	}
}

// TestSafariHasNoHTTP3 keeps the two profiles from being mixed.
//
// Safari on iOS does speak HTTP/3, but nothing in this repository has captured
// it. Sending Chrome's QUIC under a Safari user agent would be a contradiction
// visible from the ClientHello onward, which is worse than staying on TCP.
func TestSafariHasNoHTTP3(t *testing.T) {
	tr := newTransport(defaultTransportConfig(), SafariIOS18)
	defer tr.Close()
	if tr.h3Transport != nil {
		t.Error("the Safari profile built an HTTP/3 transport it has no reference for")
	}
}

// TestRecordAltSvcReadsARealResponse covers the join between the two halves:
// the header arriving on an HTTP/2 response, and the cache the next request
// consults.
func TestRecordAltSvcReadsARealResponse(t *testing.T) {
	tr := newTransport(defaultTransportConfig(), Chrome151)
	defer tr.Close()

	req := mustRequest(t, "https://example.com/thing")
	resp := &http.Response{
		Header:  http.Header{"Alt-Svc": []string{`h3=":443"; ma=86400`}},
		Request: req,
	}
	tr.recordAltSvc(resp)

	if _, ok := tr.h3Target(req); !ok {
		t.Fatal("an Alt-Svc offer on the response did not put the next request on QUIC")
	}

	// And a server withdrawing it puts the client back on TCP.
	resp.Header.Set("Alt-Svc", "clear")
	tr.recordAltSvc(resp)
	if _, ok := tr.h3Target(req); ok {
		t.Error("the client kept using QUIC after the server withdrew the offer")
	}
}

// TestClientUpgradesToHTTP3OverARealSocket is the whole path, end to end: an
// HTTP/2 request over TCP whose response offers h3, then a second request that
// goes over QUIC because of it.
//
// Both servers are upstream code — net/http for the TCP side, quic-go for the
// QUIC side — so nothing here agrees with this repository except by having
// understood the same protocols.
func TestClientUpgradesToHTTP3OverARealSocket(t *testing.T) {
	h3Addr, pool, stopH3 := startH3Echo(t)
	defer stopH3()

	// The TCP server offers h3 at the QUIC server's port.
	_, h3Port, err := net.SplitHostPort(h3Addr)
	if err != nil {
		t.Fatalf("h3 address: %v", err)
	}
	tcp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":`+h3Port+`"; ma=3600`)
		_, _ = io.WriteString(w, "over tcp")
	}))
	defer tcp.Close()

	certs := x509.NewCertPool()
	certs.AddCert(tcp.Certificate())
	for _, c := range pool {
		certs.AddCert(c)
	}

	client, err := Emulate(Chrome151,
		WithRootCAs(certs),
		WithTimeout(20*time.Second),
	)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	// First request: TCP, and it carries the offer.
	resp, err := client.Get(tcp.URL + "/first")
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	body, _ := resp.Bytes()
	resp.Close()
	if string(body) != "over tcp" {
		t.Fatalf("first response = %q", body)
	}

	host := hostProtoKey(mustURL(t, tcp.URL).Host, "443")
	if _, ok := client.transport.h3Cache.get(host); !ok {
		t.Fatal("the Alt-Svc offer on the first response was not remembered")
	}

	// Second request: QUIC, because of the offer. The QUIC server answers on a
	// different port and says so, which is how the test knows which path it
	// took rather than trusting a flag.
	resp2, err := client.Get(tcp.URL + "/second")
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	body2, _ := resp2.Bytes()
	resp2.Close()
	if string(body2) != "over quic" {
		t.Fatalf("second response = %q, want the QUIC server's answer; "+
			"the client stayed on TCP", body2)
	}
}

// startH3Echo runs an HTTP/3 server that identifies itself, on its own port.
func startH3Echo(t *testing.T) (addr string, certs []*x509.Certificate, stop func()) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	host, _, _ := net.SplitHostPort(udp.LocalAddr().String())

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP(host)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	srv := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "over quic")
		}),
		TLSConfig: &cryptotls.Config{
			Certificates: []cryptotls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
			MinVersion:   cryptotls.VersionTLS13,
		},
	}
	go func() { _ = srv.Serve(udp) }()
	return udp.LocalAddr().String(), []*x509.Certificate{leaf}, func() {
		_ = srv.Close()
		_ = udp.Close()
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	return u
}

func mustRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return req
}
