package gofire

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	http2 "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/http2"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/http2/hpack"
)

// What the client configures and what it puts on the wire are two different
// claims, and only the second one is the fingerprint.
//
// TestAkamaiFingerprints and TestH2SettingsOrder both read H2Profile through
// buildH2Settings — the same function the transport is handed — so they prove
// the profile is described correctly and stop there. Nothing between that slice
// and the socket was covered: the order the framer writes SETTINGS in, whether
// the connection-level WINDOW_UPDATE carries the increment the profile names,
// whether HPACK emits the pseudo-headers in the order the profile lists. A
// regression in any of those moves the Akamai hash a fingerprinter computes
// while every existing test stays green.
//
// So this one reads the bytes. It stands up a TLS listener, lets the real
// client dial it, and reassembles the Akamai fingerprint from the frames that
// actually arrive — then checks that string and its MD5 against the captured
// reference in reference.go.

// h2Capture is what one connection's opening frames said.
type h2Capture struct {
	Settings     []http2.Setting
	WindowUpdate uint32
	PseudoOrder  []string
	// AllHeaders is every field in wire order, pseudo-headers included. It is
	// what makes "the fast path sends what the ordinary path sends" checkable
	// as one comparison rather than field by field.
	AllHeaders  []string
	HeaderFlags http2.Flags
	HasPriority bool
	Priority    http2.PriorityParam
}

// akamai rebuilds the fingerprint string from the wire, in the format the
// fingerprinting services use: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-headers.
func (c h2Capture) akamai() string {
	parts := make([]string, 0, len(c.Settings))
	for _, s := range c.Settings {
		parts = append(parts, strconv.Itoa(int(s.ID))+":"+strconv.FormatUint(uint64(s.Val), 10))
	}
	pseudo := make([]string, 0, len(c.PseudoOrder))
	for _, p := range c.PseudoOrder {
		pseudo = append(pseudo, strings.TrimPrefix(p, ":")[:1])
	}
	return strings.Join(parts, ";") + "|" +
		strconv.FormatUint(uint64(c.WindowUpdate), 10) + "|0|" + strings.Join(pseudo, ",")
}

// captureH2Server accepts exactly one connection, records the client's opening
// frames, and hangs up.
//
// It does not answer the request. Everything being measured is on the frames
// the client sends before it needs a reply, and completing the exchange would
// mean writing a full response for nothing. The client's RoundTrip therefore
// fails, which the caller ignores.
func captureH2Server(t *testing.T) (addr string, result <-chan h2Capture) {
	t.Helper()

	cert := wireTestCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	out := make(chan h2Capture, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

		// The client preface comes first and is a fixed string.
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			return
		}
		if string(preface) != http2.ClientPreface {
			return
		}

		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)

		var cap h2Capture
		var sawSettings, sawHeaders bool
		for !sawSettings || !sawHeaders {
			f, err := fr.ReadFrame()
			if err != nil {
				break
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if f.IsAck() {
					continue
				}
				_ = f.ForeachSetting(func(s http2.Setting) error {
					cap.Settings = append(cap.Settings, s)
					return nil
				})
				sawSettings = true
			case *http2.WindowUpdateFrame:
				// Stream 0 is the connection-level flow window, which is the
				// one the fingerprint names.
				if f.StreamID == 0 {
					cap.WindowUpdate = f.Increment
				}
			case *http2.MetaHeadersFrame:
				for _, hf := range f.Fields {
					if strings.HasPrefix(hf.Name, ":") {
						cap.PseudoOrder = append(cap.PseudoOrder, hf.Name)
					}
					cap.AllHeaders = append(cap.AllHeaders, hf.Name+": "+hf.Value)
				}
				cap.HeaderFlags = f.HeadersFrame.Header().Flags
				cap.HasPriority = f.HeadersFrame.Priority != http2.PriorityParam{}
				cap.Priority = f.HeadersFrame.Priority
				sawHeaders = true
			}
		}
		out <- cap
	}()

	return ln.Addr().String(), out
}

func wireTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wire.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The fingerprint each profile puts on the wire has to be the one reference.go
// claims for it.
func TestAkamaiFingerprintOnTheWire(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile BrowserProfile
		want    string
		hash    string
	}{
		{"safari", SafariIOS18, safariAkamaiFP, safariAkamaiHash},
		{"chrome", Chrome151, chromeAkamaiFP, chromeAkamaiHash},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, result := captureH2Server(t)

			c, err := Emulate(tc.profile, WithInsecureSkipVerify())
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			defer c.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			// The server hangs up without answering, so this fails by design.
			resp, err := c.DoWithContext(ctx, "GET", "https://"+addr+"/", nil, nil)
			if err == nil {
				resp.Close()
			}

			var got h2Capture
			select {
			case got = <-result:
			case <-time.After(20 * time.Second):
				t.Fatal("the server captured nothing: no HTTP/2 connection arrived")
			}

			if fp := got.akamai(); fp != tc.want {
				t.Errorf("akamai fingerprint on the wire\n got: %s\nwant: %s", fp, tc.want)
			}
			if h := md5Hex(got.akamai()); h != tc.hash {
				t.Errorf("akamai hash on the wire = %s, want %s", h, tc.hash)
			}
		})
	}
}

// Safari announces it does not speak RFC 7540 priorities, so its HEADERS frames
// must carry no priority block; Chrome does not announce that and carries one on
// every request. fingerprint_test.go pins this through the framer's own
// encoding; this pins it after a real handshake, where a transport that
// overrode HeaderPriority would show up and there it would not.
func TestHeadersPriorityOnTheWire(t *testing.T) {
	for _, tc := range []struct {
		name        string
		profile     BrowserProfile
		wantPresent bool
		wantWeight  uint8
		wantExcl    bool
	}{
		{"safari sends none", SafariIOS18, false, 0, false},
		{"chrome sends weight 256 exclusive", Chrome151, true, 255, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, result := captureH2Server(t)

			c, err := Emulate(tc.profile, WithInsecureSkipVerify())
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			defer c.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if resp, err := c.DoWithContext(ctx, "GET", "https://"+addr+"/", nil, nil); err == nil {
				resp.Close()
			}

			var got h2Capture
			select {
			case got = <-result:
			case <-time.After(20 * time.Second):
				t.Fatal("no HEADERS frame arrived")
			}

			if got.HasPriority != tc.wantPresent {
				t.Fatalf("HEADERS priority block present = %v, want %v (flags %v, priority %+v)",
					got.HasPriority, tc.wantPresent, got.HeaderFlags, got.Priority)
			}
			if !tc.wantPresent {
				return
			}
			if got.Priority.Weight != tc.wantWeight {
				t.Errorf("priority weight = %d, want %d", got.Priority.Weight, tc.wantWeight)
			}
			if got.Priority.Exclusive != tc.wantExcl {
				t.Errorf("priority exclusive = %v, want %v", got.Priority.Exclusive, tc.wantExcl)
			}
			if got.Priority.StreamDep != 0 {
				t.Errorf("priority depends_on = %d, want 0", got.Priority.StreamDep)
			}
		})
	}
}

// md5Hex is the hash the fingerprinting services publish alongside the string.
func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// The fast path has to be the same client, not a similar one.
//
// FastDo skips the cookie jar, redirects and retries deliberately — that is what
// it is for — but it must not skip any of the fingerprint. It goes straight to
// transport.RoundTrip with a template built by PrepareRequest, while
// DoWithContext builds its request through applyBrowserHeaders on every call, so
// the two assemble their headers by different routes and nothing compared the
// results. A header the template path misses is a header missing from every
// request `send -mode fast` and every pipeline with a template makes, at the
// throughput those modes exist for.
func TestFastPathSendsTheSameHeadersAsTheOrdinaryPath(t *testing.T) {
	for _, profile := range []BrowserProfile{SafariIOS18, Chrome151} {
		t.Run(ReferenceFor(profile).Profile.String(), func(t *testing.T) {
			ordinary := captureOneRequest(t, profile, func(c *Client, url string) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if resp, err := c.DoWithContext(ctx, "GET", url, nil, nil); err == nil {
					resp.Close()
				}
			})

			fast := captureOneRequest(t, profile, func(c *Client, url string) {
				tmpl, err := c.PrepareRequest("GET", url)
				if err != nil {
					t.Fatalf("PrepareRequest: %v", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if resp, err := c.FastDo(ctx, tmpl); err == nil {
					resp.Close()
				}
			})

			if len(fast.AllHeaders) == 0 {
				t.Fatal("the fast path sent no headers at all")
			}
			// :authority names the listener, and the two runs get different
			// ephemeral ports. Its position is still compared — it is part of
			// the pseudo-header order — only its value is normalised.
			gotFast := strings.Join(withoutAuthorityValue(fast.AllHeaders), "\n  ")
			gotOrdinary := strings.Join(withoutAuthorityValue(ordinary.AllHeaders), "\n  ")
			if gotFast != gotOrdinary {
				t.Errorf("the fast path and the ordinary path disagree on the wire\n"+
					"fast:\n  %s\nordinary:\n  %s", gotFast, gotOrdinary)
			}
		})
	}
}

// A template with a body has to survive being replayed.
//
// FastDo takes a shallow copy, so the single Body reader is shared and is spent
// after the first send. GetBody is the contract that makes a template reusable,
// and a caller that sets Body without it gets one request with a body and every
// one after it empty — silently, since nothing errors.
func TestFastDoReplaysABodyEveryTime(t *testing.T) {
	const payload = `{"replay":"me"}`

	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer srv.Close()

	c, err := Emulate(Chrome151)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer c.Close()

	tmpl, err := c.PrepareRequest("POST", srv.URL)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	tmpl.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(payload)), nil
	}
	tmpl.ContentLength = int64(len(payload))

	const sends = 5
	for i := 0; i < sends; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		resp, err := c.FastDo(ctx, tmpl)
		cancel()
		if err != nil {
			t.Fatalf("FastDo %d: %v", i, err)
		}
		resp.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != sends {
		t.Fatalf("server saw %d requests, want %d", len(bodies), sends)
	}
	for i, b := range bodies {
		if b != payload {
			t.Errorf("request %d carried %q, want %q — the template was consumed", i, b, payload)
		}
	}
}

// One template, many goroutines. FastDo's shallow copy shares the header map, so
// this is the shape that would surface a write to it.
func TestFastDoIsSafeToShareATemplate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := Emulate(Chrome151)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer c.Close()

	tmpl, err := c.PrepareRequest("GET", srv.URL)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				resp, err := c.FastDo(ctx, tmpl)
				cancel()
				if err != nil {
					errs <- err
					return
				}
				resp.Close()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent FastDo: %v", err)
	}
}

// withoutAuthorityValue replaces the :authority value with a fixed token so two
// captures taken against different ephemeral ports stay comparable.
func withoutAuthorityValue(fields []string) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		if strings.HasPrefix(f, ":authority: ") {
			out[i] = ":authority: <listener>"
			continue
		}
		out[i] = f
	}
	return out
}

// captureOneRequest runs send against a capturing HTTP/2 listener and returns
// what arrived.
func captureOneRequest(t *testing.T, profile BrowserProfile, send func(c *Client, url string)) h2Capture {
	t.Helper()
	addr, result := captureH2Server(t)

	c, err := Emulate(profile, WithInsecureSkipVerify())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer c.Close()

	send(c, "https://"+addr+"/")

	select {
	case got := <-result:
		return got
	case <-time.After(20 * time.Second):
		t.Fatal("nothing arrived at the capturing server")
		return h2Capture{}
	}
}
