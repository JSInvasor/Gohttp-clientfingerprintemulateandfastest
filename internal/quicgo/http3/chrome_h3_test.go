package http3

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
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/qpack"
	quicprofile "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quic"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo/quicvarint"
)

// FORK DELTA. Not present upstream.
//
// A whole HTTP/3 request over a real UDP socket, with this repository's TLS
// stack, transport, QPACK and HTTP/3 layer on the client and upstream quic-go
// on the server.
//
// The server is what makes this worth running. It agrees with nothing this
// repository wrote: it runs crypto/tls, upstream's transport parameters, and
// upstream's QPACK, and it reports back what it actually received. So the
// header order and the field values below are read off the far end of a real
// connection rather than out of the encoder that produced them.
//
// What it cannot check is the control stream, because upstream's server ignores
// everything after SETTINGS — which is the point of sending it, and also why
// those assertions are made against the bytes instead, further down.

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "h3.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"h3.test"},
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

// received is what the server saw, recorded so the test can assert on the far
// end of the connection rather than on the near one.
type received struct {
	mu     sync.Mutex
	order  []string
	header http.Header
	method string
	path   string
	count  int
}

func (r *received) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	r.method, r.path = req.Method, req.URL.Path
	r.header = req.Header.Clone()
	// net/http gives the server a map, so the wire order is gone by the time a
	// handler sees it. What survives is in the qlog and in the raw bytes, which
	// is why TestRequestHeaderOrderIsChromes decodes the block itself.
	r.order = nil
	for k := range req.Header {
		r.order = append(r.order, strings.ToLower(k))
	}
	slices.Sort(r.order)
}

func (r *received) snapshot() received {
	r.mu.Lock()
	defer r.mu.Unlock()
	return received{order: slices.Clone(r.order), header: r.header.Clone(),
		method: r.method, path: r.path, count: r.count}
}

// h3Server starts an upstream quic-go HTTP/3 server and returns its address.
func h3Server(t *testing.T, handler http.Handler) (addr string, pool *x509.CertPool) {
	t.Helper()
	cert, pool := testCert(t)

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	srv := &Server{
		Handler:   handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
	}
	go func() { _ = srv.Serve(udp) }()
	t.Cleanup(func() { _ = srv.Close(); _ = udp.Close() })
	return udp.LocalAddr().String(), pool
}

func h3Client(t *testing.T, pool *x509.CertPool) *Transport {
	t.Helper()
	tr := &Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "h3.test",
			MinVersion: tls.VersionTLS13,
		},
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// chromeFetchHeaders sets the headers a Chrome fetch sends, deliberately in the
// wrong order, so that the order on the wire can only have come from the
// profile.
func chromeFetchHeaders(req *http.Request) {
	for _, kv := range [][2]string{
		{"priority", "u=1, i"},
		{"accept-language", "tr-TR,tr;q=0.9,en-US;q=0.8"},
		{"sec-fetch-dest", "empty"},
		{"accept", "*/*"},
		{"sec-ch-ua", `"Chromium";v="151", "Not?A_Brand";v="24"`},
		{"sec-fetch-mode", "cors"},
		{"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/151.0.0.0"},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-fetch-site", "same-origin"},
		{"sec-ch-ua-platform", `"Windows"`},
		{"origin", "https://h3.test"},
	} {
		req.Header.Set(kv[0], kv[1])
	}
}

// TestHTTP3RequestOverARealSocket is the end of the chain every other test in
// this repository covers a link of: the ClientHello internal/ctls builds, the
// Initial internal/quicgo shapes, the QPACK internal/qpack encodes, and the
// HTTP/3 layer here, all the way to a response body.
func TestHTTP3RequestOverARealSocket(t *testing.T) {
	const body = "the HTTP/3 layer this repository built, answered by one it did not"

	var seen received
	addr, pool := h3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.record(r)
		w.Header().Set("content-type", "text/plain")
		_, _ = io.WriteString(w, body)
	}))

	tr := h3Client(t, pool)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/api/v1/thing", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Host = "h3.test"
	chromeFetchHeaders(req)

	rsp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", rsp.StatusCode)
	}
	got, err := io.ReadAll(rsp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}

	s := seen.snapshot()
	if s.count != 1 {
		t.Fatalf("the server saw %d requests, want 1", s.count)
	}
	if s.path != "/api/v1/thing" {
		t.Errorf("the server saw path %q", s.path)
	}
	if ua := s.header.Get("user-agent"); !strings.Contains(ua, "Chrome/151") {
		t.Errorf("the server saw user-agent %q", ua)
	}
	if p := s.header.Get("sec-ch-ua-platform"); p != `"Windows"` {
		t.Errorf("the server saw sec-ch-ua-platform %q", p)
	}
}

// TestManyRequestsOnOneConnection is where the QPACK dynamic table earns its
// place, and where a table that drifted out of step with the server's would
// show up — as a header decoded to the wrong value, several requests after the
// mistake.
func TestManyRequestsOnOneConnection(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}

	addr, pool := h3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("x-request-id")
		mu.Unlock()
		w.Header().Set("x-echo", r.Header.Get("x-request-id"))
		_, _ = io.WriteString(w, r.URL.Path)
	}))

	tr := h3Client(t, pool)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	const requests = 30
	for i := 0; i < requests; i++ {
		path := fmt.Sprintf("/r/%d", i)
		id := fmt.Sprintf("id-%d", i)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+path, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		req.Host = "h3.test"
		chromeFetchHeaders(req)
		req.Header.Set("x-request-id", id)

		rsp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("request %d: round trip: %v", i, err)
		}
		got, err := io.ReadAll(rsp.Body)
		rsp.Body.Close()
		if err != nil {
			t.Fatalf("request %d: read: %v", i, err)
		}
		if string(got) != path {
			t.Fatalf("request %d: body %q, want %q", i, got, path)
		}
		if echo := rsp.Header.Get("x-echo"); echo != id {
			t.Fatalf("request %d: the response echoed %q, want %q", i, echo, id)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < requests; i++ {
		path, id := fmt.Sprintf("/r/%d", i), fmt.Sprintf("id-%d", i)
		if seen[path] != id {
			t.Errorf("the server read %q for %s, want %q", seen[path], path, id)
		}
	}
}

// TestRequestHeaderOrderIsChromes decodes the request's header block itself,
// because a handler cannot see the order: net/http hands it a map.
//
// The headers are set on the request in a deliberately wrong order, so an
// implementation that emitted them as given, or sorted them, or iterated the
// map, all produce something this does not accept.
func TestRequestHeaderOrderIsChromes(t *testing.T) {
	fields := encodeOneRequest(t, nil, nil)

	var pseudo, regular []string
	for _, f := range fields {
		if strings.HasPrefix(f.Name, ":") {
			pseudo = append(pseudo, f.Name)
		} else {
			regular = append(regular, f.Name)
		}
	}

	ref := quicprofile.Chrome151H3
	if !slices.Equal(pseudo, ref.PseudoHeaderOrder) {
		t.Errorf("pseudo-header order on the wire = %v\n                      Chrome's = %v",
			pseudo, ref.PseudoHeaderOrder)
	}

	// Every profile header this request carries has to appear in the profile's
	// relative order. Ones it does not carry are skipped rather than demanded:
	// the profile is a fetch and this is a GET with no body.
	var want []string
	for _, name := range ref.FetchHeaderOrder {
		if slices.Contains(regular, name) {
			want = append(want, name)
		}
	}
	var got []string
	for _, name := range regular {
		if slices.Contains(ref.FetchHeaderOrder, name) {
			got = append(got, name)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("header order on the wire = %v\n                Chrome's = %v", got, want)
	}
}

// TestHeaderOrderIsConfigurable covers the seam a caller needs to emulate
// something that is not a plain fetch.
func TestHeaderOrderIsConfigurable(t *testing.T) {
	order := []string{"accept", "user-agent", "sec-ch-ua"}
	fields := encodeOneRequest(t, []string{":path", ":scheme", ":authority", ":method"}, order)

	var pseudo, regular []string
	for _, f := range fields {
		if strings.HasPrefix(f.Name, ":") {
			pseudo = append(pseudo, f.Name)
		} else if slices.Contains(order, f.Name) {
			regular = append(regular, f.Name)
		}
	}
	if want := []string{":path", ":scheme", ":authority", ":method"}; !slices.Equal(pseudo, want) {
		t.Errorf("pseudo-header order = %v, want %v", pseudo, want)
	}
	if !slices.Equal(regular, order) {
		t.Errorf("header order = %v, want %v", regular, order)
	}
}

// encodeOneRequest runs a request through the real writer and decodes the
// header block off it, which is the only place the order still exists.
func encodeOneRequest(t *testing.T, pseudoOrder, headerOrder []string) []qpack.HeaderField {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "https://h3.test/api/v1/thing", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	chromeFetchHeaders(req)

	w := newRequestWriter()
	w.pseudoHeaderOrder, w.headerOrder = pseudoOrder, headerOrder

	var buf strings.Builder
	if err := w.WriteRequestHeader(&stringWriter{&buf}, req, false, 0, nil); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	// Skip the HEADERS frame header, then decode the block.
	raw := []byte(buf.String())
	_, n, err := readVarintFrom(raw)
	if err != nil {
		t.Fatalf("frame type: %v", err)
	}
	length, m, err := readVarintFrom(raw[n:])
	if err != nil {
		t.Fatalf("frame length: %v", err)
	}
	block := raw[n+m : n+m+int(length)]

	fields, err := qpack.NewDecoder().DecodeForStream(context.Background(), 0, block)
	if err != nil {
		t.Fatalf("decode the block we wrote: %v", err)
	}
	return fields
}

type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

func readVarintFrom(b []byte) (uint64, int, error) {
	v, err := quicvarint.Read(quicvarint.NewReader(strings.NewReader(string(b))))
	if err != nil {
		return 0, 0, err
	}
	return v, quicvarint.Len(v), nil
}

// TestControlStreamCarriesChromesSettings reads the bytes this client puts on
// its control stream and holds them to the reference.
//
// It works on the bytes rather than through a server because there is no server
// that would tell you: both frames after SETTINGS exist to be ignored, and a
// peer that noticed them would be the bug. Sending them is a fingerprint
// decision with no functional consequence at all, which is exactly the kind
// that gets quietly dropped.
func TestControlStreamCarriesChromesSettings(t *testing.T) {
	b := appendChromeSettings(nil)
	ref := quicprofile.Chrome151H3

	frameType, n, err := readVarintFrom(b)
	if err != nil {
		t.Fatalf("frame type: %v", err)
	}
	if frameType != 0x4 {
		t.Fatalf("first frame on the control stream is type %#x, want SETTINGS", frameType)
	}
	length, m, err := readVarintFrom(b[n:])
	if err != nil {
		t.Fatalf("frame length: %v", err)
	}
	if int(length) != ref.SettingsFrameLen {
		t.Errorf("SETTINGS body is %d bytes, Chrome's is %d", length, ref.SettingsFrameLen)
	}
	body := b[n+m:]
	if len(body) != int(length) {
		t.Fatalf("SETTINGS body is %d bytes, the length says %d", len(body), length)
	}

	// The entries, in order.
	for _, want := range ref.Settings {
		id, n, err := readVarintFrom(body)
		if err != nil {
			t.Fatalf("setting id: %v", err)
		}
		body = body[n:]
		val, n, err := readVarintFrom(body)
		if err != nil {
			t.Fatalf("setting value: %v", err)
		}
		body = body[n:]
		if id != want.ID || val != want.Value {
			t.Fatalf("setting %#x = %d, want %#x = %d (%s); the order is part of the profile",
				id, val, want.ID, want.Value, want.Name)
		}
	}

	// And the reserved entry, which is what is left.
	if !ref.GreaseSetting {
		if len(body) != 0 {
			t.Errorf("%d bytes left over after the pinned settings", len(body))
		}
		return
	}
	id, n, err := readVarintFrom(body)
	if err != nil {
		t.Fatalf("reserved setting id: %v", err)
	}
	if (id-0x21)%0x1f != 0 {
		t.Errorf("reserved setting id %#x is not of the form 0x1f*N+0x21", id)
	}
	if n != 8 {
		t.Errorf("reserved setting id encodes in %d bytes, want 8 — the frame length says so", n)
	}
	_, m, err = readVarintFrom(body[n:])
	if err != nil {
		t.Fatalf("reserved setting value: %v", err)
	}
	if m != 8 {
		t.Errorf("reserved setting value encodes in %d bytes, want 8", m)
	}
	if n+m != len(body) {
		t.Errorf("%d bytes left after the reserved setting", len(body)-n-m)
	}
}

// TestControlStreamDoesNotStopAtSettings is the omission that costs nothing to
// make and cannot be caught by anything failing.
func TestControlStreamDoesNotStopAtSettings(t *testing.T) {
	b := appendControlStreamTail(nil)
	if len(b) == 0 {
		t.Fatal("nothing follows SETTINGS on the control stream; Chrome sends a reserved frame")
	}
	id, n, err := readVarintFrom(b)
	if err != nil {
		t.Fatalf("frame type: %v", err)
	}
	if (id-0x21)%0x1f != 0 {
		t.Errorf("the frame after SETTINGS is %#x, want a reserved type of the "+
			"form 0x1f*N+0x21", id)
	}
	length, m, err := readVarintFrom(b[n:])
	if err != nil {
		t.Fatalf("frame length: %v", err)
	}
	if n+m+int(length) != len(b) {
		t.Errorf("the tail is %d bytes but the frame accounts for %d", len(b), n+m+int(length))
	}
}

// TestPriorityUpdateNamesTheRequestStream is the correction a live check
// forced, and it is the reason this file cannot be trusted on its own.
//
// The first version wrote PRIORITY_UPDATE at connection setup, naming element
// 0, and every test here passed: the bytes were RFC-correct and this package's
// own parser read them back. A fingerprinting service reported no
// PRIORITY_UPDATE at all against real Chrome's one. A frame about a stream that
// does not exist is not a frame anyone records.
//
// So what is pinned now is the tie between the frame and a request: the element
// id has to be the stream the request went out on.
func TestPriorityUpdateNamesTheRequestStream(t *testing.T) {
	for _, streamID := range []uint64{0, 4, 8, 400} {
		b := appendPriorityUpdate(nil, streamID)

		frameType, n, err := readVarintFrom(b)
		if err != nil {
			t.Fatalf("frame type: %v", err)
		}
		if frameType != quicprofile.H3FramePriorityUpdate {
			t.Fatalf("frame type = %#x, want %#x (PRIORITY_UPDATE for a request stream)",
				frameType, quicprofile.H3FramePriorityUpdate)
		}
		length, m, err := readVarintFrom(b[n:])
		if err != nil {
			t.Fatalf("frame length: %v", err)
		}
		payload := b[n+m:]
		if len(payload) != int(length) {
			t.Fatalf("payload is %d bytes, the length says %d", len(payload), length)
		}

		gotID, k, err := readVarintFrom(payload)
		if err != nil {
			t.Fatalf("prioritized element id: %v", err)
		}
		if gotID != streamID {
			t.Errorf("PRIORITY_UPDATE for stream %d names element %d", streamID, gotID)
		}
		if got := string(payload[k:]); got != quicprofile.Chrome151H3.DefaultPriority {
			t.Errorf("priority field value = %q, Chrome sends %q",
				got, quicprofile.Chrome151H3.DefaultPriority)
		}
	}
}

// TestEveryRequestCarriesAPriorityUpdate reads the control stream after a run
// of requests, because one frame at setup was exactly the bug.
func TestEveryRequestCarriesAPriorityUpdate(t *testing.T) {
	var sink recordingWriter
	c := &ClientConn{controlWr: &pendingWriter{}}
	if err := c.controlWr.attach(&sink); err != nil {
		t.Fatalf("attach: %v", err)
	}
	for _, id := range []quic.StreamID{0, 4, 8} {
		c.sendPriorityUpdate(id)
	}

	var ids []uint64
	rest := sink.bytes()
	for len(rest) > 0 {
		frameType, n, err := readVarintFrom(rest)
		if err != nil {
			t.Fatalf("frame type: %v", err)
		}
		rest = rest[n:]
		length, n, err := readVarintFrom(rest)
		if err != nil {
			t.Fatalf("frame length: %v", err)
		}
		rest = rest[n:]
		if frameType != quicprofile.H3FramePriorityUpdate {
			t.Fatalf("unexpected frame %#x on the control stream", frameType)
		}
		id, _, err := readVarintFrom(rest[:length])
		if err != nil {
			t.Fatalf("element id: %v", err)
		}
		ids = append(ids, id)
		rest = rest[length:]
	}
	if want := []uint64{0, 4, 8}; !slices.Equal(ids, want) {
		t.Errorf("the control stream named streams %v, want one frame per request %v", ids, want)
	}
}

// TestAPriorityUpdateWrittenBeforeTheStreamExistsIsNotLost covers the race the
// buffering exists for: the control stream is opened in a goroutine and the
// first request does not wait for it.
//
// Dropping the frame there would make it appear on some connections and not
// others, which is worse than either always or never — not Chrome, and not
// reproducible either.
func TestAPriorityUpdateWrittenBeforeTheStreamExistsIsNotLost(t *testing.T) {
	var sink recordingWriter
	c := &ClientConn{controlWr: &pendingWriter{}}

	c.sendPriorityUpdate(0) // before the stream exists
	if len(sink.bytes()) != 0 {
		t.Fatal("something reached the stream before it was attached")
	}
	if err := c.controlWr.attach(&sink); err != nil {
		t.Fatalf("attach: %v", err)
	}

	frameType, n, err := readVarintFrom(sink.bytes())
	if err != nil {
		t.Fatalf("frame type: %v", err)
	}
	if frameType != quicprofile.H3FramePriorityUpdate {
		t.Errorf("the held frame came out as %#x", frameType)
	}
	_ = n
}

type recordingWriter struct {
	mu  sync.Mutex
	buf []byte
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *recordingWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.buf)
}

// TestPeerQPACKLimitsAreReadFromSettings covers the wiring that decides whether
// this client's encoder uses its dynamic table at all.
//
// It is a unit test rather than an end-to-end one for a reason worth stating.
// The server in this file is upstream quic-go, whose QPACK has no dynamic
// table, so it advertises neither setting — and the correct behaviour against
// it is for this client to insert nothing and leave its encoder stream empty,
// which is exactly what "no table advertised" produces. So the connection tests
// above exercise the static path and cannot exercise the other one. The dynamic
// path is covered in internal/qpack, against this repository's own decoder;
// what is checked here is only the reading of the peer's SETTINGS, which is the
// one link those tests cannot see.
func TestPeerQPACKLimitsAreReadFromSettings(t *testing.T) {
	if c, b := peerQPACKLimits(nil); c != 0 || b != 0 {
		t.Errorf("a peer that sent no SETTINGS at all yields %d/%d, want 0/0", c, b)
	}

	// Upstream's server sends neither, because it has no dynamic table.
	empty := &Settings{Other: map[uint64]uint64{}}
	if c, b := peerQPACKLimits(empty); c != 0 || b != 0 {
		t.Errorf("a peer that advertised no table yields %d/%d, want 0/0; "+
			"inserting against it would reference entries it cannot resolve", c, b)
	}

	full := &Settings{Other: map[uint64]uint64{
		quicprofile.H3SettingQPACKMaxTableCapacity: 4096,
		quicprofile.H3SettingQPACKBlockedStreams:   16,
	}}
	if c, b := peerQPACKLimits(full); c != 4096 || b != 16 {
		t.Errorf("peer limits = %d/%d, want 4096/16", c, b)
	}
}

// TestOurSettingsMatchOurDecoder is the coherence check between the two places
// the same promise is written.
//
// SETTINGS say what this endpoint's decoder will accept; the decoder has to
// actually accept it. They are separate constants in separate packages, and
// nothing but this stops one from moving without the other — at which point the
// client would either advertise a table it cannot use, which is upstream's bug
// and the reason internal/qpack is a fork, or use one it never advertised.
func TestOurSettingsMatchOurDecoder(t *testing.T) {
	var capacity, blocked uint64
	for _, s := range quicprofile.Chrome151H3.Settings {
		switch s.ID {
		case quicprofile.H3SettingQPACKMaxTableCapacity:
			capacity = s.Value
		case quicprofile.H3SettingQPACKBlockedStreams:
			blocked = s.Value
		}
	}
	if capacity != chromeQPACKMaxTableCapacity {
		t.Errorf("SETTINGS advertise a %d byte table, the decoder is built with %d",
			capacity, chromeQPACKMaxTableCapacity)
	}
	if blocked != chromeQPACKBlockedStreams {
		t.Errorf("SETTINGS advertise %d blocked streams, the decoder is built with %d",
			blocked, chromeQPACKBlockedStreams)
	}
}

// TestReservedValuesMove is the negative half. A reserved identifier that came
// out the same every time would be a constant, which is worse than sending
// nothing: it would make this client the only one producing it.
func TestReservedValuesMove(t *testing.T) {
	first := string(appendChromeSettings(nil))
	var moved bool
	for i := 0; i < 8; i++ {
		if string(appendChromeSettings(nil)) != first {
			moved = true
			break
		}
	}
	if !moved {
		t.Error("eight SETTINGS frames came out identical; the reserved entry is not random")
	}

	first = string(appendControlStreamTail(nil))
	moved = false
	for i := 0; i < 8; i++ {
		if string(appendControlStreamTail(nil)) != first {
			moved = true
			break
		}
	}
	if !moved {
		t.Error("eight control stream tails came out identical; the reserved frame is not random")
	}

	// PRIORITY_UPDATE is the opposite: it must not move. Its type and payload
	// are the profile's, and the only thing that varies is the stream it names.
	if a, b := appendPriorityUpdate(nil, 4), appendPriorityUpdate(nil, 4); string(a) != string(b) {
		t.Errorf("two PRIORITY_UPDATE frames for the same stream differ:\n  %x\n  %x", a, b)
	}
}

var _ = quic.Version1
