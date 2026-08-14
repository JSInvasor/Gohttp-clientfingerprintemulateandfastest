package gofire

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

func gzipBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func brotliBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

func zlibBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func rawFlateBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write(in); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

// newResponse builds a Response carrying body under the given Content-Encoding
// header values.
func newResponse(body []byte, encodings ...string) *Response {
	h := http.Header{}
	for _, e := range encodings {
		h.Add("Content-Encoding", e)
	}
	return &Response{Response: &http.Response{
		Header: h,
		Body:   io.NopCloser(bytes.NewReader(body)),
	}}
}

// TestContentEncodingDecodes covers the codings and the header spellings a real
// server may use. Content-Encoding is a case-insensitive token list, so exact
// string matching silently returned still-compressed bytes with a nil error —
// the failure mode nothing downstream can detect.
func TestContentEncodingDecodes(t *testing.T) {
	const want = "the quick brown fox jumps over the lazy dog"
	payload := []byte(want)

	cases := []struct {
		name      string
		body      []byte
		encodings []string
	}{
		{"gzip", gzipBytes(t, payload), []string{"gzip"}},
		{"gzip uppercase", gzipBytes(t, payload), []string{"GZIP"}},
		{"gzip mixed case", gzipBytes(t, payload), []string{"GzIp"}},
		{"gzip trailing space", gzipBytes(t, payload), []string{"gzip "}},
		{"gzip leading space", gzipBytes(t, payload), []string{" gzip"}},
		{"x-gzip", gzipBytes(t, payload), []string{"x-gzip"}},
		{"brotli", brotliBytes(t, payload), []string{"br"}},
		{"identity", payload, []string{"identity"}},
		{"empty header", payload, []string{""}},
		{"no header", payload, nil},

		// RFC 9110 §8.4.1.2 defines deflate as zlib-framed...
		{"deflate as zlib", zlibBytes(t, payload), []string{"deflate"}},
		// ...but a long tail of servers send raw DEFLATE, which browsers accept.
		{"deflate as raw flate", rawFlateBytes(t, payload), []string{"deflate"}},

		// Chained codings are undone in reverse application order.
		{"gzip then br", brotliBytes(t, gzipBytes(t, payload)), []string{"gzip, br"}},
		{"br then gzip", gzipBytes(t, brotliBytes(t, payload)), []string{"br, gzip"}},
		{"chained across header lines", brotliBytes(t, gzipBytes(t, payload)), []string{"gzip", "br"}},
		{"chained with identity", brotliBytes(t, payload), []string{"identity, br"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := newResponse(tc.body, tc.encodings...)
			got, err := resp.Bytes()
			if err != nil {
				t.Fatalf("Bytes: %v", err)
			}
			if string(got) != want {
				t.Fatalf("decoded %q, want %q", got, want)
			}
		})
	}
}

// TestContentEncodingUnknownIsAnError pins that an unrecognised coding fails
// loudly. Handing back compressed bytes with a nil error is worse than an
// error: the caller has no way to notice.
func TestContentEncodingUnknownIsAnError(t *testing.T) {
	resp := newResponse([]byte("whatever"), "exi")
	got, err := resp.Bytes()
	if err == nil {
		t.Fatalf("unknown Content-Encoding accepted, returned %q", got)
	}
	if !strings.Contains(err.Error(), "exi") {
		t.Fatalf("error should name the coding, got %v", err)
	}
}

// countingCloser reports whether the body was drained to completion.
type countingCloser struct {
	r      io.Reader
	closed bool
	read   int
}

func (c *countingCloser) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func (c *countingCloser) Close() error { c.closed = true; return nil }

// TestMaxBodySizeDrainsBody pins that hitting the limit still consumes the
// body. Closing early makes HTTP/2 emit RST_STREAM, which Cloudflare and
// Akamai score as abusive — the signal Close and the drain pool exist to avoid.
func TestMaxBodySizeDrainsBody(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 4096)
	body := &countingCloser{r: bytes.NewReader(payload)}
	resp := &Response{
		Response:    &http.Response{Header: http.Header{}, Body: body},
		maxBodySize: 100,
	}

	if _, err := resp.Bytes(); err == nil {
		t.Fatal("oversized body accepted")
	}
	if body.read != len(payload) {
		t.Fatalf("drained %d of %d bytes; the stream would be reset", body.read, len(payload))
	}
	if !body.closed {
		t.Fatal("body was not closed")
	}
}

// TestBytesIsCached pins that the body is read once and replayed afterwards.
func TestBytesIsCached(t *testing.T) {
	resp := newResponse(gzipBytes(t, []byte("payload")), "gzip")
	first, err := resp.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	second, err := resp.Bytes()
	if err != nil {
		t.Fatalf("Bytes (cached): %v", err)
	}
	if string(first) != "payload" || string(second) != "payload" {
		t.Fatalf("got %q then %q, want %q both times", first, second, "payload")
	}
}

// TestHostProtoKey pins the canonical form both sides of the ALPN cache use.
// RoundTrip looks up req.URL.Host, which omits the default port, while the dial
// path stores the dialer's addr, which never does. Keying on the raw values
// meant non-standard ports never hit the cache, and a result learned from
// example.com:8443 was applied to example.com:443.
func TestHostProtoKey(t *testing.T) {
	cases := map[string]string{
		"example.com":        "example.com:443",
		"example.com:443":    "example.com:443",
		"example.com:8443":   "example.com:8443",
		"[2001:db8::1]":      "[2001:db8::1]:443",
		"[2001:db8::1]:8443": "[2001:db8::1]:8443",
		"2001:db8::1":        "[2001:db8::1]:443",
		"127.0.0.1":          "127.0.0.1:443",
	}
	for in, want := range cases {
		if got := hostProtoKey(in, "443"); got != want {
			t.Errorf("hostProtoKey(%q) = %q, want %q", in, got, want)
		}
	}

	// The two call sites must agree, which is the whole point.
	if hostProtoKey("example.com", "443") != hostProtoKey("example.com:443", "443") {
		t.Error("URL host and dial addr produce different keys for the same origin")
	}
	if hostProtoKey("example.com:8443", "443") == hostProtoKey("example.com", "443") {
		t.Error("a non-standard port collides with the default-port origin")
	}
}

// A response may not name an unbounded decoder chain.
//
// Every coding costs a decoder before a byte of body is read, and zstd's costs
// goroutines: zstd.NewReader validates nothing up front, so it allocates and
// spawns workers and returns successfully however many times it is nested.
// Measured before the bound: ten nested readers cost fourteen goroutines and
// fifty hung the process outright — bought with about three hundred bytes of
// response header, from the one party in this exchange that is not trusted.
func TestContentEncodingChainIsBounded(t *testing.T) {
	long := make([]string, maxContentCodings+1)
	for i := range long {
		long[i] = "zstd"
	}

	resp := newResponse(nil, long...)
	done := make(chan error, 1)
	go func() {
		_, err := resp.Bytes()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a chain past the bound was accepted")
		}
		if !strings.Contains(err.Error(), "content codings") {
			t.Errorf("error %q does not say what was refused", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("decoding a long coding chain hung — the bound is not being applied")
	}
}

// The bound must not reject the chains that are legal and do occur: RFC 9110
// §8.4 lists codings in the order they were applied, so this is undone
// last-first.
func TestContentEncodingShortChainStillWorks(t *testing.T) {
	const want = "chained"
	// Applied gzip first, then brotli, so the header reads "gzip, br".
	body := brotliBytes(t, gzipBytes(t, []byte(want)))

	got, err := newResponse(body, "gzip", "br").Bytes()
	if err != nil {
		t.Fatalf("a two-coding chain failed: %v", err)
	}
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
