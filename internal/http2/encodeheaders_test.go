package http2

import (
	"net/http"
	"strings"
	"testing"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/http2/hpack"
)

// The header block is the fingerprint. Order, names and values are what a peer
// hashes into an Akamai fingerprint, so any change to how encodeHeaders resolves
// them has to leave the bytes on the wire exactly where they were.
//
// This decodes what the encoder produced rather than asserting on internals,
// which is the only version of the question a server would ask.
// newBlockDecoder returns a decoder that survives across requests.
//
// One per connection, not one per block: HPACK is stateful, so the second
// request on a connection encodes most of its fields as references into the
// dynamic table the first one populated. A fresh decoder rejects those with
// "invalid indexed representation" — which is the encoder doing its job, and
// what a browser's connection does too.
func newBlockDecoder() (func(*testing.T, []byte) []string, *hpack.Decoder) {
	var out []string
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		out = append(out, f.Name+": "+f.Value)
	})
	return func(t *testing.T, block []byte) []string {
		t.Helper()
		out = nil
		if _, err := dec.Write(block); err != nil {
			t.Fatalf("decode header block: %v", err)
		}
		if err := dec.Close(); err != nil {
			t.Fatalf("close decoder: %v", err)
		}
		return out
	}, dec
}

func decodeBlock(t *testing.T, block []byte) []string {
	t.Helper()
	decode, _ := newBlockDecoder()
	return decode(t, block)
}

func TestEncodeHeadersOrder(t *testing.T) {
	cc := benchConn(chromeHeaderOrderForBench)
	req := benchRequest()

	block, err := cc.encodeHeaders(req, false, "", -1)
	if err != nil {
		t.Fatalf("encodeHeaders: %v", err)
	}
	got := decodeBlock(t, block)

	want := []string{
		// Pseudo-headers first, in the profile's own order.
		":method: GET",
		":authority: site.example",
		":scheme: https",
		":path: /",
		// Then the header order, skipping the entries this request has no
		// value for (content-type, content-length, origin, referer).
		`sec-ch-ua: "Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`,
		"sec-ch-ua-mobile: ?0",
		`sec-ch-ua-platform: "Linux"`,
		"upgrade-insecure-requests: 1",
		"user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
		"accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"sec-fetch-site: none",
		"sec-fetch-mode: navigate",
		"sec-fetch-user: ?1",
		"sec-fetch-dest: document",
		"accept-encoding: gzip, deflate, br, zstd",
		"accept-language: en-US,en;q=0.9",
		"priority: u=0, i",
		// Cookie is split on "; " into one field per crumb, which is what
		// HTTP/2 requires and what a browser does.
		"cookie: cf_clearance=abcdefghijklmnop",
		"cookie: __cf_bm=qrstuvwxyz",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d fields, want %d:\n got: %s\nwant: %s",
			len(got), len(want), strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
}

// A header whose name is not in canonical form only gets into the map by being
// written there directly, which net/http allows. The ordered lookup resolves
// canonical names directly now, so this is the path that keeps the rest correct.
func TestEncodeHeadersFindsNonCanonicalNames(t *testing.T) {
	cc := benchConn([]string{"User-Agent", "Accept", "Cookie"})
	req := benchRequest()
	// Bypass Set, which would canonicalise it.
	delete(req.Header, "Accept")
	req.Header["accept"] = []string{"text/plain"}

	got := decodeBlock(t, mustEncode(t, cc, req))
	var accept []string
	for _, f := range got {
		if strings.HasPrefix(f, "accept:") {
			accept = append(accept, f)
		}
	}
	if len(accept) != 1 || accept[0] != "accept: text/plain" {
		t.Fatalf("accept fields = %v, want the non-canonical entry emitted once", accept)
	}
	// And it has to land in its ordered position — after User-Agent and before
	// Cookie — rather than being swept up by the second pass that emits
	// whatever the order list missed.
	pos := func(prefix string) int {
		for i, f := range got {
			if strings.HasPrefix(f, prefix) {
				return i
			}
		}
		return -1
	}
	ua, acc, ck := pos("user-agent:"), pos("accept:"), pos("cookie:")
	if ua < 0 || acc < 0 || ck < 0 || !(ua < acc && acc < ck) {
		t.Errorf("order list not honoured for a non-canonical key: ua=%d accept=%d cookie=%d\n%v",
			ua, acc, ck, got)
	}
}

// Every header is emitted exactly once, including ones the order list does not
// name — those follow in a second pass rather than being dropped.
func TestEncodeHeadersEmitsEverythingOnce(t *testing.T) {
	cc := benchConn([]string{"User-Agent", "Accept"})
	req := benchRequest()
	req.Header.Set("X-Custom", "1")

	got := decodeBlock(t, mustEncode(t, cc, req))
	seen := map[string]int{}
	for _, f := range got {
		if strings.HasPrefix(f, ":") {
			continue // pseudo-headers have their own order test
		}
		seen[strings.SplitN(f, ":", 2)[0]]++
	}
	for name, n := range seen {
		if name == "cookie" {
			continue // one field per crumb, by design
		}
		if n != 1 {
			t.Errorf("%s emitted %d times", name, n)
		}
	}
	if seen["x-custom"] != 1 {
		t.Error("a header outside the order list was dropped")
	}
	if got[0] != ":method: GET" {
		t.Errorf("pseudo-headers moved: %v", got[:1])
	}
}

// Encoding is stateful — the HPACK dynamic table evolves — so the second request
// on a connection must still decode to the same fields as the first.
func TestEncodeHeadersStableAcrossRequests(t *testing.T) {
	cc := benchConn(chromeHeaderOrderForBench)
	req := benchRequest()

	decode, _ := newBlockDecoder()
	first := decode(t, mustEncode(t, cc, req))
	second := decode(t, mustEncode(t, cc, req))
	if len(first) != len(second) {
		t.Fatalf("%d fields then %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("field %d drifted: %q then %q", i, first[i], second[i])
		}
	}
}

func mustEncode(t *testing.T, cc *ClientConn, req *http.Request) []byte {
	t.Helper()
	block, err := cc.encodeHeaders(req, false, "", -1)
	if err != nil {
		t.Fatalf("encodeHeaders: %v", err)
	}
	return block
}
