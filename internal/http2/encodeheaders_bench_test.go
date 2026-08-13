package http2

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/http2/hpack"
)

// encodeHeaders runs once per request, twice over the header set (once to size
// the block, once to encode it), and both times while holding cc.wmu — the lock
// every other stream on the connection is queued behind. So its cost is not only
// CPU: it is the width of the critical section that decides how far a single
// HTTP/2 connection can be driven.
//
// The order and the header set here are the real ones: chromeHeaderOrder from
// headers.go, against the headers a Chrome-profile navigation actually carries.
func benchConn(order []string) *ClientConn {
	cc := &ClientConn{
		t: &Transport{
			HeaderOrder:       order,
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		},
		peerMaxHeaderListSize: 1 << 20,
	}
	cc.henc = hpack.NewEncoder(&cc.hbuf)
	return cc
}

func benchRequest() *http.Request {
	h := http.Header{}
	for _, kv := range [][2]string{
		{"Sec-Ch-Ua", `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`},
		{"Sec-Ch-Ua-Mobile", "?0"},
		{"Sec-Ch-Ua-Platform", `"Linux"`},
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-User", "?1"},
		{"Sec-Fetch-Dest", "document"},
		{"Accept-Encoding", "gzip, deflate, br, zstd"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Priority", "u=0, i"},
		{"Cookie", "cf_clearance=abcdefghijklmnop; __cf_bm=qrstuvwxyz"},
	} {
		h.Set(kv[0], kv[1])
	}
	return &http.Request{
		Method: "GET",
		URL:    &url.URL{Scheme: "https", Host: "site.example", Path: "/"},
		Host:   "site.example",
		Header: h,
	}
}

func BenchmarkEncodeHeaders(b *testing.B) {
	cc := benchConn(chromeHeaderOrderForBench)
	req := benchRequest()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cc.encodeHeaders(req, false, "", -1); err != nil {
			b.Fatal(err)
		}
	}
}

// chromeHeaderOrderForBench mirrors headers.go's chromeHeaderOrder. It is copied
// rather than imported because that list lives in the parent package, which
// imports this one.
var chromeHeaderOrderForBench = []string{
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile",
	"Sec-Ch-Ua-Platform",
	"Upgrade-Insecure-Requests",
	"User-Agent",
	"Accept",
	"Content-Type",
	"Content-Length",
	"Origin",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-User",
	"Sec-Fetch-Dest",
	"Referer",
	"Accept-Encoding",
	"Accept-Language",
	"Priority",
	"Cookie",
}
