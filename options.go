package gofire

import (
	"crypto/x509"
	"time"
)

// Option configures the Client.
type Option func(*clientConfig)

type clientConfig struct {
	transport TransportConfig

	// Client-level settings
	browser          BrowserProfile
	followRedirects  bool
	maxRedirects     int
	timeout          time.Duration
	acceptLanguage   string
	accept           string
	userAgent        string        // custom override, empty = use browser default
	referer          string        // default Referer header, empty = don't send
	maxResponseBody  int64         // max response body size in bytes, 0 = unlimited
	retryCount       int           // number of retries, 0 = no retry
	retryBaseDelay   time.Duration // base delay for exponential backoff
	retryStatusCodes []int         // HTTP status codes to retry on (e.g. 429, 502, 503, 504)
}

// defaultMaxResponseBody caps Response.Bytes() when the caller has not chosen a
// limit. Bytes() decodes Content-Encoding itself and this client advertises
// br and zstd, both of which reach compression ratios far past gzip's — an
// unlimited io.ReadAll over a decoder lets a hostile endpoint answer a few MiB
// of ciphertext with tens of GiB of plaintext and take the process out.
//
// 256 MiB is well beyond any body a caller would sensibly hold in memory (which
// is what Bytes() does regardless), so this bounds the damage without getting in
// the way. WithMaxResponseBodySize(0) still means genuinely unlimited for
// callers who want it.
const defaultMaxResponseBody = 256 << 20

// DefaultAcceptLanguage is the Accept-Language every profile sends unless
// WithAcceptLanguage overrides it.
//
// Exported because it is half of a pair. Anything that earns a credential in
// one browser and replays it from this one — solver/, above all — has to
// advertise the same language on both sides, and a value duplicated in two
// places is a value that drifts.
const DefaultAcceptLanguage = "en-US,en;q=0.9"

func defaultClientConfig() clientConfig {
	return clientConfig{
		transport:       defaultTransportConfig(),
		browser:         SafariIOS18,
		followRedirects: true,
		maxRedirects:    10,
		timeout:         30 * time.Second,
		acceptLanguage:  DefaultAcceptLanguage,
		accept:          defaultNavigateAccept,
		maxResponseBody: defaultMaxResponseBody,
	}
}

// WithTimeout sets the total request timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.timeout = d
	}
}

// WithProxy sets an HTTP/SOCKS5 proxy URL.
func WithProxy(proxyURL string) Option {
	return func(c *clientConfig) {
		c.transport.ProxyURL = proxyURL
	}
}

// WithMaxIdleConnsPerHost sets the maximum number of idle connections per host.
// Higher values improve RPS but use more memory. Default: 1000.
func WithMaxIdleConnsPerHost(n int) Option {
	return func(c *clientConfig) {
		c.transport.MaxIdleConnsPerHost = n
	}
}

// WithMaxIdleConns sets the total maximum idle connections. Default: 10000.
func WithMaxIdleConns(n int) Option {
	return func(c *clientConfig) {
		c.transport.MaxIdleConns = n
	}
}

// WithMaxConnsPerHost sets the maximum total connections per host (0=unlimited). Default: 0.
func WithMaxConnsPerHost(n int) Option {
	return func(c *clientConfig) {
		c.transport.MaxConnsPerHost = n
	}
}

// WithDisableKeepAlives disables HTTP keep-alive connections.
// NOT recommended for high RPS.
func WithDisableKeepAlives() Option {
	return func(c *clientConfig) {
		c.transport.DisableKeepAlives = true
	}
}

// WithForceHTTP1 forces HTTP/1.1 connections (disables HTTP/2).
func WithForceHTTP1() Option {
	return func(c *clientConfig) {
		c.transport.ForceHTTP1 = true
	}
}

// WithForceHTTP3 sends the first request to a host over QUIC, without waiting
// for it to advertise HTTP/3.
//
// Off by default, and that default is a fingerprint decision rather than a
// conservative one. Chrome learns about HTTP/3 from an Alt-Svc header on a TCP
// response and only then switches; a client whose first packet to an unknown
// host is a QUIC Initial is doing something no browser does, however good that
// Initial looks. Use this for a host already known to speak HTTP/3, and for
// measuring the QUIC fingerprint directly.
//
// Only the Chrome profile has a measured HTTP/3 fingerprint, so this does
// nothing under Safari — see newH3Transport.
func WithForceHTTP3() Option {
	return func(c *clientConfig) {
		c.transport.ForceHTTP3 = true
	}
}

// WithoutHTTP3 stops this client from using QUIC at all, even for a host that
// offered it.
func WithoutHTTP3() Option {
	return func(c *clientConfig) {
		c.transport.DisableHTTP3 = true
	}
}

// WithDisableRedirects disables automatic redirect following.
func WithDisableRedirects() Option {
	return func(c *clientConfig) {
		c.followRedirects = false
	}
}

// WithMaxRedirects sets the maximum number of redirects to follow.
func WithMaxRedirects(n int) Option {
	return func(c *clientConfig) {
		c.maxRedirects = n
	}
}

// WithIdleConnTimeout sets how long idle connections stay in the pool. Default: 90s.
func WithIdleConnTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.transport.IdleConnTimeout = d
	}
}

// WithTLSHandshakeTimeout sets the TLS handshake timeout. Default: 10s.
//
// It bounds one handshake attempt, and the dial retries up to three times, so
// the worst case for an unreachable-but-accepting host is roughly three times
// this. A deadline on the request context still wins whenever it is sooner.
func WithTLSHandshakeTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.transport.TLSHandshakeTimeout = d
	}
}

// WithDNSCacheTTL sets the DNS cache TTL. Default: 5m.
func WithDNSCacheTTL(d time.Duration) Option {
	return func(c *clientConfig) {
		c.transport.DNSCacheTTL = d
	}
}

// WithDialTimeout sets the TCP dial timeout. Default: 10s.
func WithDialTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.transport.DialTimeout = d
	}
}

// WithAcceptLanguage sets the Accept-Language header. Default:
// "en-US,en;q=0.9".
//
// Worth setting. The default is a device-locale value, not a browser constant —
// the iPhone the Safari profile is modelled on reports "tr-TR,tr;q=0.9" — and
// bot scoring compares it against the exit IP's geolocation. Requesting English
// from a Turkish residential address is a small inconsistency that costs
// nothing to remove: match the language to wherever your proxies exit.
func WithAcceptLanguage(lang string) Option {
	return func(c *clientConfig) {
		c.acceptLanguage = lang
	}
}

// WithAccept sets the Accept header.
func WithAccept(accept string) Option {
	return func(c *clientConfig) {
		c.accept = accept
	}
}

// WithRootCAs sets custom root certificate authorities for TLS verification.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(c *clientConfig) {
		c.transport.RootCAs = pool
	}
}

// WithInsecureSkipVerify disables TLS certificate verification.
func WithInsecureSkipVerify() Option {
	return func(c *clientConfig) {
		c.transport.InsecureSkipVerify = true
	}
}

// WithResponseHeaderTimeout sets the timeout for reading response headers. Default: 30s.
func WithResponseHeaderTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.transport.ResponseHeaderTimeout = d
	}
}

// WithEnableCompression is a no-op and is kept only for compatibility.
//
// Deprecated: response bodies are always decompressed. It flips
// http.Transport.DisableCompression, which controls net/http's transparent
// gzip — but that path only engages when the request carries no
// Accept-Encoding, and the browser profiles always set one. Decompression is
// handled by Response.Bytes instead, which covers gzip, br, deflate and zstd
// including chained encodings, whatever this option is set to.
func WithEnableCompression() Option {
	return func(c *clientConfig) {
		c.transport.DisableCompression = false
	}
}

// WithWriteBufferSize sets the write buffer size per connection. Default: 64KB.
func WithWriteBufferSize(n int) Option {
	return func(c *clientConfig) {
		c.transport.WriteBufferSize = n
	}
}

// WithReadBufferSize sets the read buffer size per connection. Default: 64KB.
func WithReadBufferSize(n int) Option {
	return func(c *clientConfig) {
		c.transport.ReadBufferSize = n
	}
}

// WithMaxStreamsPerConn sets how many HTTP/2 streams a single connection
// handles before being cycled. Lower = more TLS handshakes (more fingerprint
// noise but also more origin load). Higher = fewer handshakes, but a long
// monotonic stream-ID sequence is a passive fingerprint signal. Default: 8000.
// For pure throughput without fingerprint concerns, 50000+ is reasonable.
func WithMaxStreamsPerConn(n int) Option {
	return func(c *clientConfig) {
		c.transport.MaxStreamsPerConn = n
	}
}

// WithSocketBuffers sets the Linux SO_RCVBUF / SO_SNDBUF sizes in bytes.
// Default 256KB is conservative; raise to 1-4MB on high-throughput links with
// non-trivial RTT (large bandwidth-delay product). No-op on non-Linux.
func WithSocketBuffers(rcv, snd int) Option {
	return func(c *clientConfig) {
		c.transport.SocketRcvBuf = rcv
		c.transport.SocketSndBuf = snd
	}
}

// WithTCPFastOpen enables TCP_FASTOPEN_CONNECT on Linux, saving one RTT on
// repeat dials to a host the kernel holds a cookie for. No-op on other
// platforms.
//
// It is off by default because no shipping browser uses TFO — Chrome dropped
// client support in 2020 — so a SYN carrying payload contradicts, at the
// transport layer, the browser this client impersonates everywhere above it.
// Enable it when throughput against a permissive target matters more than
// looking like a browser end to end.
func WithTCPFastOpen() Option {
	return func(c *clientConfig) {
		c.transport.TCPFastOpen = true
	}
}

// WithTLSSessionResumption offers a cached TLS 1.3 session ticket as a
// pre_shared_key on the second and later connections to a host, the way a
// browser does.
//
// Off by default. Resuming is what Chrome does, and never resuming across
// hundreds of connections to one host is itself a pattern — but offering a PSK
// adds an extension to the ClientHello and moves JA4 from t13d1516h2 to
// t13d1517h2, so the resumed connection no longer carries the fingerprint this
// package pins. That resumed shape has been checked against a Go TLS server,
// not against a capture of real Chrome resuming against a real edge.
//
// Tickets are scoped to the egress that earned them, so this is safe to combine
// with a proxy rotator: a ticket is never offered from an exit other than the
// one the server issued it to.
func WithTLSSessionResumption() Option {
	return func(c *clientConfig) {
		c.transport.TLSSessionResumption = true
	}
}

// WithWriteByteTimeout caps how long an HTTP/2 frame write may block.
// Default 30s is browser-lenient; for high-RPS workloads with proxies that
// occasionally stall, 5-10s prevents a slow peer from pinning a worker.
func WithWriteByteTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.transport.WriteByteTimeout = d
	}
}

// WithUserAgent sets a custom User-Agent header, overriding the browser profile default.
func WithUserAgent(ua string) Option {
	return func(c *clientConfig) {
		c.userAgent = ua
	}
}

// WithReferer sets a default Referer header on all requests.
func WithReferer(referer string) Option {
	return func(c *clientConfig) {
		c.referer = referer
	}
}

// WithMaxResponseBodySize sets the maximum allowed response body size in bytes,
// measured after Content-Encoding is decoded. Responses exceeding the limit
// return an error (the body is still drained, so the HTTP/2 stream ends with
// END_STREAM rather than RST_STREAM).
//
// Default: 256 MiB, see defaultMaxResponseBody. Pass 0 for genuinely unlimited,
// which removes the only guard against a decompression bomb.
func WithMaxResponseBodySize(n int64) Option {
	return func(c *clientConfig) {
		c.maxResponseBody = n
	}
}

// WithRetry enables automatic retry with exponential backoff.
// count is the number of retry attempts (e.g. 3 means up to 3 retries after the initial request).
// baseDelay is the initial delay between retries (doubles each attempt).
// statusCodes are the HTTP status codes that trigger a retry (e.g. 429, 502, 503, 504).
// Network errors are always retried regardless of statusCodes.
func WithRetry(count int, baseDelay time.Duration, statusCodes ...int) Option {
	return func(c *clientConfig) {
		c.retryCount = count
		c.retryBaseDelay = baseDelay
		c.retryStatusCodes = statusCodes
	}
}
