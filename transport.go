package gofire

import (
	"context"
	cryptorand "crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	ctls "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/ctls"
	http2 "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/http2"
)

// Transport is a high-performance HTTP transport with browser fingerprint
// emulation. Safari iOS 18 and Chrome 150 are supported.
//
// It emulates both TLS (JA3/JA4) and HTTP/2 (Akamai) fingerprints using a custom
// TLS 1.3 implementation (internal/ctls) - no uTLS dependency. Everything below
// is selected from the BrowserProfile passed to newTransport:
//
//   - TLS: ClientHello built at the byte level. Safari: GREASE,
//     MLKEM768+X25519 key shares, no padding extension, zlib
//     compress_certificate. Chrome: GREASE, per-connection extension shuffle,
//     MLKEM768+X25519 key shares, ALPS, ECH GREASE, brotli
//     compress_certificate.
//   - HTTP/2 SETTINGS: Safari sends ENABLE_PUSH, MAX_CONCURRENT_STREAMS=100,
//     INITIAL_WINDOW_SIZE=2097152, NO_RFC7540_PRIORITIES=1. Chrome sends
//     HEADER_TABLE_SIZE=65536, ENABLE_PUSH, INITIAL_WINDOW_SIZE=6291456,
//     MAX_HEADER_LIST_SIZE=262144.
//   - HTTP/2 WINDOW_UPDATE: Safari 10420225, Chrome 15663105.
//   - HTTP/2 Header Order: exact per-browser header order via HPACK.
//   - HTTP/2 Pseudo-header Order: Safari m,s,a,p - Chrome m,a,s,p.
type Transport struct {
	h1Transport *http.Transport  // HTTP/1.1 fallback
	h2Transport *http2.Transport // HTTP/2 with browser settings

	h2Settings  H2Settings
	headerOrder []string
	forceH1     bool
	rootCAs     *x509.CertPool
	skipVerify  bool
	browser     BrowserProfile
	ctlsBrowser ctls.BrowserType // which ClientHello the TLS layer builds
	dnscache    *dnsCache
	connCount   atomic.Int64
	dialer      *net.Dialer

	// hostProto records the ALPN protocol negotiated per host so subsequent
	// requests skip the h2 attempt for hosts that only speak http/1.1. Without
	// this cache every request to an h1-only host would dial twice (once for
	// h2 to fail, once for h1) and h2Transport would also panic by feeding the
	// h2 preface into an http/1.1 connection.
	//
	// Keys are always the canonical host:port from hostProtoKey; see the note
	// there. Values are hostProtoEntry.
	hostProto sync.Map

	// Proxy support - used directly in dialTLS to tunnel through proxies
	proxyMu      sync.RWMutex
	proxyFunc    func(*http.Request) (*url.URL, error) // nil = no proxy
	proxyRotator *ProxyRotator                         // nil unless SetProxyRotator was used
}

// errAlpnHTTP1 is the sentinel dialTLSForH2 returns when the server picked
// http/1.1 over h2. RoundTrip catches it and routes to h1Transport instead.
var errAlpnHTTP1 = errors.New("ctls: server negotiated http/1.1, not h2")

// TransportConfig holds configuration for creating a Transport.
type TransportConfig struct {
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	DisableKeepAlives     bool
	DisableCompression    bool
	ForceHTTP1            bool
	ProxyURL              string
	RootCAs               *x509.CertPool
	InsecureSkipVerify    bool
	DNSCacheTTL           time.Duration
	DialTimeout           time.Duration
	ResponseHeaderTimeout time.Duration
	WriteBufferSize       int
	ReadBufferSize        int
	// MaxStreamsPerConn cycles the HTTP/2 connection after this many streams.
	// Lower = more frequent TLS handshakes (fingerprint noise). Higher = fewer
	// handshakes but a long monotonic stream-ID sequence is a passive
	// fingerprint signal. Default: 8000 (browser-ish). Set to 50000+ for
	// pure throughput when fingerprint sensitivity is low.
	MaxStreamsPerConn int
	// SocketRcvBuf / SocketSndBuf override the Linux SO_RCVBUF / SO_SNDBUF
	// sizes (in bytes). Default 256KB is conservative; raise to 1-4MB for
	// high-throughput links with non-trivial RTT (large BDP). 0 = default.
	SocketRcvBuf int
	SocketSndBuf int
	// WriteByteTimeout caps how long an h2 frame write may block. Default 30s
	// is browser-lenient; for high-RPS workloads with proxies that occasionally
	// stall, 5-10s prevents a slow peer from pinning a worker.
	WriteByteTimeout time.Duration
}

func defaultTransportConfig() TransportConfig {
	return TransportConfig{
		MaxIdleConns:          10000,
		MaxIdleConnsPerHost:   1000,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    true,
		ForceHTTP1:            false,
		InsecureSkipVerify:    false,
		DNSCacheTTL:           5 * time.Minute,
		DialTimeout:           10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		WriteBufferSize:       64 * 1024,
		ReadBufferSize:        64 * 1024,
		MaxStreamsPerConn:     8000,
		SocketRcvBuf:          256 * 1024,
		SocketSndBuf:          256 * 1024,
		WriteByteTimeout:      30 * time.Second,
	}
}

// newTransport creates a new Transport with full browser fingerprint emulation.
func newTransport(cfg TransportConfig, browser BrowserProfile) *Transport {
	t := &Transport{
		forceH1:    cfg.ForceHTTP1,
		rootCAs:    cfg.RootCAs,
		skipVerify: cfg.InsecureSkipVerify,
		dnscache:   newDNSCache(cfg.DNSCacheTTL),
		browser:    browser,
	}

	// Per-browser fingerprint tables.
	switch browser {
	case Chrome150:
		t.h2Settings = Chrome146H2Settings()
		t.headerOrder = chromeHeaderOrder
		t.ctlsBrowser = ctls.BrowserChrome
	default:
		t.h2Settings = SafariIOS18H2Settings()
		t.headerOrder = safariIOS18HeaderOrder
		t.ctlsBrowser = ctls.BrowserSafari
	}

	rcvBuf := cfg.SocketRcvBuf
	if rcvBuf <= 0 {
		rcvBuf = 256 * 1024
	}
	sndBuf := cfg.SocketSndBuf
	if sndBuf <= 0 {
		sndBuf = 256 * 1024
	}
	t.dialer = &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = setSocketOpts(fd, rcvBuf, sndBuf)
			})
			return err
		},
	}

	wbs := cfg.WriteBufferSize
	if wbs <= 0 {
		wbs = 64 * 1024
	}
	rbs := cfg.ReadBufferSize
	if rbs <= 0 {
		rbs = 64 * 1024
	}

	// HTTP/1.1 transport (for plain HTTP or ForceHTTP1 mode)
	t.h1Transport = &http.Transport{
		DialContext:           t.dialWithDNSCache(),
		DialTLSContext:        t.dialTLSForH1(),
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		DisableKeepAlives:     cfg.DisableKeepAlives,
		DisableCompression:    cfg.DisableCompression,
		ForceAttemptHTTP2:     false, // We handle HTTP/2 ourselves
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		WriteBufferSize:       wbs,
		ReadBufferSize:        rbs,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// HTTP/2 transport with the selected browser's fingerprint.
	if !cfg.ForceHTTP1 {
		h2p := SafariIOS18H2Profile()
		if browser == Chrome150 {
			h2p = Chrome146H2Profile()
		}

		// MaxReadFrameSize controls the framer's accept cap (NOT what we advertise).
		// We advertise the browser's MAX_FRAME_SIZE via the custom Settings slice below,
		// but real browsers tolerate frames larger than they advertise. Setting the cap
		// to 1MB matches Go stdlib's defaultMaxReadFrameSize and prevents
		// ErrFrameTooLarge ("http2: frame too large") on CDNs that occasionally
		// emit slightly oversized DATA/HEADERS frames under load.
		const framerAcceptCap = 1 << 20 // 1MB

		t.h2Transport = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *cryptotls.Config) (net.Conn, error) {
				return t.dialTLSForH2(ctx, network, addr)
			},
			DisableCompression:        cfg.DisableCompression,
			AllowHTTP:                 false,
			MaxDecoderHeaderTableSize: t.h2Settings.HeaderTableSize,
			MaxReadFrameSize:          framerAcceptCap,
			Settings:                  buildH2Settings(t.h2Settings),
			ConnectionFlow:            t.h2Settings.ConnectionWindowSize,
			PseudoHeaderOrder:         h2p.PseudoHeaders,
			HeaderOrder:               t.headerOrder,
			HeaderPriority: http2.PriorityParam{
				Weight:    h2p.PriorityWeight,
				Exclusive: h2p.PriorityExclusive,
			},
			StrictMaxConcurrentStreams: false,
			ReadIdleTimeout:            15 * time.Second,
			PingTimeout:                5 * time.Second,
			WriteByteTimeout:           cfg.WriteByteTimeout,
			// Cycle the H2 conn after this many streams. Real browsers don't push
			// 100k+ streams over a single connection; a long monotonic
			// stream-ID sequence is a passive fingerprint signal. Configurable
			// via TransportConfig.MaxStreamsPerConn — raise for pure throughput.
			MaxStreamsPerConn: uint32(cfg.MaxStreamsPerConn),
		}
	}

	return t
}

// RoundTrip implements http.RoundTripper with full fingerprint emulation.
//
// For HTTPS it tries the HTTP/2 transport first, but falls back to
// HTTP/1.1 if the host has previously negotiated http/1.1 (cached via
// hostProto) or if the h2 dial fails with errAlpnHTTP1. The cache means
// h1-only hosts pay the dial-and-fallback cost exactly once.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || t.forceH1 || t.h2Transport == nil {
		return t.h1Transport.RoundTrip(req)
	}

	if t.prefersHTTP1(hostProtoKey(req.URL.Host, "443")) {
		return t.h1Transport.RoundTrip(req)
	}

	resp, err := t.h2Transport.RoundTrip(req)
	if err != nil && errors.Is(err, errAlpnHTTP1) {
		// dialTLSForH2 already cached host->http/1.1; retry on h1.
		return t.h1Transport.RoundTrip(req)
	}
	return resp, err
}

// dialWithDNSCache returns the DialContext used for cleartext HTTP. Only
// h1Transport uses it, so the returned conn carries the HTTP/1.1 header-order
// rewriter.
//
// It goes through dialRaw, which is what applies the configured proxy or
// rotator. Dialling t.dialer directly here — the previous behaviour — meant
// every http:// request went out from the real IP no matter what WithProxy or
// SetProxyRotator was set to, because http.Transport.Proxy is deliberately left
// nil (proxying is handled at the dial layer so the rotator can score each
// proxy's health). dialRaw falls back to a direct, DNS-cached dial when no
// proxy is configured, so the unproxied path is unchanged.
func (t *Transport) dialWithDNSCache() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host, port = addr, "80"
		}

		conn, err := t.dialRaw(ctx, network, host, port)
		if err != nil {
			return nil, err
		}
		return newH1OrderConn(conn, t.headerOrder), nil
	}
}

// dialTLSForH1 creates ctls connections for HTTP/1.1 (ALPN: http/1.1 only).
//
// The conn is wrapped so request headers go out in the browser's order.
// net/http sorts them alphabetically with no hook to intervene, so the h1 path
// would otherwise emit an order no browser produces — losing the header-order
// half of the fingerprint on every h1-only host and under WithForceHTTP1, while
// h2 kept its order through HPACK.
func (t *Transport) dialTLSForH1() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := t.dialTLS(ctx, network, addr, []string{"http/1.1"})
		if err != nil {
			return nil, err
		}
		return newH1OrderConn(conn, t.headerOrder), nil
	}
}

// dialTLSForH2 creates ctls connections for HTTP/2 (ALPN: h2, http/1.1) and
// rejects the conn if the server picked http/1.1. With a custom DialTLSContext
// the http2 transport otherwise skips its own ALPN check (transport.go:826-843)
// and pumps the h2 preface into an http/1.1 socket, which silently kills every
// request to h1-only hosts. We surface errAlpnHTTP1 so RoundTrip can fall back
// to h1Transport and cache the host as http/1.1 for future requests.
func (t *Transport) dialTLSForH2(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := t.dialTLS(ctx, network, addr, []string{"h2", "http/1.1"})
	if err != nil {
		return nil, err
	}
	if alpnConn, ok := conn.(interface{ NegotiatedProtocol() string }); ok {
		if proto := alpnConn.NegotiatedProtocol(); proto != "" && proto != "h2" {
			t.hostProto.Store(hostProtoKey(addr, "443"), hostProtoEntry{
				proto:   "http/1.1",
				expires: time.Now().Add(hostProtoTTL),
			})
			conn.Close()
			return nil, errAlpnHTTP1
		}
	}
	return conn, nil
}

// hostProtoTTL bounds how long an http/1.1 negotiation is remembered. Without
// it, a host that fell back to HTTP/1.1 once — during an incident, or behind a
// misconfigured edge node — stays pinned to HTTP/1.1 for the life of the
// process, and the map only ever grows.
const hostProtoTTL = 10 * time.Minute

type hostProtoEntry struct {
	proto   string
	expires time.Time
}

// hostProtoKey canonicalises a host into the host:port form that both the
// RoundTrip lookup and the dial-time store agree on.
//
// req.URL.Host omits the default port while the dialer's addr always carries
// one, so keying on the raw values meant the cache never hit for a host on a
// non-standard port — every request paid dial, fail, redial — and, worse, a
// result learned from example.com:8443 was stored under "example.com" and then
// applied to example.com:443, routing ordinary HTTPS traffic to HTTP/1.1.
func hostProtoKey(host, defaultPort string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	// Either a bracketed host with no port or a bare IPv6 literal lands here.
	// JoinHostPort re-adds brackets, so strip any that are already present
	// rather than producing [[::1]]:443.
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return net.JoinHostPort(host, defaultPort)
}

// prefersHTTP1 reports whether key is known to speak only HTTP/1.1, dropping
// the record once it has aged out.
func (t *Transport) prefersHTTP1(key string) bool {
	v, ok := t.hostProto.Load(key)
	if !ok {
		return false
	}
	entry, ok := v.(hostProtoEntry)
	if !ok {
		t.hostProto.Delete(key)
		return false
	}
	if time.Now().After(entry.expires) {
		t.hostProto.Delete(key)
		return false
	}
	return entry.proto == "http/1.1"
}

// dialTLS performs TLS handshake using our custom ctls package with browser-specific ClientHello.
//
// Includes a bounded retry loop on transient failures (EOF, connection reset,
// i/o timeout). Under heavy parallel dialing - thousands of workers all
// opening connections to the same edge - some TCP/TLS handshakes get dropped
// by the load balancer or fail mid-handshake. Real browsers retry these
// transparently; our previous behavior surfaced them to the worker as
// "tls handshake failed" errors, polluting blaze's error report.
func (t *Transport) dialTLS(ctx context.Context, network, addr string, alpn []string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	// When a proxy rotator is configured, do exactly one TLS dial attempt:
	// every retry calls dialRaw again which would consume another proxy from
	// the rotator, meaning a single request could burn N proxies. User wants
	// 1 request = 1 proxy. The next request will naturally pick a fresh
	// proxy via round-robin if this one fails.
	t.proxyMu.RLock()
	hasRotator := t.proxyRotator != nil
	t.proxyMu.RUnlock()

	// Retry budget:
	//   - rotator: 1 attempt (each retry would burn another proxy from the
	//     rotation; user contract is 1 request = 1 proxy).
	//   - direct:  3 attempts with tight jittered backoff (5-15ms, 10-30ms).
	//     Under heavy concurrent dialing the edge LB occasionally drops a
	//     handshake mid-flight; recovering in ~10ms instead of ~100ms is the
	//     difference between a worker resuming this second vs next second,
	//     which is a real RPS hit when thousands of workers are racing.
	maxAttempts := 3
	if hasRotator {
		maxAttempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Tight jittered backoff for the direct path. Attempt 1: 5-15ms,
			// attempt 2: 10-30ms. The window stays attempt-scaled so future
			// maxAttempts bumps extend it naturally without rewriting the math.
			minMs := 5 * attempt
			maxMs := 10 + 10*attempt
			delay := time.Duration(minMs+secureRandIntn(maxMs-minMs)) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		rawConn, err := t.dialRaw(ctx, network, host, port)
		if err != nil {
			lastErr = err
			if !isTransientDialErr(err) {
				return nil, err
			}
			continue
		}

		tlsConn, err := ctls.WrapConn(ctx, rawConn, host, alpn, t.skipVerify, t.rootCAs, t.ctlsBrowser)
		if err != nil {
			// WrapConn closes rawConn on every failure path, so there is
			// nothing to close here.
			// WrapConn already prefixes "tls handshake:"; don't double-wrap.
			// The underlying detail (e.g. "read server hello record: i/o
			// timeout") is what makes proxy failures diagnosable, so keep it.
			lastErr = err
			if !isTransientDialErr(err) {
				return nil, lastErr
			}
			continue
		}

		t.connCount.Add(1)
		return tlsConn, nil
	}
	return nil, lastErr
}

// isTransientDialErr classifies errors that are worth retrying. We only
// retry connection-level transients - protocol errors, certificate failures,
// and context cancellation surface immediately.
func isTransientDialErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "EOF") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "no route to host") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "TLS handshake failure") ||
		strings.Contains(s, "unexpected EOF")
}

// secureRandIntn returns a random int in [0, n) using crypto/rand.
// Used for handshake retry jitter; not on the hot path.
//
// The value is assembled as a uint32 and only then narrowed. Building it in an
// int and negating a negative result was fine on 64-bit, where the four bytes
// can never overflow, but on a 32-bit build 0x80000000 negates to itself — so
// the result stayed negative, the caller's minMs+jitter could go below zero,
// and time.After of a negative duration fires immediately, removing the very
// backoff this exists to provide.
func secureRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var b [4]byte
	_, _ = cryptorand.Read(b[:])
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return int(v % uint32(n))
}

// dialRaw establishes a raw TCP connection, optionally through a proxy.
//
// When a ProxyRotator is configured, dial failures are reported back so dead
// proxies are taken out of rotation, and a single dial will retry up to
// proxyDialAttempts times against different rotator entries before giving up.
// This keeps a few dead members of a large proxy list from translating into
// per-request failures.
func (t *Transport) dialRaw(ctx context.Context, network, host, port string) (net.Conn, error) {
	t.proxyMu.RLock()
	proxyFunc := t.proxyFunc
	rotator := t.proxyRotator
	t.proxyMu.RUnlock()

	targetAddr := net.JoinHostPort(host, port)

	if rotator != nil {
		// One proxy per dial. If this proxy fails the rotator marks it as
		// failed and the next request naturally picks a different proxy via
		// round-robin in NextEntry(). Retrying within a single dial wasted
		// the parent ctx budget AND meant 1 request consumed up to N
		// proxies — user wants exactly 1 proxy per request.
		const proxyDialAttempts = 1
		var lastErr error
		for attempt := 0; attempt < proxyDialAttempts; attempt++ {
			proxyURL, entry := rotator.nextProxyEntry()
			if proxyURL == nil {
				break
			}
			conn, err := t.dialViaProxy(ctx, network, targetAddr, proxyURL)
			if err == nil {
				rotator.MarkSuccess(entry)
				return conn, nil
			}
			rotator.MarkFailure(entry)
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		// A configured rotator MUST NOT silently fall through to a direct
		// connection — the user expects every request to go through a proxy.
		// Surface the failure (or an explicit "no proxies" error if the rotator
		// is empty) instead of leaking the client's real IP.
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("proxy rotator: no usable proxies")
	} else if proxyFunc != nil {
		dummyReq := &http.Request{URL: &url.URL{Scheme: "https", Host: targetAddr}}
		proxyURL, err := proxyFunc(dummyReq)
		if err != nil {
			return nil, fmt.Errorf("proxy func: %w", err)
		}
		if proxyURL != nil {
			return t.dialViaProxy(ctx, network, targetAddr, proxyURL)
		}
	}

	// Direct connection with DNS cache
	ip, err := t.dnscache.lookup(host)
	if err != nil {
		ip = host
	}

	dialAddr := targetAddr
	if ip != host {
		dialAddr = net.JoinHostPort(ip, port)
	}

	conn, err := t.dialer.DialContext(ctx, network, dialAddr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}
	return conn, nil
}

// dialViaProxy connects through a proxy. Supports HTTP CONNECT, HTTPS CONNECT
// (TLS to the proxy first), and SOCKS5 (RFC 1928) with optional username/password
// authentication (RFC 1929).
func (t *Transport) dialViaProxy(ctx context.Context, network, targetAddr string, proxyURL *url.URL) (net.Conn, error) {
	scheme := strings.ToLower(proxyURL.Scheme)
	switch scheme {
	case "socks5", "socks5h":
		return t.dialViaSocks5(ctx, network, targetAddr, proxyURL)
	case "http", "https", "":
		return t.dialViaHTTPConnect(ctx, network, targetAddr, proxyURL)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
}

// proxyDefaultPort returns the conventional default port for a proxy scheme.
func proxyDefaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		return "443"
	case "socks5", "socks5h":
		return "1080"
	default:
		return "8080"
	}
}

// dialViaHTTPConnect implements HTTP CONNECT tunneling. For "https" scheme it
// performs a real TLS handshake to the proxy first.
//
// The classic bufio bug in this routine: a bufio.Reader over the proxy conn
// can read MORE bytes than just the CONNECT response (it greedily fills its
// buffer). After CONNECT 200 the next bytes belong to the inner TLS handshake,
// so any byte stuck in the bufio buffer is silently lost the moment the TLS
// layer reads from the underlying conn directly. We protect against this by
// reading the response status+headers byte-by-byte until "\r\n\r\n", so the
// underlying conn's read offset is exactly at the start of the tunneled stream.
func (t *Transport) dialViaHTTPConnect(ctx context.Context, network, targetAddr string, proxyURL *url.URL) (net.Conn, error) {
	proxyHost := proxyURL.Hostname()
	proxyPort := proxyURL.Port()
	if proxyPort == "" {
		proxyPort = proxyDefaultPort(proxyURL.Scheme)
	}
	proxyAddr := net.JoinHostPort(proxyHost, proxyPort)

	rawConn, err := t.dialer.DialContext(ctx, network, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}

	// HTTPS proxy: TLS-wrap the tunnel BEFORE sending CONNECT.
	var proxyConn net.Conn = rawConn
	if strings.ToLower(proxyURL.Scheme) == "https" {
		tlsCfg := &cryptotls.Config{
			ServerName:         proxyHost,
			InsecureSkipVerify: t.skipVerify,
			RootCAs:            t.rootCAs,
		}
		tlsConn := cryptotls.Client(rawConn, tlsCfg)
		if deadline, ok := ctx.Deadline(); ok {
			tlsConn.SetDeadline(deadline)
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("tls handshake to proxy %s: %w", proxyAddr, err)
		}
		proxyConn = tlsConn
	}

	if deadline, ok := ctx.Deadline(); ok {
		proxyConn.SetDeadline(deadline)
	}

	// Build CONNECT request.
	var b strings.Builder
	b.WriteString("CONNECT ")
	b.WriteString(targetAddr)
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(targetAddr)
	b.WriteString("\r\nProxy-Connection: keep-alive\r\nUser-Agent: gofire\r\n")
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		b.WriteString("Proxy-Authorization: Basic ")
		b.WriteString(auth)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")

	if _, err := proxyConn.Write([]byte(b.String())); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("write CONNECT to %s: %w", proxyAddr, err)
	}

	statusLine, err := readHeaderLine(proxyConn)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("read CONNECT status from %s: %w", proxyAddr, err)
	}
	// Drain the rest of the response headers byte-by-byte until empty line.
	for {
		line, err := readHeaderLine(proxyConn)
		if err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("read CONNECT headers from %s: %w", proxyAddr, err)
		}
		if line == "" {
			break
		}
	}

	// Parse "HTTP/1.1 200 ..." status line.
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		proxyConn.Close()
		return nil, fmt.Errorf("malformed CONNECT response from %s: %q", proxyAddr, statusLine)
	}
	if parts[1] != "200" {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy %s CONNECT failed: %s", proxyAddr, statusLine)
	}

	proxyConn.SetDeadline(time.Time{})
	return proxyConn, nil
}

// readHeaderLine reads a single CRLF-terminated header line from conn,
// byte-by-byte. We avoid bufio because any byte buffered past the end of the
// CONNECT response would be lost when the caller starts reading the tunneled
// (TLS) bytes directly from conn.
func readHeaderLine(conn net.Conn) (string, error) {
	const maxLine = 4096
	var line []byte
	var prev byte
	buf := make([]byte, 1)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		c := buf[0]
		line = append(line, c)
		if prev == '\r' && c == '\n' {
			return string(line[:len(line)-2]), nil
		}
		prev = c
		if len(line) > maxLine {
			return "", fmt.Errorf("header line too long")
		}
	}
}

// dialViaSocks5 implements RFC 1928 SOCKS5 + RFC 1929 username/password auth.
// We send the target as a domain name (ATYP=0x03) when the target host is not
// a literal IP, so the proxy does the DNS resolution - this is the standard
// "socks5h" behavior and avoids local DNS leak / mismatch.
func (t *Transport) dialViaSocks5(ctx context.Context, network, targetAddr string, proxyURL *url.URL) (net.Conn, error) {
	proxyHost := proxyURL.Hostname()
	proxyPort := proxyURL.Port()
	if proxyPort == "" {
		proxyPort = proxyDefaultPort(proxyURL.Scheme)
	}
	proxyAddr := net.JoinHostPort(proxyHost, proxyPort)

	conn, err := t.dialer.DialContext(ctx, network, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 %s: %w", proxyAddr, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	var (
		username string
		password string
	)
	if proxyURL.User != nil {
		username = proxyURL.User.Username()
		password, _ = proxyURL.User.Password()
	}

	// Greeting: VER=5, NMETHODS, METHODS...
	if username != "" || password != "" {
		// Offer both no-auth and user/pass; let the server pick.
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 greeting: %w", err)
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 greeting: %w", err)
		}
	}

	// Method selection response: VER, METHOD
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 method select: %w", err)
	}
	if resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5 bad version 0x%02x from %s", resp[0], proxyAddr)
	}

	switch resp[1] {
	case 0x00:
		// no auth
	case 0x02:
		// username/password (RFC 1929)
		if username == "" && password == "" {
			conn.Close()
			return nil, fmt.Errorf("socks5 %s requires auth, none provided", proxyAddr)
		}
		if len(username) > 255 || len(password) > 255 {
			conn.Close()
			return nil, fmt.Errorf("socks5 username/password too long")
		}
		authReq := make([]byte, 0, 3+len(username)+len(password))
		authReq = append(authReq, 0x01, byte(len(username)))
		authReq = append(authReq, username...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, password...)
		if _, err := conn.Write(authReq); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth write: %w", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth read: %w", err)
		}
		if authResp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5 %s auth rejected (0x%02x)", proxyAddr, authResp[1])
		}
	case 0xFF:
		conn.Close()
		return nil, fmt.Errorf("socks5 %s rejected all auth methods", proxyAddr)
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5 %s selected unsupported method 0x%02x", proxyAddr, resp[1])
	}

	// CONNECT request: VER, CMD=CONNECT, RSV=0, ATYP, ADDR, PORT
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 split host: %w", err)
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 port parse: %w", err)
	}
	port := uint16(port64)

	req := make([]byte, 0, 22)
	req = append(req, 0x05, 0x01, 0x00)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("socks5 hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect write: %w", err)
	}

	// Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 reply read: %w", err)
	}
	if head[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5 bad reply version 0x%02x", head[0])
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 %s connect failed: %s", proxyAddr, socks5ReplyMsg(head[1]))
	}
	// Skip BND.ADDR + BND.PORT so the conn read offset is at the start of the
	// tunneled stream.
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 reply addr len: %w", err)
		}
		skip = int(lenBuf[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5 unknown atyp 0x%02x", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 reply addr/port: %w", err)
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5ReplyMsg(rep byte) string {
	switch rep {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown rep 0x%02x", rep)
	}
}

// PreConnect pre-warms n TLS connections to the given host.
func (t *Transport) PreConnect(ctx context.Context, host string, n int) error {
	if n <= 0 {
		n = 10
	}

	// Use the browser profile's User-Agent so the pre-warm HEAD doesn't show
	// up in logs/fingerprinters as a "Mozilla/5.0" mismatch against the
	// Chrome/Safari TLS handshake we just performed.
	ua := SafariIOS18UserAgent
	if t.browser == Chrome150 {
		ua = Chrome150UserAgent
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, "HEAD", host, nil)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Accept", "*/*")

			resp, err := t.RoundTrip(req)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			// Drain before closing so the HTTP/2 stream ends with END_STREAM.
			// Closing an unfinished body makes the transport emit RST_STREAM,
			// which Cloudflare and Akamai score as an abusive client — and a
			// pre-warm burst would fire n of them back to back, which is a
			// worse first impression than not pre-warming at all.
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}()
	}

	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("preconnect: %d/%d failed, first: %w", len(errs), n, errs[0])
	}
	return nil
}

// CloseIdleConnections closes all idle connections.
func (t *Transport) CloseIdleConnections() {
	t.h1Transport.CloseIdleConnections()
	if t.h2Transport != nil {
		t.h2Transport.CloseIdleConnections()
	}
}

// ActiveConnections returns the total number of TLS connections created.
func (t *Transport) ActiveConnections() int64 {
	return t.connCount.Load()
}

// setProxy configures the proxy function for all connections (HTTP/1.1 and HTTP/2).
func (t *Transport) setProxy(f func(*http.Request) (*url.URL, error)) {
	t.proxyMu.Lock()
	t.proxyFunc = f
	t.proxyRotator = nil
	t.proxyMu.Unlock()
}

// setProxyRotator binds a ProxyRotator to the transport. dialRaw will route
// through the rotator (with health tracking + per-dial fallback) instead of
// the simple proxyFunc path.
func (t *Transport) setProxyRotator(pr *ProxyRotator) {
	t.proxyMu.Lock()
	t.proxyRotator = pr
	t.proxyFunc = pr.ProxyFunc()
	t.proxyMu.Unlock()
}

// cachedNowNs is a coarse monotonic-ish unix-nano clock updated by a single
// goroutine every ~50ms. The DNS cache's TTL check reads this instead of
// calling time.Now().UnixNano() per request. time.Now() on Linux is vdso-fast
// (~20ns) but at 200k+ RPS the integral cost is real, and DNS TTL accuracy
// at 50ms granularity is more than enough (browser DNS TTLs are seconds-minutes).
var cachedNowNs atomic.Int64

func init() {
	cachedNowNs.Store(time.Now().UnixNano())
	go func() {
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			cachedNowNs.Store(time.Now().UnixNano())
		}
	}()
}

func runtimeNanoCached() int64 {
	return cachedNowNs.Load()
}

// dnsCache provides a lock-free DNS cache with round-robin IP selection.
// Uses sync.Map for the hot read path to eliminate RWMutex contention at high RPS.
type dnsCache struct {
	entries  sync.Map // map[string]*dnsCacheEntry
	ttl      time.Duration
	inflight sync.Map // dedup concurrent lookups for same host
	stopCh   chan struct{}
}

type dnsCacheEntry struct {
	ips         []string
	expiresAtNs int64 // unix nano, read atomically (immutable after store, no atomic needed for read)
	counter     atomic.Uint64
	ipsLen      uint64 // cached len(ips) so the hot path skips a slice header deref
}

// hasGlobalIPv6 reports whether this host has a routable global IPv6 address.
// Dialing UDP sends no packets; it only asks the kernel to select a source
// address, which fails when there is no global IPv6 route. Evaluated once.
var hasGlobalIPv6 = sync.OnceValue(func() bool {
	c, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return false
	}
	c.Close()
	return true
})

// selectAddressFamily narrows a mixed A/AAAA result down to one family.
//
// net.LookupHost returns both, and round-robining across the mixed list sent a
// share of every host's requests to an address family the machine may have no
// route for. On an IPv4-only host that surfaced as a fraction of requests
// failing with "network unreachable" for no visible reason. There is no Happy
// Eyeballs here, so the family has to be picked up front: IPv6 when this host
// can actually reach it, IPv4 otherwise, and whatever is left if the preferred
// family returned nothing.
func selectAddressFamily(ips []string) []string {
	var v4, v6 []string
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	if hasGlobalIPv6() && len(v6) > 0 {
		return v6
	}
	if len(v4) > 0 {
		return v4
	}
	return v6
}

func newDNSCache(ttl time.Duration) *dnsCache {
	// Guard against zero/negative TTLs — time.NewTicker(0) panics, and a
	// negative TTL would expire every lookup immediately. Either is almost
	// certainly a configuration mistake (e.g. WithDNSCacheTTL(0)), so fall
	// back to a sane default rather than crashing the process.
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	d := &dnsCache{
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}
	go d.cleanupLoop()
	return d
}

func (d *dnsCache) cleanupLoop() {
	ticker := time.NewTicker(d.ttl * 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			nowNs := time.Now().UnixNano()
			d.entries.Range(func(key, value interface{}) bool {
				entry := value.(*dnsCacheEntry)
				if nowNs > entry.expiresAtNs {
					d.entries.Delete(key)
				}
				return true
			})
		case <-d.stopCh:
			return
		}
	}
}

func (d *dnsCache) Close() {
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}
}

func (d *dnsCache) lookup(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}

	// Hot path: lock-free read from sync.Map. The cleanup goroutine deletes
	// expired entries every 2*ttl, so a stale read is bounded to that window —
	// acceptable in exchange for skipping time.Now() (a vdso syscall) on every
	// request. nanotime is cheaper than full wall-clock read.
	if val, ok := d.entries.Load(host); ok {
		entry := val.(*dnsCacheEntry)
		if runtimeNanoCached() <= entry.expiresAtNs {
			idx := entry.counter.Add(1) - 1
			return entry.ips[idx%entry.ipsLen], nil
		}
	}

	// Cold path: resolve with inflight dedup
	type resolveResult struct {
		ips []string
		err error
	}

	resultCh := make(chan resolveResult, 1)
	actual, loaded := d.inflight.LoadOrStore(host, resultCh)

	if loaded {
		ch := actual.(chan resolveResult)
		res := <-ch
		ch <- res
		if res.err != nil {
			return "", res.err
		}
		if val, ok := d.entries.Load(host); ok {
			entry := val.(*dnsCacheEntry)
			idx := entry.counter.Add(1) - 1
			return entry.ips[idx%entry.ipsLen], nil
		}
		return res.ips[0], nil
	}

	resolved, err := net.LookupHost(host)
	if err != nil {
		resultCh <- resolveResult{err: err}
		d.inflight.Delete(host)
		return "", err
	}
	ips := selectAddressFamily(resolved)
	if len(ips) == 0 {
		err := fmt.Errorf("no IPs found for %s", host)
		resultCh <- resolveResult{err: err}
		d.inflight.Delete(host)
		return "", err
	}

	newEntry := &dnsCacheEntry{
		ips:         ips,
		expiresAtNs: time.Now().Add(d.ttl).UnixNano(),
		ipsLen:      uint64(len(ips)),
	}

	d.entries.Store(host, newEntry)

	resultCh <- resolveResult{ips: ips}
	d.inflight.Delete(host)

	return ips[0], nil
}

func (d *dnsCache) Refresh(host string) {
	d.entries.Delete(host)
}
