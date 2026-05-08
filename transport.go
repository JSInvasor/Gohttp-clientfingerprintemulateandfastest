package gofire

import (
	"context"
	cryptorand "crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

// Transport is a high-performance HTTP transport with full browser fingerprint emulation.
//
// It emulates both TLS (JA3/JA4) and HTTP/2 (Akamai) fingerprints using a custom
// TLS 1.3 implementation (internal/ctls) - no uTLS dependency:
//
//   - TLS: custom Firefox 148 ClientHello built at the byte level
//   - HTTP/2 SETTINGS: HEADER_TABLE_SIZE, ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE
//   - HTTP/2 WINDOW_UPDATE: Connection-level window increment matching Firefox
//   - HTTP/2 Header Order: Exact Firefox 148 header order via HPACK
//   - HTTP/2 Pseudo-header Order: :method, :path, :authority, :scheme (m,p,a,s)
type Transport struct {
	h1Transport *http.Transport  // HTTP/1.1 fallback
	h2Transport *http2.Transport // HTTP/2 with browser settings

	h2Settings  H2Settings
	headerOrder []string
	forceH1     bool
	rootCAs     *x509.CertPool
	skipVerify  bool
	browser     BrowserProfile
	dnscache    *dnsCache
	connCount   atomic.Int64
	dialer      *net.Dialer

	// Proxy support - used directly in dialTLS to tunnel through proxies
	proxyMu       sync.RWMutex
	proxyFunc     func(*http.Request) (*url.URL, error) // nil = no proxy
	proxyRotator  *ProxyRotator                         // nil unless SetProxyRotator was used
}

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

	// Set browser-specific fingerprint
	switch browser {
	case Chrome147:
		t.h2Settings = Chrome146H2Settings()
		t.headerOrder = chrome146HeaderOrder
	case SafariIOS18:
		t.h2Settings = SafariIOS18H2Settings()
		t.headerOrder = safariIOS18HeaderOrder
	default:
		t.h2Settings = Firefox148H2Settings()
		t.headerOrder = firefox148HeaderOrder
	}

	t.dialer = &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = setSocketOpts(fd)
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

	// HTTP/2 transport with browser-specific fingerprint
	if !cfg.ForceHTTP1 {
		// Get browser-specific H2 profile
		var h2p H2Profile
		switch browser {
		case Chrome147:
			h2p = Chrome146H2Profile()
		case SafariIOS18:
			h2p = SafariIOS18H2Profile()
		default:
			h2p = Firefox148H2Profile()
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
			ReadIdleTimeout:           15 * time.Second,
			PingTimeout:               5 * time.Second,
			WriteByteTimeout:          30 * time.Second,
			// Cycle the H2 conn after ~8000 streams. Real browsers don't push
			// 100k+ streams over a single connection; a long monotonic
			// stream-ID sequence is a passive fingerprint signal.
			MaxStreamsPerConn: 8000,
		}
	}

	return t
}

// RoundTrip implements http.RoundTripper with full fingerprint emulation.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" && !t.forceH1 && t.h2Transport != nil {
		return t.h2Transport.RoundTrip(req)
	}
	return t.h1Transport.RoundTrip(req)
}

// dialWithDNSCache returns a DialContext function with DNS caching and round-robin.
func (t *Transport) dialWithDNSCache() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return t.dialer.DialContext(ctx, network, addr)
		}

		ip, err := t.dnscache.lookup(host)
		if err != nil {
			return t.dialer.DialContext(ctx, network, addr)
		}

		return t.dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
}

// dialTLSForH1 creates ctls connections for HTTP/1.1 (ALPN: http/1.1 only).
func (t *Transport) dialTLSForH1() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return t.dialTLS(ctx, network, addr, []string{"http/1.1"})
	}
}

// dialTLSForH2 creates ctls connections for HTTP/2 (ALPN: h2, http/1.1).
func (t *Transport) dialTLSForH2(ctx context.Context, network, addr string) (net.Conn, error) {
	return t.dialTLS(ctx, network, addr, []string{"h2", "http/1.1"})
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

	// Map browser profile to ctls browser type once, outside the loop.
	browserType := ctls.BrowserFirefox148
	switch t.browser {
	case Chrome147:
		browserType = ctls.BrowserChrome146
	case SafariIOS18:
		browserType = ctls.BrowserSafariIOS18
	}

	const maxAttempts = 2
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Jittered backoff: ~50-150ms, ~150-400ms.
			minMs := 50 * attempt
			maxMs := 50 + 100*attempt
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

		tlsConn, err := ctls.WrapConn(ctx, rawConn, host, alpn, t.skipVerify, t.rootCAs, browserType)
		if err != nil {
			rawConn.Close()
			lastErr = fmt.Errorf("tls handshake: %w", err)
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

// secureRandIntn returns a uniform random int in [0, n) using crypto/rand.
// Used for handshake retry jitter; not on the hot path.
func secureRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var b [4]byte
	_, _ = cryptorand.Read(b[:])
	v := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if v < 0 {
		v = -v
	}
	return v % n
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
		const proxyDialAttempts = 2
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
		if lastErr != nil {
			return nil, lastErr
		}
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
			// Set minimal headers for pre-warm; actual browser headers are set by the Client layer.
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Header.Set("Accept", "*/*")

			resp, err := t.RoundTrip(req)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
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

// dnsCache provides a lock-free DNS cache with round-robin IP selection.
// Uses sync.Map for the hot read path to eliminate RWMutex contention at high RPS.
type dnsCache struct {
	entries  sync.Map // map[string]*dnsCacheEntry
	ttl      time.Duration
	inflight sync.Map // dedup concurrent lookups for same host
	stopCh   chan struct{}
}

type dnsCacheEntry struct {
	ips       []string
	expiresAt time.Time
	counter   atomic.Uint64
}

func newDNSCache(ttl time.Duration) *dnsCache {
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
			now := time.Now()
			d.entries.Range(func(key, value interface{}) bool {
				entry := value.(*dnsCacheEntry)
				if now.After(entry.expiresAt) {
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

	// Hot path: lock-free read from sync.Map
	if val, ok := d.entries.Load(host); ok {
		entry := val.(*dnsCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			idx := entry.counter.Add(1) - 1
			return entry.ips[idx%uint64(len(entry.ips))], nil
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
			return entry.ips[idx%uint64(len(entry.ips))], nil
		}
		return res.ips[0], nil
	}

	ips, err := net.LookupHost(host)
	if err != nil {
		resultCh <- resolveResult{err: err}
		d.inflight.Delete(host)
		return "", err
	}
	if len(ips) == 0 {
		err := fmt.Errorf("no IPs found for %s", host)
		resultCh <- resolveResult{err: err}
		d.inflight.Delete(host)
		return "", err
	}

	newEntry := &dnsCacheEntry{
		ips:       ips,
		expiresAt: time.Now().Add(d.ttl),
	}

	d.entries.Store(host, newEntry)

	resultCh <- resolveResult{ips: ips}
	d.inflight.Delete(host)

	return ips[0], nil
}

func (d *dnsCache) Refresh(host string) {
	d.entries.Delete(host)
}
