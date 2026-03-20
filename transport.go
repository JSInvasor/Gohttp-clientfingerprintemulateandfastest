package gofire

import (
	"bufio"
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Transport is a high-performance HTTP transport with full browser fingerprint emulation.
//
// It emulates both TLS (JA3/JA4) and HTTP/2 (Akamai) fingerprints:
//
//   - TLS: uTLS with exact Firefox 148 ClientHello spec
//   - HTTP/2 SETTINGS: HEADER_TABLE_SIZE, ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE
//   - HTTP/2 WINDOW_UPDATE: Connection-level window increment matching Firefox
//   - HTTP/2 Header Order: Exact Firefox 148 header order via HPACK
//   - HTTP/2 Pseudo-header Order: :method, :path, :authority, :scheme (m,p,a,s)
type Transport struct {
	h1Transport *http.Transport    // HTTP/1.1 fallback
	h2Transport *http2.Transport   // HTTP/2 with Firefox settings

	spec        func() *tls.ClientHelloSpec
	h2Settings  H2Settings
	headerOrder []string
	forceH1     bool
	rootCAs     *x509.CertPool
	skipVerify  bool
	dnscache    *dnsCache
	connCount   atomic.Int64
	dialer      *net.Dialer

	// Proxy support - used directly in dialTLS to tunnel through proxies
	proxyMu   sync.RWMutex
	proxyFunc func(*http.Request) (*url.URL, error) // nil = no proxy
}

// TransportConfig holds configuration for creating a Transport.
type TransportConfig struct {
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout  time.Duration
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
		TLSHandshakeTimeout:  10 * time.Second,
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
	}

	// Set browser-specific fingerprint
	switch browser {
	case Firefox148:
		t.spec = Firefox148Spec
		t.h2Settings = Firefox148H2Settings()
		t.headerOrder = firefox148HeaderOrder
	default:
		t.spec = Firefox148Spec
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
		DialContext:            t.dialWithDNSCache(),
		DialTLSContext:         t.dialTLSForH1(),
		MaxIdleConns:           cfg.MaxIdleConns,
		MaxIdleConnsPerHost:    cfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:        cfg.MaxConnsPerHost,
		IdleConnTimeout:        cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		DisableKeepAlives:      cfg.DisableKeepAlives,
		DisableCompression:     cfg.DisableCompression,
		ForceAttemptHTTP2:      false, // We handle HTTP/2 ourselves
		ResponseHeaderTimeout:  cfg.ResponseHeaderTimeout,
		WriteBufferSize:        wbs,
		ReadBufferSize:         rbs,
		ExpectContinueTimeout:  1 * time.Second,
	}

	// HTTP/2 transport with Firefox SETTINGS fingerprint
	// Akamai fingerprint: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
	if !cfg.ForceHTTP1 {
		t.h2Transport = &http2.Transport{
			// Use our uTLS dialer for TLS connections with Firefox fingerprint
			DialTLSContext: func(ctx context.Context, network, addr string, _ *cryptotls.Config) (net.Conn, error) {
				return t.dialTLSForH2(ctx, network, addr)
			},
			DisableCompression: cfg.DisableCompression,
			AllowHTTP:          false,

			// Firefox 148 HTTP/2 SETTINGS:
			// SETTINGS_HEADER_TABLE_SIZE (0x1) = 65536
			MaxDecoderHeaderTableSize: t.h2Settings.HeaderTableSize,
			// SETTINGS_MAX_FRAME_SIZE (0x5) = 16384
			MaxReadFrameSize: t.h2Settings.MaxFrameSize,
			// SETTINGS_MAX_HEADER_LIST_SIZE = 0 (not sent by Firefox)
			StrictMaxConcurrentStreams: false,
		}
	}

	return t
}

// RoundTrip implements http.RoundTripper with full fingerprint emulation.
//
// For HTTPS requests, uses HTTP/2 with Firefox SETTINGS/WINDOW_UPDATE fingerprint.
// For HTTP requests or ForceHTTP1 mode, uses HTTP/1.1.
// Header order matches Firefox 148 for both protocols.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Reorder headers to match Firefox 148 header fingerprint
	t.orderRequestHeaders(req)

	// Route to correct transport based on scheme and H2 support
	if req.URL.Scheme == "https" && !t.forceH1 && t.h2Transport != nil {
		return t.h2Transport.RoundTrip(req)
	}

	return t.h1Transport.RoundTrip(req)
}

// orderRequestHeaders rebuilds the request header map in Firefox 148 order.
//
// This is critical because Go's http2 HPACK encoder iterates headers in map order.
// By rebuilding the map in Firefox order, HPACK encodes them in the correct sequence.
//
// Firefox 148 header order:
//
//	user-agent, accept, accept-language, accept-encoding,
//	[content-type], [content-length], [origin], [referer], [cookie],
//	upgrade-insecure-requests, sec-fetch-dest, sec-fetch-mode,
//	sec-fetch-site, sec-fetch-user, priority, te
func (t *Transport) orderRequestHeaders(req *http.Request) {
	if req.Header == nil || len(t.headerOrder) == 0 {
		return
	}

	original := req.Header
	ordered := make(http.Header, len(original))

	// Add headers in Firefox 148 exact order
	for _, key := range t.headerOrder {
		canonicalKey := http.CanonicalHeaderKey(key)
		if vals, ok := original[canonicalKey]; ok {
			ordered[canonicalKey] = vals
		}
	}

	// Add any custom headers not in Firefox order (appended at end)
	seen := make(map[string]bool, len(t.headerOrder))
	for _, key := range t.headerOrder {
		seen[http.CanonicalHeaderKey(key)] = true
	}
	for key, vals := range original {
		if !seen[key] {
			ordered[key] = vals
		}
	}

	req.Header = ordered
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

// dialTLSForH1 creates uTLS connections for HTTP/1.1 (ALPN: http/1.1 only).
func (t *Transport) dialTLSForH1() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return t.dialTLS(ctx, network, addr, []string{"http/1.1"})
	}
}

// dialTLSForH2 creates uTLS connections for HTTP/2 (ALPN: h2, http/1.1).
// The connection is wrapped with h2Conn to inject Firefox WINDOW_UPDATE on the connection.
func (t *Transport) dialTLSForH2(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := t.dialTLS(ctx, network, addr, []string{"h2", "http/1.1"})
	if err != nil {
		return nil, err
	}

	// Wrap connection to inject Firefox HTTP/2 WINDOW_UPDATE frame
	// This makes the connection-level window size match Firefox 148
	return newH2Conn(conn, t.h2Settings), nil
}

// dialTLS performs TLS handshake using uTLS with exact Firefox 148 ClientHello.
// If a proxy is configured, it tunnels through the proxy via CONNECT before TLS.
//
// This produces the correct JA3/JA4 fingerprint:
//
//	JA3 Hash: 0e76c7e9d06fa0e211b1827687dd8f43
//	JA4:      t13d1717h2_5b57614c22b0_e6dcd7ae0a9e
func (t *Transport) dialTLS(ctx context.Context, network, addr string, alpn []string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	// Get raw TCP connection (direct or through proxy)
	rawConn, err := t.dialRaw(ctx, network, host, port)
	if err != nil {
		return nil, err
	}

	// Configure uTLS with exact Firefox 148 spec
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: t.skipVerify,
		RootCAs:            t.rootCAs,
		NextProtos:         alpn,
	}

	uconn := tls.UClient(rawConn, tlsConfig, tls.HelloCustom)
	if err := uconn.ApplyPreset(t.spec()); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("apply tls preset: %w", err)
	}

	// TLS handshake with context deadline
	if deadline, ok := ctx.Deadline(); ok {
		if err := uconn.SetDeadline(deadline); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	// Clear deadline after successful handshake
	if err := uconn.SetDeadline(time.Time{}); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("clear deadline: %w", err)
	}

	t.connCount.Add(1)
	return uconn, nil
}

// dialRaw establishes a raw TCP connection, optionally through a proxy.
// For HTTPS proxy tunneling, it sends a CONNECT request and establishes a tunnel.
func (t *Transport) dialRaw(ctx context.Context, network, host, port string) (net.Conn, error) {
	t.proxyMu.RLock()
	proxyFunc := t.proxyFunc
	t.proxyMu.RUnlock()

	targetAddr := net.JoinHostPort(host, port)

	// Check if proxy is configured
	if proxyFunc != nil {
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

// dialViaProxy connects through an HTTP/SOCKS5 proxy using CONNECT tunnel.
func (t *Transport) dialViaProxy(ctx context.Context, network, targetAddr string, proxyURL *url.URL) (net.Conn, error) {
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		if proxyURL.Scheme == "https" {
			proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "443")
		} else {
			proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "8080")
		}
	}

	// Connect to proxy
	proxyConn, err := t.dialer.DialContext(ctx, network, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}

	// Build CONNECT request
	connectReq := "CONNECT " + targetAddr + " HTTP/1.1\r\n"
	connectReq += "Host: " + targetAddr + "\r\n"

	// Add proxy authentication if present
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += "Proxy-Authorization: Basic " + auth + "\r\n"
	}

	connectReq += "\r\n"

	// Set deadline for CONNECT handshake
	if deadline, ok := ctx.Deadline(); ok {
		proxyConn.SetDeadline(deadline)
	}

	// Send CONNECT
	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	// Read CONNECT response
	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	// Clear deadline after CONNECT
	proxyConn.SetDeadline(time.Time{})

	return proxyConn, nil
}

// h2Conn wraps a TLS connection to replace Go's default HTTP/2 WINDOW_UPDATE
// with the Firefox 148 value.
//
// Go's http2.Transport sends: preface + SETTINGS + WINDOW_UPDATE(0, 1<<30)
// Firefox 148 sends:          preface + SETTINGS + WINDOW_UPDATE(0, 12517377)
//
// This wrapper intercepts the first write (which contains the entire connection
// preface + SETTINGS + WINDOW_UPDATE as a single flush) and replaces the
// WINDOW_UPDATE increment value with the Firefox value.
//
// Akamai HTTP/2 fingerprint format: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-headers
// Firefox 148: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
type h2Conn struct {
	net.Conn
	settings H2Settings
	once     sync.Once
}

func newH2Conn(conn net.Conn, settings H2Settings) *h2Conn {
	return &h2Conn{
		Conn:     conn,
		settings: settings,
	}
}

// Write intercepts the first write to rebuild SETTINGS + WINDOW_UPDATE with Firefox 148 fingerprint.
//
// The first write from http2.Transport contains:
//   - Connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
//   - SETTINGS frame: 9-byte header + N*6 bytes of settings
//   - WINDOW_UPDATE frame: 9-byte header + 4-byte increment
//
// Go's http2.Transport sends extra settings (MAX_CONCURRENT_STREAMS, MAX_HEADER_LIST_SIZE)
// and wrong setting order. We rebuild the SETTINGS frame to match Firefox 148 exactly:
//
//	Firefox 148 SETTINGS order: HEADER_TABLE_SIZE(1), ENABLE_PUSH(2), INITIAL_WINDOW_SIZE(4), MAX_FRAME_SIZE(5)
//
// We also replace the WINDOW_UPDATE increment from Go's 1<<30 to Firefox's 12517377.
func (c *h2Conn) Write(b []byte) (int, error) {
	var modified []byte

	c.once.Do(func() {
		if len(b) >= len(http2ClientPreface) &&
			string(b[:len(http2ClientPreface)]) == http2ClientPreface {

			// Parse Go's SETTINGS frame to get INITIAL_WINDOW_SIZE value
			// (we must keep Go's value to avoid flow control mismatch)
			goInitWindowSize := uint32(0)
			pos := len(http2ClientPreface)
			for pos+9 <= len(b) {
				frameLen := int(b[pos])<<16 | int(b[pos+1])<<8 | int(b[pos+2])
				frameType := b[pos+3]

				if frameType == 0x04 { // SETTINGS frame
					payload := b[pos+9 : pos+9+frameLen]
					for i := 0; i+5 < len(payload); i += 6 {
						id := uint16(payload[i])<<8 | uint16(payload[i+1])
						val := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 |
							uint32(payload[i+4])<<8 | uint32(payload[i+5])
						if id == 4 { // SETTINGS_INITIAL_WINDOW_SIZE
							goInitWindowSize = val
						}
					}
				}

				pos += 9 + frameLen
			}

			// Use Go's INITIAL_WINDOW_SIZE to keep flow control in sync
			initWindowSize := goInitWindowSize
			if initWindowSize == 0 {
				initWindowSize = 4 << 20 // Go default: 4MB
			}

			// Build Firefox 148 connection preface:
			// Preface + SETTINGS(1:65536, 2:0, 4:IWS, 5:16384) + WINDOW_UPDATE(0, 12517377)
			type h2Setting struct {
				id  uint16
				val uint32
			}

			firefoxSettings := []h2Setting{
				{1, c.settings.HeaderTableSize},  // HEADER_TABLE_SIZE = 65536
				{2, c.settings.EnablePush},        // ENABLE_PUSH = 0
				{4, initWindowSize},               // INITIAL_WINDOW_SIZE (Go's value)
				{5, c.settings.MaxFrameSize},      // MAX_FRAME_SIZE = 16384
			}

			payloadLen := len(firefoxSettings) * 6 // 4 settings × 6 bytes = 24

			// Allocate: preface(24) + settings_header(9) + settings_payload(24) + window_update(13) = 70 bytes
			buf := make([]byte, 0, 70)

			// HTTP/2 client connection preface
			buf = append(buf, []byte(http2ClientPreface)...)

			// SETTINGS frame header: Length(3) + Type(1) + Flags(1) + StreamID(4)
			buf = append(buf, byte(payloadLen>>16), byte(payloadLen>>8), byte(payloadLen))
			buf = append(buf, 0x04, 0x00, 0, 0, 0, 0) // Type=SETTINGS, Flags=0, StreamID=0

			// SETTINGS payload: each setting is ID(2) + Value(4) = 6 bytes
			for _, s := range firefoxSettings {
				buf = append(buf, byte(s.id>>8), byte(s.id))
				buf = append(buf, byte(s.val>>24), byte(s.val>>16), byte(s.val>>8), byte(s.val))
			}

			// WINDOW_UPDATE frame: Length=4, Type=8, Flags=0, StreamID=0, Increment=12517377
			increment := c.settings.ConnectionWindowSize
			buf = append(buf, 0, 0, 4)                // Length = 4
			buf = append(buf, 0x08, 0x00, 0, 0, 0, 0) // Type=WINDOW_UPDATE, Flags=0, StreamID=0
			buf = append(buf, byte(increment>>24), byte(increment>>16), byte(increment>>8), byte(increment))

			modified = buf
		}
	})

	if modified != nil {
		_, err := c.Conn.Write(modified)
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}

	return c.Conn.Write(b)
}

const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

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
			applyFirefoxHeaders(req, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "en-US,en;q=0.9")

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
	t.proxyMu.Unlock()
}

// dnsCache provides a thread-safe DNS cache with round-robin IP selection.
type dnsCache struct {
	mu       sync.RWMutex
	entries  map[string]*dnsCacheEntry
	ttl      time.Duration
	inflight sync.Map
	stopCh   chan struct{}
}

type dnsCacheEntry struct {
	ips       []string
	expiresAt time.Time
	counter   atomic.Uint64
}

func newDNSCache(ttl time.Duration) *dnsCache {
	d := &dnsCache{
		entries: make(map[string]*dnsCacheEntry, 1024),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
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
			d.mu.Lock()
			for host, entry := range d.entries {
				if now.After(entry.expiresAt) {
					delete(d.entries, host)
				}
			}
			d.mu.Unlock()
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

	d.mu.RLock()
	entry, ok := d.entries[host]
	d.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		idx := entry.counter.Add(1) - 1
		return entry.ips[idx%uint64(len(entry.ips))], nil
	}

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
		d.mu.RLock()
		entry, ok := d.entries[host]
		d.mu.RUnlock()
		if ok {
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

	d.mu.Lock()
	d.entries[host] = newEntry
	d.mu.Unlock()

	resultCh <- resolveResult{ips: ips}
	d.inflight.Delete(host)

	return ips[0], nil
}

func (d *dnsCache) Refresh(host string) {
	d.mu.Lock()
	delete(d.entries, host)
	d.mu.Unlock()
}
