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
	h2Transport *http2.Transport // HTTP/2 with Firefox settings

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
	}

	// Set browser-specific fingerprint
	switch browser {
	case Firefox148:
		t.h2Settings = Firefox148H2Settings()
		t.headerOrder = firefox148HeaderOrder
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

	// HTTP/2 transport with FULL Firefox 148 fingerprint
	// Akamai fingerprint: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
	if !cfg.ForceHTTP1 {
		t.h2Transport = &http2.Transport{
			// Use our custom ctls dialer for TLS connections with Firefox fingerprint
			DialTLSContext: func(ctx context.Context, network, addr string, _ *cryptotls.Config) (net.Conn, error) {
				return t.dialTLSForH2(ctx, network, addr)
			},
			DisableCompression: cfg.DisableCompression,
			AllowHTTP:          false,

			// These affect Go's internal tracking (must match SETTINGS we send)
			MaxDecoderHeaderTableSize: t.h2Settings.HeaderTableSize, // 65536
			MaxReadFrameSize:          t.h2Settings.MaxFrameSize,    // 16384

			// Custom SETTINGS frame: exact Firefox 148 order and values
			Settings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: t.h2Settings.HeaderTableSize},    // 1:65536
				{ID: http2.SettingEnablePush, Val: t.h2Settings.EnablePush},               // 2:0
				{ID: http2.SettingInitialWindowSize, Val: t.h2Settings.InitialWindowSize}, // 4:131072
				{ID: http2.SettingMaxFrameSize, Val: t.h2Settings.MaxFrameSize},           // 5:16384
			},

			// Connection-level WINDOW_UPDATE: Firefox 148 sends 12517377
			ConnectionFlow: t.h2Settings.ConnectionWindowSize,

			// Pseudo-header order: Firefox sends :method, :path, :authority, :scheme (m,p,a,s)
			PseudoHeaderOrder: Firefox148PseudoHeaderOrder(),

			// Header order: exact Firefox 148 HPACK encoding order
			HeaderOrder: t.headerOrder,

			// HEADERS frame PRIORITY: Firefox 148 sends Priority flag (0x20)
			// with weight=42, depends_on=0, exclusive=false
			HeaderPriority: http2.PriorityParam{
				Weight: Firefox148PriorityWeight(), // 42
			},

			// Allow new connections when per-connection stream limit is hit.
			// With StrictMaxConcurrentStreams=false, the transport creates new TCP
			// connections instead of blocking when all connections are at max streams.
			// This is critical for high RPS: if server allows 100 streams/conn,
			// 2048 concurrent requests use ~21 connections with proper multiplexing.
			StrictMaxConcurrentStreams: false,

			// Keep-alive via PING frames.
			// ReadIdleTimeout triggers a PING when no frames are received for this duration.
			// This detects dead connections killed by NAT/proxy/load balancers silently,
			// preventing requests from being sent to zombie connections.
			ReadIdleTimeout: 15 * time.Second,

			// PingTimeout closes the connection if PING response is not received in time.
			PingTimeout: 5 * time.Second,

			// WriteByteTimeout closes connections stuck on write (network issue).
			WriteByteTimeout: 30 * time.Second,
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

// dialTLS performs TLS handshake using our custom ctls package with exact Firefox 148 ClientHello.
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

	// Perform custom TLS 1.3 handshake with Firefox 148 fingerprint
	tlsConn, err := ctls.WrapConn(ctx, rawConn, host, alpn, t.skipVerify, t.rootCAs)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	t.connCount.Add(1)
	return tlsConn, nil
}

// dialRaw establishes a raw TCP connection, optionally through a proxy.
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
			applyFirefoxHeaders(req, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "en-US,en;q=0.5")

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
