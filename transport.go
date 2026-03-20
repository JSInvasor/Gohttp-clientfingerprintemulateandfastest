package gofire

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tls "github.com/refraction-networking/utls"
)

// Transport is a high-performance HTTP transport with browser TLS fingerprinting.
type Transport struct {
	inner *http.Transport

	spec       func() *tls.ClientHelloSpec
	h2Settings H2Settings
	proxyURL   string
	forceH1    bool
	rootCAs    *x509.CertPool
	skipVerify bool
	dnscache   *dnsCache
	connCount  atomic.Int64
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
		MaxConnsPerHost:       0, // unlimited
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    true, // avoid CPU overhead for max RPS
		ForceHTTP1:            false,
		InsecureSkipVerify:    false,
		DNSCacheTTL:           5 * time.Minute,
		DialTimeout:           10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		WriteBufferSize:       64 * 1024,
		ReadBufferSize:        64 * 1024,
	}
}

// newTransport creates a new Transport with the given configuration.
func newTransport(cfg TransportConfig, browser BrowserProfile) *Transport {
	t := &Transport{
		proxyURL:   cfg.ProxyURL,
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
	default:
		t.spec = Firefox148Spec
		t.h2Settings = Firefox148H2Settings()
	}

	dialer := &net.Dialer{
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

	t.inner = &http.Transport{
		DialContext:            t.dialWithDNSCache(dialer),
		DialTLSContext:         t.dialTLS(dialer),
		MaxIdleConns:           cfg.MaxIdleConns,
		MaxIdleConnsPerHost:    cfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:        cfg.MaxConnsPerHost,
		IdleConnTimeout:        cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		DisableKeepAlives:      cfg.DisableKeepAlives,
		DisableCompression:     cfg.DisableCompression,
		ForceAttemptHTTP2:      !cfg.ForceHTTP1,
		ResponseHeaderTimeout:  cfg.ResponseHeaderTimeout,
		WriteBufferSize:        wbs,
		ReadBufferSize:         rbs,
		ExpectContinueTimeout:  1 * time.Second,
	}

	return t
}

// dialWithDNSCache returns a DialContext function that uses DNS caching
// with round-robin IP selection for load distribution.
func (t *Transport) dialWithDNSCache(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return dialer.DialContext(ctx, network, addr)
		}

		ip, err := t.dnscache.lookup(host)
		if err != nil {
			return dialer.DialContext(ctx, network, addr)
		}

		return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
}

// dialTLS creates a TLS connection using uTLS with browser fingerprint.
func (t *Transport) dialTLS(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		// Resolve DNS with cache
		ip, err := t.dnscache.lookup(host)
		if err != nil {
			ip = host
		}

		dialAddr := addr
		if ip != host {
			dialAddr = net.JoinHostPort(ip, port)
		}

		// Dial TCP
		rawConn, err := dialer.DialContext(ctx, network, dialAddr)
		if err != nil {
			return nil, fmt.Errorf("dial tcp: %w", err)
		}

		// Configure uTLS
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: t.skipVerify,
			RootCAs:            t.rootCAs,
			NextProtos:         []string{"h2", "http/1.1"},
		}

		if t.forceH1 {
			tlsConfig.NextProtos = []string{"http/1.1"}
		}

		// Create uTLS connection with browser spec
		uconn := tls.UClient(rawConn, tlsConfig, tls.HelloCustom)
		if err := uconn.ApplyPreset(t.spec()); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("apply tls preset: %w", err)
		}

		// Handshake with context timeout
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

		// Clear deadline after handshake
		if err := uconn.SetDeadline(time.Time{}); err != nil {
			uconn.Close()
			return nil, fmt.Errorf("clear deadline: %w", err)
		}

		t.connCount.Add(1)
		return uconn, nil
	}
}

// PreConnect pre-warms n TLS connections to the given host.
// This eliminates TLS handshake latency from the first n requests.
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
			// Make a HEAD request to establish the connection
			req, err := http.NewRequestWithContext(ctx, "HEAD", host, nil)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			applyFirefoxHeaders(req, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "en-US,en;q=0.9")
			resp, err := t.inner.RoundTrip(req)
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
		return fmt.Errorf("preconnect: %d/%d connections failed, first error: %w", len(errs), n, errs[0])
	}
	return nil
}

// RoundTrip executes a single HTTP transaction.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.inner.RoundTrip(req)
}

// CloseIdleConnections closes idle connections.
func (t *Transport) CloseIdleConnections() {
	t.inner.CloseIdleConnections()
}

// ActiveConnections returns the total number of TLS connections created.
func (t *Transport) ActiveConnections() int64 {
	return t.connCount.Load()
}

// dnsCache provides a thread-safe DNS cache with round-robin IP selection.
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsCacheEntry
	ttl     time.Duration
	inflight sync.Map // singleflight per host to prevent thundering herd
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

	// Background cleanup of expired entries to prevent memory leaks
	go d.cleanupLoop()

	return d
}

// cleanupLoop periodically removes expired DNS cache entries.
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

// Close stops the background cleanup goroutine.
func (d *dnsCache) Close() {
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}
}

func (d *dnsCache) lookup(host string) (string, error) {
	// Check if it's already an IP
	if net.ParseIP(host) != nil {
		return host, nil
	}

	d.mu.RLock()
	entry, ok := d.entries[host]
	d.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		// Round-robin IP selection
		idx := entry.counter.Add(1) - 1
		return entry.ips[idx%uint64(len(entry.ips))], nil
	}

	// Singleflight: only one goroutine resolves per host at a time
	type resolveResult struct {
		ips []string
		err error
	}

	resultCh := make(chan resolveResult, 1)
	actual, loaded := d.inflight.LoadOrStore(host, resultCh)

	if loaded {
		// Another goroutine is already resolving; wait for its result
		ch := actual.(chan resolveResult)
		res := <-ch
		ch <- res // put it back for other waiters
		if res.err != nil {
			return "", res.err
		}
		// Use fresh entry from cache (set by the resolving goroutine)
		d.mu.RLock()
		entry, ok := d.entries[host]
		d.mu.RUnlock()
		if ok {
			idx := entry.counter.Add(1) - 1
			return entry.ips[idx%uint64(len(entry.ips))], nil
		}
		return res.ips[0], nil
	}

	// We are the resolving goroutine
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

// Refresh forces a DNS re-lookup for the given host.
func (d *dnsCache) Refresh(host string) {
	d.mu.Lock()
	delete(d.entries, host)
	d.mu.Unlock()
}
