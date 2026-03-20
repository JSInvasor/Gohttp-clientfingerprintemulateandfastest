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
	"golang.org/x/net/http2"
)

// Transport is a high-performance HTTP transport with Firefox 148 TLS fingerprinting.
// It wraps http.Transport with uTLS for TLS fingerprint emulation.
type Transport struct {
	inner     *http.Transport
	h2Inner   *http2.Transport
	spec      func() *tls.ClientHelloSpec
	proxyURL  string
	forceH1   bool
	rootCAs   *x509.CertPool
	dnscache  *dnsCache
	connCount atomic.Int64

	mu       sync.RWMutex
	h2Conns  map[string]*http2.ClientConn
	tlsConns map[string][]*tls.UConn
}

// TransportConfig holds configuration for creating a Transport.
type TransportConfig struct {
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
	IdleConnTimeout     time.Duration
	TLSHandshakeTimeout time.Duration
	DisableKeepAlives   bool
	DisableCompression  bool
	ForceHTTP1          bool
	ProxyURL            string
	RootCAs             *x509.CertPool
	DNSCacheTTL         time.Duration
	DialTimeout         time.Duration
	ResponseHeaderTimeout time.Duration
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
		DNSCacheTTL:           5 * time.Minute,
		DialTimeout:           10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

// newTransport creates a new Transport with the given configuration.
func newTransport(cfg TransportConfig) *Transport {
	t := &Transport{
		spec:     Firefox148Spec,
		proxyURL: cfg.ProxyURL,
		forceH1:  cfg.ForceHTTP1,
		rootCAs:  cfg.RootCAs,
		dnscache: newDNSCache(cfg.DNSCacheTTL),
		h2Conns:  make(map[string]*http2.ClientConn),
		tlsConns: make(map[string][]*tls.UConn),
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

	t.inner = &http.Transport{
		DialContext:           t.dialWithDNSCache(dialer),
		DialTLSContext:        t.dialTLS(dialer),
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:  cfg.TLSHandshakeTimeout,
		DisableKeepAlives:     cfg.DisableKeepAlives,
		DisableCompression:    cfg.DisableCompression,
		ForceAttemptHTTP2:     !cfg.ForceHTTP1,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		WriteBufferSize:       64 * 1024,
		ReadBufferSize:        64 * 1024,
	}

	return t
}

// dialWithDNSCache returns a DialContext function that uses DNS caching.
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

// dialTLS creates a TLS connection using uTLS with Firefox 148 fingerprint.
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

		// Configure TLS
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: false,
			RootCAs:            t.rootCAs,
			NextProtos:         []string{"h2", "http/1.1"},
		}

		if t.forceH1 {
			tlsConfig.NextProtos = []string{"http/1.1"}
		}

		// Create uTLS connection with Firefox 148 spec
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

// dnsCache provides a simple thread-safe DNS cache.
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
	ttl     time.Duration
}

type dnsCacheEntry struct {
	ip        string
	expiresAt time.Time
}

func newDNSCache(ttl time.Duration) *dnsCache {
	return &dnsCache{
		entries: make(map[string]dnsCacheEntry, 1024),
		ttl:     ttl,
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
		return entry.ip, nil
	}

	// Resolve
	ips, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs found for %s", host)
	}

	ip := ips[0]

	d.mu.Lock()
	d.entries[host] = dnsCacheEntry{
		ip:        ip,
		expiresAt: time.Now().Add(d.ttl),
	}
	d.mu.Unlock()

	return ip, nil
}

