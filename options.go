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
	browser         BrowserProfile
	followRedirects bool
	maxRedirects    int
	timeout         time.Duration
	acceptLanguage  string
	accept          string
}

func defaultClientConfig() clientConfig {
	return clientConfig{
		transport:       defaultTransportConfig(),
		browser:         Firefox148,
		followRedirects: true,
		maxRedirects:    10,
		timeout:         30 * time.Second,
		acceptLanguage:  "en-US,en;q=0.9",
		accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
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

// WithAcceptLanguage sets the Accept-Language header. Default: "en-US,en;q=0.9".
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

// WithEnableCompression enables response decompression (disabled by default for speed).
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
