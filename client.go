// Package gofire provides a high-performance HTTP client with Firefox 148
// TLS fingerprint emulation. It is designed for maximum throughput (200-300k+ RPS)
// with accurate browser fingerprinting to bypass TLS/JA3 detection.
//
// Key features:
//   - Firefox 148 TLS fingerprint (JA3/JA4) via uTLS
//   - Firefox 148 HTTP/2 fingerprint (SETTINGS, WINDOW_UPDATE)
//   - Firefox-accurate header ordering
//   - DNS caching for reduced latency
//   - Aggressive connection pooling (10k+ idle connections)
//   - Zero-allocation hot paths via sync.Pool
//   - Automatic gzip/br/deflate decompression
//   - TCP socket tuning (TCP_NODELAY, TCP_QUICKACK on Linux)
package gofire

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
)

// Client is a high-performance HTTP client with Firefox 148 fingerprint emulation.
type Client struct {
	httpClient *http.Client
	transport  *Transport
	config     clientConfig
	jar        http.CookieJar

	reqPool sync.Pool
}

// NewClient creates a new Client with the given options.
// Default configuration is optimized for maximum RPS.
func NewClient(opts ...Option) (*Client, error) {
	cfg := defaultClientConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	transport := newTransport(cfg.transport)

	// Configure proxy if set
	if cfg.transport.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.transport.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.inner.Proxy = http.ProxyURL(proxyURL)
	}

	jar, _ := cookiejar.New(nil)

	c := &Client{
		transport: transport,
		config:    cfg,
		jar:       jar,
	}

	c.reqPool = sync.Pool{
		New: func() interface{} {
			return &http.Request{
				Header: make(http.Header, 12),
			}
		},
	}

	redirectPolicy := func(req *http.Request, via []*http.Request) error {
		if !cfg.followRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= cfg.maxRedirects {
			return fmt.Errorf("stopped after %d redirects", cfg.maxRedirects)
		}
		// Copy Firefox headers to redirect request
		applyFirefoxHeaders(req, cfg.accept, cfg.acceptLanguage)
		return nil
	}

	c.httpClient = &http.Client{
		Transport:     transport,
		Timeout:       cfg.timeout,
		Jar:           jar,
		CheckRedirect: redirectPolicy,
	}

	return c, nil
}

// Get performs an HTTP GET request.
func (c *Client) Get(rawURL string) (*Response, error) {
	return c.Do("GET", rawURL, nil, nil)
}

// GetWithContext performs an HTTP GET request with context.
func (c *Client) GetWithContext(ctx context.Context, rawURL string) (*Response, error) {
	return c.DoWithContext(ctx, "GET", rawURL, nil, nil)
}

// Post performs an HTTP POST request.
func (c *Client) Post(rawURL string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do("POST", rawURL, body, headers)
}

// PostJSON performs an HTTP POST request with JSON content type.
func (c *Client) PostJSON(rawURL string, body []byte) (*Response, error) {
	return c.Do("POST", rawURL, body, map[string]string{
		"Content-Type": "application/json",
	})
}

// Put performs an HTTP PUT request.
func (c *Client) Put(rawURL string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do("PUT", rawURL, body, headers)
}

// Delete performs an HTTP DELETE request.
func (c *Client) Delete(rawURL string) (*Response, error) {
	return c.Do("DELETE", rawURL, nil, nil)
}

// Head performs an HTTP HEAD request.
func (c *Client) Head(rawURL string) (*Response, error) {
	return c.Do("HEAD", rawURL, nil, nil)
}

// Do performs an HTTP request with the given method, URL, body, and headers.
func (c *Client) Do(method, rawURL string, body []byte, headers map[string]string) (*Response, error) {
	return c.DoWithContext(context.Background(), method, rawURL, body, headers)
}

// DoWithContext performs an HTTP request with context.
func (c *Client) DoWithContext(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Apply Firefox default headers
	applyFirefoxHeaders(req, c.config.accept, c.config.acceptLanguage)

	// Apply custom headers (override defaults)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return &Response{Response: resp}, nil
}

// DoHTTPRequest executes a standard *http.Request with fingerprint headers applied.
func (c *Client) DoHTTPRequest(req *http.Request) (*Response, error) {
	applyFirefoxHeaders(req, c.config.accept, c.config.acceptLanguage)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return &Response{Response: resp}, nil
}

// Close releases all resources held by the client.
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
}

// ClearCookies removes all cookies from the client's cookie jar.
func (c *Client) ClearCookies() {
	jar, _ := cookiejar.New(nil)
	c.jar = jar
	c.httpClient.Jar = jar
}

// SetCookies sets cookies for the given URL.
func (c *Client) SetCookies(rawURL string, cookies []*http.Cookie) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	c.jar.SetCookies(u, cookies)
	return nil
}

// GetCookies returns cookies for the given URL.
func (c *Client) GetCookies(rawURL string) ([]*http.Cookie, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	return c.jar.Cookies(u), nil
}

// ActiveConnections returns the number of TLS connections created.
func (c *Client) ActiveConnections() int64 {
	return c.transport.ActiveConnections()
}

// GetHTTPClient returns the underlying http.Client for advanced usage.
func (c *Client) GetHTTPClient() *http.Client {
	return c.httpClient
}

// Flood sends n concurrent requests to the given URL and returns all responses.
// This is optimized for maximum throughput with worker pool pattern.
func (c *Client) Flood(ctx context.Context, method, rawURL string, n, concurrency int) ([]*Response, []error) {
	if concurrency <= 0 {
		concurrency = 100
	}
	if concurrency > n {
		concurrency = n
	}

	responses := make([]*Response, n)
	errors := make([]error, n)

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				errors[idx] = ctx.Err()
				return
			default:
			}

			resp, err := c.DoWithContext(ctx, method, rawURL, nil, nil)
			responses[idx] = resp
			errors[idx] = err
		}(i)
	}

	wg.Wait()
	return responses, errors
}

// BuildRequest creates an http.Request builder for more complex requests.
func (c *Client) BuildRequest() *RequestBuilder {
	return &RequestBuilder{
		client:  c,
		headers: make(map[string]string),
	}
}

// RequestBuilder provides a fluent API for building complex HTTP requests.
type RequestBuilder struct {
	client  *Client
	method  string
	url     string
	body    []byte
	headers map[string]string
	ctx     context.Context
}

func (rb *RequestBuilder) Method(method string) *RequestBuilder {
	rb.method = strings.ToUpper(method)
	return rb
}

func (rb *RequestBuilder) URL(url string) *RequestBuilder {
	rb.url = url
	return rb
}

func (rb *RequestBuilder) Body(body []byte) *RequestBuilder {
	rb.body = body
	return rb
}

func (rb *RequestBuilder) Header(key, value string) *RequestBuilder {
	rb.headers[key] = value
	return rb
}

func (rb *RequestBuilder) Context(ctx context.Context) *RequestBuilder {
	rb.ctx = ctx
	return rb
}

func (rb *RequestBuilder) Send() (*Response, error) {
	if rb.method == "" {
		rb.method = "GET"
	}
	if rb.ctx == nil {
		rb.ctx = context.Background()
	}
	return rb.client.DoWithContext(rb.ctx, rb.method, rb.url, rb.body, rb.headers)
}
