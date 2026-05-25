// Package gofire provides a high-performance HTTP client with Firefox 148
// TLS fingerprint emulation. Designed for 200-300k+ RPS with full
// JA3/JA4 + HTTP/2 + header fingerprint bypass.
//
// Usage:
//
//	client, _ := gofire.Emulate(gofire.Firefox148)
//	resp, _ := client.Get("https://example.com")
//	text, _ := resp.Text()
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
	"time"
)

// Client is a high-performance HTTP client with browser fingerprint emulation.
type Client struct {
	httpClient *http.Client
	transport  *Transport
	config     clientConfig
	jar        http.CookieJar
}

// NewClient creates a new Client with the given options.
// For the simplest usage, prefer Emulate() instead.
func NewClient(opts ...Option) (*Client, error) {
	cfg := defaultClientConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	transport := newTransport(cfg.transport, cfg.browser)

	// Configure proxy if set
	if cfg.transport.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.transport.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.setProxy(http.ProxyURL(proxyURL))
	}

	jar, _ := cookiejar.New(nil)

	c := &Client{
		transport: transport,
		config:    cfg,
		jar:       jar,
	}

	redirectPolicy := func(req *http.Request, via []*http.Request) error {
		if !cfg.followRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= cfg.maxRedirects {
			return fmt.Errorf("stopped after %d redirects", cfg.maxRedirects)
		}
		// Sec-Fetch-Site has to be recomputed for the new URL+Referer pair;
		// otherwise the stale value from the previous hop leaks through and
		// no longer matches the actual origin transition.
		req.Header.Del("Sec-Fetch-Site")
		applyBrowserHeaders(req, cfg.browser, cfg.accept, cfg.acceptLanguage)
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

// Patch performs an HTTP PATCH request.
func (c *Client) Patch(rawURL string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do("PATCH", rawURL, body, headers)
}

// PatchJSON performs an HTTP PATCH request with JSON content type.
func (c *Client) PatchJSON(rawURL string, body []byte) (*Response, error) {
	return c.Do("PATCH", rawURL, body, map[string]string{
		"Content-Type": "application/json",
	})
}

// Delete performs an HTTP DELETE request.
func (c *Client) Delete(rawURL string) (*Response, error) {
	return c.Do("DELETE", rawURL, nil, nil)
}

// DeleteWithBody performs an HTTP DELETE request with a body.
func (c *Client) DeleteWithBody(rawURL string, body []byte, headers map[string]string) (*Response, error) {
	return c.Do("DELETE", rawURL, body, headers)
}

// Head performs an HTTP HEAD request.
func (c *Client) Head(rawURL string) (*Response, error) {
	return c.Do("HEAD", rawURL, nil, nil)
}

// PostForm performs an HTTP POST with URL-encoded form data.
func (c *Client) PostForm(rawURL string, data url.Values) (*Response, error) {
	return c.Do("POST", rawURL, []byte(data.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

// Do performs an HTTP request with the given method, URL, body, and headers.
func (c *Client) Do(method, rawURL string, body []byte, headers map[string]string) (*Response, error) {
	return c.DoWithContext(context.Background(), method, rawURL, body, headers)
}

// DoWithContext performs an HTTP request with context.
// If retry is configured, automatically retries on network errors and specified status codes.
func (c *Client) DoWithContext(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	maxAttempts := 1 + c.config.retryCount
	var lastErr error
	var lastResp *Response

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Drop any prior retryable response — only the final one is returned.
		if lastResp != nil {
			lastResp.Close()
			lastResp = nil
		}
		if attempt > 0 {
			// Exponential backoff: baseDelay * 2^(attempt-1)
			delay := c.config.retryBaseDelay * (1 << (attempt - 1))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}

		req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		// Stage Referer BEFORE applyBrowserHeaders so Sec-Fetch-Site can be
		// computed against the correct origin. Caller-supplied Referer wins
		// over the configured default.
		if v, ok := headers["Referer"]; ok && v != "" {
			req.Header.Set("Referer", v)
		} else if c.config.referer != "" {
			req.Header.Set("Referer", c.config.referer)
		}

		// Apply browser default headers (Sec-Fetch-Site reads the staged Referer).
		applyBrowserHeaders(req, c.config.browser, c.config.accept, c.config.acceptLanguage)

		// Apply custom User-Agent if set
		if c.config.userAgent != "" {
			req.Header.Set("User-Agent", c.config.userAgent)
		}

		// Apply custom headers (override defaults)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			// Network error - retry if we have attempts left
			if attempt < maxAttempts-1 {
				continue
			}
			return nil, lastErr
		}

		r := &Response{Response: resp, maxBodySize: c.config.maxResponseBody}

		// Check if we should retry on this status code
		if attempt < maxAttempts-1 && c.shouldRetryStatus(resp.StatusCode) {
			// Keep this response around — if retries exhaust without a non-retryable
			// status, the caller still gets the final attempt's full response
			// (body, headers, status) rather than just an "HTTP 503" error.
			lastResp = r
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		return r, nil
	}

	// All retries exhausted on retryable status codes — surface the last
	// response so the caller can still inspect headers/body.
	if lastResp != nil {
		return lastResp, nil
	}
	return nil, lastErr
}

// shouldRetryStatus checks if an HTTP status code should trigger a retry.
func (c *Client) shouldRetryStatus(statusCode int) bool {
	for _, code := range c.config.retryStatusCodes {
		if statusCode == code {
			return true
		}
	}
	return false
}

// DoHTTPRequest executes a standard *http.Request with fingerprint headers applied.
func (c *Client) DoHTTPRequest(req *http.Request) (*Response, error) {
	// Stage Referer first so Sec-Fetch-Site sees the correct origin.
	if c.config.referer != "" {
		setIfEmpty(req.Header, "Referer", c.config.referer)
	}
	applyBrowserHeaders(req, c.config.browser, c.config.accept, c.config.acceptLanguage)

	if c.config.userAgent != "" {
		req.Header.Set("User-Agent", c.config.userAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return &Response{Response: resp, maxBodySize: c.config.maxResponseBody}, nil
}

// PrepareRequest pre-builds a reusable request template for a given URL.
// The returned *http.Request has all browser headers pre-set. Clone it with
// req.Clone(ctx) or use FastDo for maximum throughput.
func (c *Client) PrepareRequest(method, rawURL string) (*http.Request, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// Stage Referer first so Sec-Fetch-Site sees the correct origin.
	if c.config.referer != "" {
		setIfEmpty(req.Header, "Referer", c.config.referer)
	}
	applyBrowserHeaders(req, c.config.browser, c.config.accept, c.config.acceptLanguage)
	if c.config.userAgent != "" {
		req.Header.Set("User-Agent", c.config.userAgent)
	}
	return req, nil
}

// FastDo sends a request using a pre-built template, bypassing http.Client.Do entirely.
// Skips: cookie jar (no mutex), redirect handling, retry logic, URL parsing.
// This is the fastest path for high-RPS workloads while maintaining full fingerprint bypass.
//
// If the template carries a body (POST/PUT), template.GetBody must be set: the
// shallow WithContext copy shares the single Body reader, which is consumed
// after the first send. We pull a fresh reader from GetBody on every call so
// the same template can be replayed with its body intact across millions of
// requests.
func (c *Client) FastDo(ctx context.Context, template *http.Request) (*Response, error) {
	// Use WithContext for a fast shallow copy instead of Clone() which does a deep
	// copy of headers/URL. Deep copies at high RPS cause massive GC pressure.
	req := template.WithContext(ctx)
	if template.GetBody != nil {
		body, err := template.GetBody()
		if err != nil {
			return nil, err
		}
		req.Body = body
	}
	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	return &Response{Response: resp, maxBodySize: c.config.maxResponseBody}, nil
}

// PreConnect pre-warms n TLS connections to the given URL.
// Call this before sending requests for lowest latency on first requests.
func (c *Client) PreConnect(ctx context.Context, rawURL string, n int) error {
	return c.transport.PreConnect(ctx, rawURL, n)
}

// NewPipeline creates a new Pipeline with the specified worker count.
// Use this for maximum RPS throughput.
//
//	pipeline := client.NewPipeline(3000)
//	defer pipeline.Close()
//	result := pipeline.Spray(ctx, "GET", "https://target.com", 100000)
func (c *Client) NewPipeline(workers int) *Pipeline {
	return newPipeline(c, workers)
}

// Close releases all resources held by the client.
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
	c.transport.dnscache.Close()
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

// BuildRequest creates an http.Request builder for complex requests.
func (c *Client) BuildRequest() *RequestBuilder {
	return &RequestBuilder{
		client:  c,
		headers: make(map[string]string),
	}
}

// RequestBuilder provides a fluent API for building HTTP requests.
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
