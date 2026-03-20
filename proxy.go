package gofire

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
)

// ProxyRotator rotates through a list of proxy URLs using round-robin.
type ProxyRotator struct {
	proxies []*url.URL
	counter atomic.Uint64
}

// NewProxyRotator creates a ProxyRotator from a list of proxy strings.
// Supported formats:
//   - ip:port                    -> http://ip:port
//   - ip:port:user:pass          -> http://user:pass@ip:port
//   - socks5://ip:port           -> socks5://ip:port
//   - http://ip:port             -> http://ip:port
//   - http://user:pass@ip:port   -> http://user:pass@ip:port
func NewProxyRotator(proxies []string) (*ProxyRotator, error) {
	if len(proxies) == 0 {
		return nil, fmt.Errorf("no proxies provided")
	}

	parsed := make([]*url.URL, 0, len(proxies))
	for _, p := range proxies {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}

		u, err := parseProxyString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy %q: %w", p, err)
		}
		parsed = append(parsed, u)
	}

	if len(parsed) == 0 {
		return nil, fmt.Errorf("no valid proxies found")
	}

	return &ProxyRotator{proxies: parsed}, nil
}

// NewProxyRotatorFromFile loads proxies from a file (one per line).
func NewProxyRotatorFromFile(path string) (*ProxyRotator, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open proxy file: %w", err)
	}
	defer f.Close()

	var proxies []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read proxy file: %w", err)
	}

	return NewProxyRotator(proxies)
}

// Next returns the next proxy URL in round-robin order.
func (pr *ProxyRotator) Next() *url.URL {
	idx := pr.counter.Add(1) - 1
	return pr.proxies[idx%uint64(len(pr.proxies))]
}

// Count returns the number of proxies.
func (pr *ProxyRotator) Count() int {
	return len(pr.proxies)
}

// ProxyFunc returns an http.Transport-compatible proxy function.
func (pr *ProxyRotator) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		return pr.Next(), nil
	}
}

// parseProxyString parses various proxy string formats into a URL.
func parseProxyString(s string) (*url.URL, error) {
	// Already a full URL
	if strings.Contains(s, "://") {
		return url.Parse(s)
	}

	parts := strings.Split(s, ":")
	switch len(parts) {
	case 2:
		// ip:port
		return url.Parse("http://" + s)
	case 4:
		// ip:port:user:pass
		host := parts[0] + ":" + parts[1]
		user := parts[2]
		pass := parts[3]
		return url.Parse(fmt.Sprintf("http://%s:%s@%s", user, pass, host))
	default:
		return url.Parse("http://" + s)
	}
}

// SetProxyRotator configures the client to use rotating proxies.
// This replaces any previously set proxy.
func (c *Client) SetProxyRotator(pr *ProxyRotator) {
	c.transport.inner.Proxy = pr.ProxyFunc()
}
