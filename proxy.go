package gofire

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// ProxyRotator rotates through a list of proxy URLs and tracks per-proxy health.
//
// A proxy that fails repeatedly is marked dead and skipped for a cooldown period;
// after the cooldown it gets one probe slot to recover. This keeps a partially
// rotten proxy list from dragging the whole RPS down to its slowest member.
type ProxyRotator struct {
	proxies []*proxyEntry
	counter atomic.Uint64

	// health holds the cooldown and failure threshold. It is a pointer so
	// every Pinned view shares it with the parent: the settings were
	// previously copied into each view, so a SetCooldown call after the views
	// existed silently applied to none of them. The fields are atomic because
	// MarkFailure reads them from dial goroutines while a caller may still be
	// setting them.
	health *proxyHealth

	// primaryIdx, when >= 0, makes this rotator "sticky": NextEntry always
	// prefers proxies[primaryIdx] while it is alive, and only rotates to a live
	// backup when the primary is in cooldown. -1 means pure round-robin.
	// Per-client views created via Pinned share the same proxyEntry pointers
	// (and thus health) but carry their own primaryIdx + counter.
	primaryIdx int
}

// proxyHealth is the failure policy shared by a rotator and all of its views.
type proxyHealth struct {
	cooldownNs    atomic.Int64
	failThreshold atomic.Int32
}

type proxyEntry struct {
	url *url.URL

	// failCount is the consecutive-failure counter. Reset to 0 on any success.
	failCount atomic.Int32

	// deadUntilNs is a unixnano timestamp; while time.Now() < deadUntil the
	// proxy is skipped by Next(). Stored as int64 so we can CAS it atomically.
	deadUntilNs atomic.Int64

	// totalUsed / totalFailed for diagnostics.
	totalUsed   atomic.Uint64
	totalFailed atomic.Uint64
}

// NewProxyRotator creates a ProxyRotator from a list of proxy strings.
// Supported formats:
//
//	ip:port                       -> http://ip:port
//	ip:port:user:pass             -> http://user:pass@ip:port
//	socks5://ip:port              -> SOCKS5 (no auth)
//	socks5://user:pass@ip:port    -> SOCKS5 with username/password auth
//	http://ip:port                -> HTTP CONNECT
//	http://user:pass@ip:port      -> HTTP CONNECT with Basic auth
//	https://ip:port               -> HTTPS CONNECT (TLS to proxy first)
func NewProxyRotator(proxies []string) (*ProxyRotator, error) {
	if len(proxies) == 0 {
		return nil, fmt.Errorf("no proxies provided")
	}

	parsed := make([]*proxyEntry, 0, len(proxies))
	for _, p := range proxies {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}

		u, err := parseProxyString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy %q: %w", p, err)
		}
		parsed = append(parsed, &proxyEntry{url: u})
	}

	if len(parsed) == 0 {
		return nil, fmt.Errorf("no valid proxies found")
	}

	health := &proxyHealth{}
	health.cooldownNs.Store(int64(30 * time.Second))
	health.failThreshold.Store(3)

	return &ProxyRotator{
		proxies:    parsed,
		health:     health,
		primaryIdx: -1,
	}, nil
}

// Pinned returns a lightweight per-client view of this rotator with a sticky
// primary proxy (proxies[idx]). The view SHARES the underlying proxy entries —
// and therefore their health (failure counts, cooldown) — with the parent and
// every sibling view, so a proxy marked dead by one client is skipped by all.
// Each view has its own round-robin cursor used only for failover.
//
// This gives both wide coverage (every client prefers a distinct proxy, so the
// whole list is exercised) and failover (a dead primary transparently routes
// through a live backup, then returns to the primary once it recovers).
func (pr *ProxyRotator) Pinned(idx int) *ProxyRotator {
	if len(pr.proxies) > 0 {
		idx = ((idx % len(pr.proxies)) + len(pr.proxies)) % len(pr.proxies)
	} else {
		idx = -1
	}
	return &ProxyRotator{
		proxies:    pr.proxies,
		health:     pr.health,
		primaryIdx: idx,
	}
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
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
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

// SetCooldown configures how long a dead proxy is skipped before getting
// another chance. Default 30s. Safe to call while requests are in flight, and
// the change is seen by every view created with Pinned.
func (pr *ProxyRotator) SetCooldown(d time.Duration) {
	if d > 0 {
		pr.health.cooldownNs.Store(int64(d))
	}
}

// SetFailThreshold configures how many consecutive failures mark a proxy
// dead. Default 3. Same concurrency and sharing rules as SetCooldown.
func (pr *ProxyRotator) SetFailThreshold(n int) {
	if n > 0 {
		pr.health.failThreshold.Store(int32(n))
	}
}

// Next returns the next live proxy URL in round-robin order. Dead proxies in
// cooldown are skipped. If every proxy is dead, returns the least-recently-failed
// one anyway (better to try a stale proxy than fail outright). Returns nil when
// the rotator holds no proxies.
func (pr *ProxyRotator) Next() *url.URL {
	e := pr.NextEntry()
	if e == nil {
		return nil
	}
	return e.url
}

// NextEntry is like Next but returns the proxyEntry so the caller can report
// success/failure back via MarkSuccess/MarkFailure.
func (pr *ProxyRotator) NextEntry() *proxyEntry {
	n := len(pr.proxies)
	now := time.Now().UnixNano()

	// Sticky primary: prefer the pinned proxy while it is alive. Once it enters
	// cooldown we fall through to the round-robin sweep for a live backup, and
	// when its cooldown expires this check picks it up again (re-probing it).
	if pr.primaryIdx >= 0 && pr.primaryIdx < n {
		if p := pr.proxies[pr.primaryIdx]; p.deadUntilNs.Load() <= now {
			return p
		}
	}

	// One full sweep: pick the first live proxy after our round-robin cursor.
	for i := 0; i < n; i++ {
		idx := pr.counter.Add(1) - 1
		entry := pr.proxies[idx%uint64(n)]
		if entry.deadUntilNs.Load() <= now {
			return entry
		}
	}

	// All proxies are in cooldown - return the one whose cooldown expires
	// soonest so we probe it. Better than failing the whole request.
	var best *proxyEntry
	var bestUntil int64
	for _, e := range pr.proxies {
		until := e.deadUntilNs.Load()
		if best == nil || until < bestUntil {
			best = e
			bestUntil = until
		}
	}
	return best
}

// MarkSuccess clears the failure count on a proxy.
func (pr *ProxyRotator) MarkSuccess(e *proxyEntry) {
	if e == nil {
		return
	}
	e.totalUsed.Add(1)
	e.failCount.Store(0)
	e.deadUntilNs.Store(0)
}

// MarkFailure increments the failure counter and, if the threshold is reached,
// puts the proxy in cooldown.
func (pr *ProxyRotator) MarkFailure(e *proxyEntry) {
	if e == nil {
		return
	}
	e.totalFailed.Add(1)
	if e.failCount.Add(1) >= pr.health.failThreshold.Load() {
		e.deadUntilNs.Store(time.Now().UnixNano() + pr.health.cooldownNs.Load())
	}
}

// Count returns the number of proxies (alive + dead).
func (pr *ProxyRotator) Count() int {
	return len(pr.proxies)
}

// ProxyURLs returns the canonical proxy URL strings (one per entry, in input
// order). Useful when the caller wants to pin one proxy per client instead
// of using shared rotation — the rotator's Next() is dial-time, so HTTP/2
// connection reuse means a small number of dials only ever exercises a few
// proxies. Pinning one proxy per client guarantees every entry is used.
func (pr *ProxyRotator) ProxyURLs() []string {
	out := make([]string, 0, len(pr.proxies))
	for _, e := range pr.proxies {
		out = append(out, e.url.String())
	}
	return out
}

// LiveCount returns the number of proxies not currently in cooldown.
func (pr *ProxyRotator) LiveCount() int {
	now := time.Now().UnixNano()
	c := 0
	for _, e := range pr.proxies {
		if e.deadUntilNs.Load() <= now {
			c++
		}
	}
	return c
}

// Stats returns a per-proxy snapshot for diagnostics.
type ProxyStat struct {
	URL         string
	Used        uint64
	Failed      uint64
	Alive       bool
	CooldownEnd time.Time
}

func (pr *ProxyRotator) Stats() []ProxyStat {
	now := time.Now()
	out := make([]ProxyStat, 0, len(pr.proxies))
	for _, e := range pr.proxies {
		until := time.Unix(0, e.deadUntilNs.Load())
		out = append(out, ProxyStat{
			URL:         e.url.Redacted(),
			Used:        e.totalUsed.Load(),
			Failed:      e.totalFailed.Load(),
			Alive:       until.Before(now),
			CooldownEnd: until,
		})
	}
	return out
}

// ProxyFunc returns an http.Transport-compatible proxy function. The function
// rotates with each call; this is invoked by Transport.dialRaw at every new
// dial, so connection-level rotation happens automatically.
func (pr *ProxyRotator) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		return pr.Next(), nil
	}
}

// proxyFuncEntry is a richer variant that returns the entry too, so the
// transport can call MarkSuccess/MarkFailure on the actual entry that was used.
func (pr *ProxyRotator) nextProxyEntry() (*url.URL, *proxyEntry) {
	e := pr.NextEntry()
	return e.url, e
}

// parseProxyString parses various proxy string formats into a URL.
//
// The shorthand forms (ip:port and ip:port:user:pass) default to http://. The
// scheme-prefixed form lets the caller pick http/https/socks5.
func parseProxyString(s string) (*url.URL, error) {
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return nil, err
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("missing host")
		}
		return u, nil
	}

	// Shorthand: split only on the first three colons so passwords containing
	// ':' don't get mangled. Real format is host:port[:user:pass].
	parts := strings.SplitN(s, ":", 4)
	switch len(parts) {
	case 2:
		return url.Parse("http://" + s)
	case 4:
		host := parts[0] + ":" + parts[1]
		user := url.QueryEscape(parts[2])
		pass := url.QueryEscape(parts[3])
		return url.Parse(fmt.Sprintf("http://%s:%s@%s", user, pass, host))
	default:
		return nil, fmt.Errorf("expected ip:port or ip:port:user:pass, got %q", s)
	}
}

// SetProxyRotator configures the client to use rotating proxies with health
// tracking. Failed dials and CONNECT/SOCKS5 errors are reported back to the
// rotator so dead proxies are taken out of rotation automatically.
//
// Proxies are applied at the dial level, so they work for both HTTP/1.1 and
// HTTP/2 transports.
func (c *Client) SetProxyRotator(pr *ProxyRotator) {
	c.transport.setProxyRotator(pr)
}
