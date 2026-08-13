package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// session is one independent identity: a Client with its own cookie jar, its
// own connection pool, and — when a proxy list is loaded — its own pinned
// proxy.
//
// Separating them matters for what this client is for. A target that scores
// behaviour per identity sees one session making a thousand requests very
// differently from a thousand sessions making one each, and the cookie jar is
// half of that: a shared jar means every worker presents whatever session
// cookie the origin handed the first one.
type session struct {
	index    int
	client   *gofire.Client
	pipeline *gofire.Pipeline
}

type sessionPool struct {
	sessions []*session
	rotator  *gofire.ProxyRotator
}

func newSessionPool(o *options, profile gofire.BrowserProfile, target string) (*sessionPool, error) {
	pool := &sessionPool{}

	if o.proxyFile != "" {
		rotator, err := gofire.NewProxyRotatorFromFile(o.proxyFile)
		if err != nil {
			return nil, fmt.Errorf("proxy file: %w", err)
		}
		if o.proxyCooldown > 0 {
			rotator.SetCooldown(o.proxyCooldown)
		}
		if o.proxyFails > 0 {
			rotator.SetFailThreshold(o.proxyFails)
		}
		pool.rotator = rotator
	}

	for i := 0; i < o.sessions; i++ {
		s, err := newSession(o, profile, target, i, pool.rotator)
		if err != nil {
			pool.Close()
			return nil, err
		}
		pool.sessions = append(pool.sessions, s)
	}

	if pool.rotator != nil {
		fmt.Fprintf(os.Stderr, "%d proxies loaded, %d sessions pinned across them\n",
			pool.rotator.Count(), o.sessions)
	}
	return pool, nil
}

func newSession(o *options, profile gofire.BrowserProfile, target string, index int, rotator *gofire.ProxyRotator) (*session, error) {
	client, err := gofire.Emulate(profile, clientOptions(o)...)
	if err != nil {
		return nil, err
	}

	if rotator != nil {
		// Pinned gives this session a primary proxy of its own while sharing
		// health state with its siblings, so the list is covered evenly and a
		// proxy one session finds dead is skipped by all of them.
		client.SetProxyRotator(rotator.Pinned(index))
	}

	if len(o.cookies) > 0 {
		cookies := make([]*http.Cookie, 0, len(o.cookies))
		for _, raw := range o.cookies {
			name, value, _ := strings.Cut(raw, "=")
			cookies = append(cookies, &http.Cookie{Name: strings.TrimSpace(name), Value: value})
		}
		if err := client.SetCookies(target, cookies); err != nil {
			client.Close()
			return nil, fmt.Errorf("seed cookies: %w", err)
		}
	}

	s := &session{index: index, client: client}

	if o.mode == modePipeline {
		workers := o.concurrency / o.sessions
		if index < o.concurrency%o.sessions {
			workers++
		}
		s.pipeline = client.NewPipelineWithConfig(gofire.PipelineConfig{
			Workers: workers,
			// Matching drain workers to request workers keeps a slow body from
			// backing up into the request path. The pipeline blocks rather than
			// truncating when the drain queue fills — truncating would emit
			// RST_STREAM, the abusive-client signal this package exists to
			// avoid — so an undersized drain pool shows up as lost throughput.
			DrainWorkers: workers,
		})
	}
	return s, nil
}

// clientOptions maps the flags onto the library's options. Everything is left
// at the library default unless the flag was actually given, so an unset knob
// means "whatever the package chose" rather than a zero this tool invented.
func clientOptions(o *options) []gofire.Option {
	opts := []gofire.Option{
		gofire.WithTimeout(o.timeout),
		gofire.WithTLSHandshakeTimeout(o.handshake),
	}

	add := func(cond bool, opt gofire.Option) {
		if cond {
			opts = append(opts, opt)
		}
	}

	add(o.proxy != "", gofire.WithProxy(o.proxy))
	add(o.dialTimeout > 0, gofire.WithDialTimeout(o.dialTimeout))
	add(o.headerTimeout > 0, gofire.WithResponseHeaderTimeout(o.headerTimeout))
	add(o.writeTimeout > 0, gofire.WithWriteByteTimeout(o.writeTimeout))
	add(o.dnsTTL > 0, gofire.WithDNSCacheTTL(o.dnsTTL))
	add(o.forceH1, gofire.WithForceHTTP1())
	add(o.insecure, gofire.WithInsecureSkipVerify())
	add(o.noRedirect, gofire.WithDisableRedirects())
	add(o.maxRedirects > 0, gofire.WithMaxRedirects(o.maxRedirects))
	add(o.noKeepAlive, gofire.WithDisableKeepAlives())
	add(o.maxStreams > 0, gofire.WithMaxStreamsPerConn(o.maxStreams))
	add(o.idleConns > 0, gofire.WithMaxIdleConns(o.idleConns))
	add(o.idlePerHost > 0, gofire.WithMaxIdleConnsPerHost(o.idlePerHost))
	add(o.connsPerHost > 0, gofire.WithMaxConnsPerHost(o.connsPerHost))
	add(o.sockBuf > 0, gofire.WithSocketBuffers(o.sockBuf, o.sockBuf))
	add(o.fastOpen, gofire.WithTCPFastOpen())
	add(o.tlsResume, gofire.WithTLSSessionResumption())
	add(o.lang != "", gofire.WithAcceptLanguage(o.lang))
	add(o.accept != "", gofire.WithAccept(o.accept))
	add(o.userAgent != "", gofire.WithUserAgent(o.userAgent))
	add(o.referer != "", gofire.WithReferer(o.referer))
	add(o.retries > 0, gofire.WithRetry(o.retries, 200*time.Millisecond, 429, 502, 503, 504))
	// -1 is "flag not given"; 0 is a deliberate request for no ceiling.
	add(o.maxBody >= 0, gofire.WithMaxResponseBodySize(o.maxBody))

	return opts
}

// warm pre-opens connections on every session so the first measured requests
// are not paying for handshakes the run is not trying to measure.
func (p *sessionPool) warm(ctx context.Context, target string, n int) {
	for _, s := range p.sessions {
		if err := s.client.PreConnect(ctx, target, n); err != nil {
			fmt.Fprintf(os.Stderr, "session %d preconnect: %v\n", s.index, err)
		}
	}
}

// connections totals the TLS connections every session opened.
func (p *sessionPool) connections() int64 {
	var total int64
	for _, s := range p.sessions {
		total += s.client.ActiveConnections()
	}
	return total
}

func (p *sessionPool) Close() {
	for _, s := range p.sessions {
		if s.pipeline != nil {
			s.pipeline.Close()
		}
		s.client.Close()
	}
}
