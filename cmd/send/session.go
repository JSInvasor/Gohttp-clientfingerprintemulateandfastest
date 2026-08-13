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

	rotator, err := newRotator(o)
	if err != nil {
		return nil, err
	}
	pool.rotator = rotator

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

// newRotator builds the proxy rotator every session shares, or nil when the run
// has no list.
//
// A solve narrows the file down to the exits that actually earned a cookie, and
// that narrowed list wins here. Re-reading the file would put the exits that
// failed back into rotation with nothing to present at them.
func newRotator(o *options) (*gofire.ProxyRotator, error) {
	var (
		rotator *gofire.ProxyRotator
		err     error
	)
	switch {
	case len(o.proxyList) > 0:
		rotator, err = gofire.NewProxyRotator(o.proxyList)
	case o.proxyFile != "":
		rotator, err = gofire.NewProxyRotatorFromFile(o.proxyFile)
	default:
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("proxy file: %w", err)
	}

	if o.proxyCooldown > 0 {
		rotator.SetCooldown(o.proxyCooldown)
	}
	if o.proxyFails > 0 {
		rotator.SetFailThreshold(o.proxyFails)
	}
	return rotator, nil
}

// seedFor returns the solved identity session index replays, or nil when the run
// has one identity for every session — a single solve goes into o.cookies and
// o.userAgent instead, the same way -cookie and -ua do.
//
// The modulo matches how newSession pins its proxy, which is what keeps a
// session's cookies on the exit they were issued to when there are more sessions
// than exits. Two sessions sharing an exit share its cookie legitimately: same
// IP, same UA, same fingerprint.
func (o *options) seedFor(index int) *solveSeed {
	if len(o.solveSeeds) == 0 {
		return nil
	}
	return &o.solveSeeds[index%len(o.solveSeeds)]
}

func newSession(o *options, profile gofire.BrowserProfile, target string, index int, rotator *gofire.ProxyRotator) (*session, error) {
	seed := o.seedFor(index)

	client, err := gofire.Emulate(profile, clientOptions(o, seed)...)
	if err != nil {
		return nil, err
	}

	if rotator != nil {
		switch {
		case seed != nil:
			// This session holds a cf_clearance issued to this exit's address,
			// so PinnedOnly drops the failover: a dead proxy fails its own
			// session's dials instead of routing its cookie through a sibling's
			// IP, which the edge answers with 403s that read as the target
			// blocking the client.
			client.SetProxyRotator(rotator.PinnedOnly(index))
		default:
			// Pinned gives this session a primary proxy of its own while sharing
			// health state with its siblings, so the list is covered evenly and a
			// proxy one session finds dead is skipped by all of them.
			client.SetProxyRotator(rotator.Pinned(index))
		}
	}

	// The seeded cookies come after the ones -cookie asked for, so a solve
	// cannot be quietly overwritten by a stale hand-typed cf_clearance.
	raw := o.cookies
	if seed != nil {
		raw = append(append(make([]string, 0, len(o.cookies)+len(seed.cookies)), o.cookies...), seed.cookies...)
	}
	if len(raw) > 0 {
		cookies := make([]*http.Cookie, 0, len(raw))
		for _, c := range raw {
			name, value, _ := strings.Cut(c, "=")
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
//
// seed is this session's solved identity, when it has one of its own. Its UA is
// part of what the cookie is bound to, so it belongs to the session rather than
// to the run.
func clientOptions(o *options, seed *solveSeed) []gofire.Option {
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

	// Last option wins, so an explicit -ua above still beats the solved UA —
	// deliberately. Replacing an override the user typed would hide the
	// mismatch it creates rather than surface it, and solveAndSeed already warns
	// about that one.
	if seed != nil && o.userAgent == "" && seed.userAgent != "" {
		opts = append(opts, gofire.WithUserAgent(seed.userAgent))
	}

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
