package main

import (
	"context"
	"fmt"
	"io"
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
		describeExits(os.Stderr, o, pool.rotator.Count())
	}
	return pool, nil
}

// describeExits says how many of the loaded proxies the run will actually leave
// from, which is not the same number as how many were loaded.
//
// It used to print "%d proxies loaded, %d sessions pinned across them", which
// reads as though the list is in use. It is not: a pinned session dials one
// exit for its whole life, so a hundred-entry file behind -s 2 is two addresses
// and ninety-eight idle lines. That is the single most surprising thing about
// this tool's proxying, and it was being reported as a success.
func describeExits(w io.Writer, o *options, loaded int) {
	if o.proxyRotate {
		fmt.Fprintf(w, "%d proxies loaded, every session rotating over all of them "+
			"(a fresh exit per connection)\n", loaded)
		// Rotation is per dial, so a session that opens one connection and keeps
		// it rotates exactly once. Worth saying while there is still time to add
		// the flag that fixes it rather than after a run that used two addresses.
		if !o.noKeepAlive && o.maxStreams == 0 {
			fmt.Fprintf(w, "  note: the exit changes when a connection is opened, and HTTP/2 keeps "+
				"one open — add -no-keepalive (an exit per request) or -max-streams N to keep it turning\n")
		}
		return
	}

	used := min(loaded, o.sessions)
	fmt.Fprintf(w, "%d proxies loaded, %d session(s) pinned across them — this run leaves from %d of them\n",
		loaded, o.sessions, used)
	if used < loaded {
		fmt.Fprintf(w, "  %d entries will never be dialled: a pinned session keeps one exit for the whole "+
			"run. Raise -s (up to -c, currently %d) to use more, or -proxy-rotate to take the whole list\n",
			loaded-used, o.concurrency)
	}
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
		case o.proxyRotate:
			// The bare rotator: NextEntry takes the next live entry on every
			// dial, so one session reaches the whole list rather than one
			// address of it. See newSessionPool for why that is a flag and not
			// the default.
			client.SetProxyRotator(rotator)
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
	add(o.forceH3, gofire.WithForceHTTP3())
	add(o.noH3, gofire.WithoutHTTP3())
	add(o.insecure, gofire.WithInsecureSkipVerify())
	add(o.noRedirect, gofire.WithDisableRedirects())
	add(o.maxRedirects > 0, gofire.WithMaxRedirects(o.maxRedirects))
	add(o.noKeepAlive, gofire.WithDisableKeepAlives())
	add(o.maxStreams > 0, gofire.WithMaxStreamsPerConn(o.maxStreams))
	add(o.idleConns > 0, gofire.WithMaxIdleConns(o.idleConns))
	add(o.idlePerHost > 0, gofire.WithMaxIdleConnsPerHost(o.idlePerHost))
	add(o.connsPerHost > 0, gofire.WithMaxConnsPerHost(o.connsPerHost))
	// -tls is the connection count: run pre-opens that many per session (a bare
	// -tls resolves to the machine's budget), and this holds the pool there so
	// the run reuses them rather than opening more. It comes after -conns-per-host
	// so an explicit -tls wins if both are given. The cap binds on the HTTP/1.1
	// path; over HTTP/2 the pre-opened connections carry the run and -max-streams
	// governs when one is cycled.
	if n := o.tlsConnCount(); n > 0 {
		opts = append(opts, gofire.WithMaxConnsPerHost(n))
	}
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

	// The language is the same handover as the UA, and it overrides -lang rather
	// than deferring to it — which is the opposite of the rule above, for a
	// reason. -ua is a value the user typed and the run is theirs to break; the
	// solve's Accept-Language is not something anyone typed, it is what the
	// browser did with what they typed. Chromium regenerates the header from the
	// first tag and drops the rest, so honouring -lang here would replay a
	// language the session that earned the cookie never advertised — while
	// looking, in the flags, as though the two agreed.
	if seed != nil && seed.acceptLanguage != "" {
		opts = append(opts, gofire.WithAcceptLanguage(seed.acceptLanguage))
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

// closePipelines ends the pipelines and waits for their drain pools, so what the
// run reports is what it finished rather than what it had got round to.
//
// It has to happen before the summary, not in the deferred Close(). A pipeline
// hands each body to a drain pool and returns, so OnResult firing for the last
// request does not mean the last body has been read — the run's own waiter is
// satisfied while bodies are still in the queue. Measured against a local h2
// server, a 20-request run reported 19 bodies' worth about half the time.
//
// Pipeline.Close is idempotent, so the pool's own Close still runs afterwards.
func (p *sessionPool) closePipelines() {
	for _, s := range p.sessions {
		if s.pipeline != nil {
			s.pipeline.Close()
		}
	}
}

// drainedBytes totals what the pipelines actually read off the wire, and reports
// whether there was a pipeline to ask.
//
// It exists because the other two modes count bytes where they read them — the
// io.Copy in runWorkers returns the number — and pipeline mode cannot: the body
// is handed to the pipeline's drain pool and read there, so by the time OnResult
// sees the response there is nothing left to measure. What OnResult had instead
// was resp.ContentLength, the length the origin *declared*, which is -1 whenever
// the header is absent. That is every streamed HTTP/2 response, so the run
// reported no body at all for the mode that moves the most of it.
func (p *sessionPool) drainedBytes() (int64, bool) {
	var total int64
	found := false
	for _, s := range p.sessions {
		if s.pipeline != nil {
			total += s.pipeline.Stats.TotalBytes.Load()
			found = true
		}
	}
	return total, found
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
