package gofire

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// Pre-warming connections, and the pace they are opened at.
//
// Standing up a connection is not free to either end: a dial, a TLS handshake
// and — over HTTP/2 — a preface and SETTINGS exchange. Asking for a few is
// nothing; asking for tens of thousands and starting them all at once is a burst
// no browser produces and no target enjoys, and it does not even work: the
// handshakes contend for CPU, the ones at the back of the queue time out, and
// the caller cannot tell a target that refused the load from a client that
// asked for more than it could carry.
//
// So the count and the pace are separate dials here. How many connections to end
// up with is the caller's business; how fast to get there is what this file
// governs, and it is bounded whether the caller thinks about it or not.

// PreConnectConfig paces how PreConnect stands up its connections.
//
// The zero value is the default pace: a bounded number of handshakes in flight
// and no ceiling on how quickly they are started.
type PreConnectConfig struct {
	// Concurrency is how many handshakes may be in flight at once. 0 means
	// DefaultPreConnectConcurrency. The requested count is itself a ceiling —
	// pre-warming ten connections never runs more than ten dials.
	Concurrency int

	// Rate caps how many connections are *started* per second. 0 opens them as
	// fast as Concurrency allows, which for a large count is still a slope
	// rather than a step.
	//
	// This is the knob for going easy on the target rather than on this
	// process: a rate is what an edge sees as a connection arrival curve, and
	// a curve is what distinguishes a client warming up from a client
	// flooding.
	Rate int

	// Progress, when set, is called about once a second while the warm runs and
	// once more when it ends, with the number of connections opened so far and
	// the number asked for. Calls are serialised, so it needs no locking of its
	// own, and it is never called concurrently with PreConnect's return.
	//
	// It exists because a large warm takes long enough that silence is
	// indistinguishable from a hang.
	Progress func(opened, total int)
}

// DefaultPreConnectConcurrency is how many handshakes PreConnect runs at once
// when the caller does not say.
//
// It is a ceiling on the burst, not a target: a warm of 50 connections still
// opens all 50 together. What it bounds is the case the old unbounded loop got
// wrong — a five-figure count, where starting every dial at once means tens of
// thousands of goroutines contending for the CPU that the TLS handshakes need,
// and the tail of that queue failing on a timeout that measured nothing but the
// size of the burst.
const DefaultPreConnectConcurrency = 256

// PreConnect pre-warms n connections to the given URL at the default pace.
//
// It opens each connection and runs the TLS handshake plus the HTTP/2
// preface/SETTINGS/WINDOW_UPDATE exchange, then parks the connection in the
// pool. No HTTP request is sent — which is precisely what a browser's
// <link rel="preconnect"> does.
//
// The previous implementation fired n concurrent `HEAD /` requests carrying
// only User-Agent and Accept: */*. That leaked a request shape the emulated
// browser cannot produce (Chrome without any sec-ch-ua/sec-fetch-* header,
// Safari without accept-language, and a HEAD for a document neither of them
// ever issues), landing it in the target's logs right beside a handshake that
// claims to be that browser. It also could not reliably open n connections: the
// HTTP/2 pool hands an existing connection to any request that still has stream
// capacity, so the burst frequently collapsed onto one connection.
func (t *Transport) PreConnect(ctx context.Context, rawURL string, n int) error {
	_, err := t.PreConnectWithConfig(ctx, rawURL, n, PreConnectConfig{})
	return err
}

// PreConnectWithConfig is PreConnect with the pace spelled out, returning how
// many connections it actually opened.
//
// The count is returned rather than only the error because a partial warm is a
// normal outcome at large counts — a target that accepts eight thousand of the
// ten thousand asked for has told the caller something useful, and an error
// alone throws that away. It is accurate whether the warm finished, failed in
// part, or stopped early because ctx was cancelled.
func (t *Transport) PreConnectWithConfig(ctx context.Context, rawURL string, n int, cfg PreConnectConfig) (int, error) {
	if n <= 0 {
		n = 10
	}

	addr, isTLS, err := preconnectAddr(rawURL)
	if err != nil {
		return 0, err
	}

	workers := cfg.Concurrency
	if workers <= 0 {
		workers = DefaultPreConnectConcurrency
	}
	if workers > n {
		workers = n
	}

	pacer := newConnPacer(cfg.Rate)
	defer pacer.stop()

	var (
		opened   atomic.Int64
		failed   atomic.Int64
		next     atomic.Int64
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	fail := func(err error) {
		failed.Add(1)
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	stopProgress := startProgress(cfg.Progress, &opened, n)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each worker claims the next slot until the run is used up, so the
			// pool sizes the burst without the count having to be divisible by
			// it — and a slow handshake holds up only its own worker.
			for next.Add(1) <= int64(n) {
				if !pacer.wait(ctx) {
					return
				}
				if err := t.preconnectOne(ctx, addr, isTLS); err != nil {
					fail(err)
					// A cancelled context fails every remaining slot in turn,
					// which would bury the real first error under thousands of
					// its own. Stopping here leaves the count as what was
					// actually opened.
					if ctx.Err() != nil {
						return
					}
					continue
				}
				opened.Add(1)
			}
		}()
	}

	wg.Wait()
	stopProgress()
	if cfg.Progress != nil {
		cfg.Progress(int(opened.Load()), n)
	}

	if nFailed := int(failed.Load()); nFailed > 0 {
		return int(opened.Load()), fmt.Errorf("preconnect: %d/%d failed, first: %w", nFailed, n, firstErr)
	}
	return int(opened.Load()), nil
}

// startProgress runs the once-a-second progress callback and returns the
// function that stops it, having waited for the last call to finish. Waiting is
// what lets the caller make a final call of its own without racing this one.
func startProgress(report func(opened, total int), opened *atomic.Int64, total int) func() {
	if report == nil {
		return func() {}
	}
	var (
		done = make(chan struct{})
		gone = make(chan struct{})
		once sync.Once
	)
	go func() {
		defer close(gone)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				report(int(opened.Load()), total)
			}
		}
	}()
	return func() {
		once.Do(func() { close(done) })
		<-gone
	}
}

// connPacer releases permission to start one connection, at most Rate of them a
// second.
//
// It is the limiter from the request path in miniature, and for the same reason:
// tokens are refilled in slices rather than one timer per connection, because a
// ticker per connection stops being the pace and starts being the ceiling well
// before the rates this tool runs at. The carried remainder keeps a rate that is
// not a multiple of the slice count exact on average rather than rounded down.
type connPacer struct {
	tokens chan struct{}
	done   chan struct{}
}

const pacerSlicesPerSecond = 20

func newConnPacer(rate int) *connPacer {
	if rate <= 0 {
		return &connPacer{}
	}
	p := &connPacer{
		tokens: make(chan struct{}, max(rate/pacerSlicesPerSecond, 1)),
		done:   make(chan struct{}),
	}
	go func() {
		tick := time.NewTicker(time.Second / pacerSlicesPerSecond)
		defer tick.Stop()

		carry := 0
		for {
			select {
			case <-p.done:
				return
			case <-tick.C:
				carry += rate
				release := carry / pacerSlicesPerSecond
				carry -= release * pacerSlicesPerSecond
				for i := 0; i < release; i++ {
					select {
					case p.tokens <- struct{}{}:
					default:
						// Bucket full: the handshakes are slower than the rate,
						// so this slice has nothing to give. Dropping it rather
						// than banking it is what keeps a slow start from
						// turning into a burst once the target speeds up.
						i = release
					}
				}
			}
		}
	}()
	return p
}

// wait blocks until a connection may be started, reporting false if ctx ended
// first.
func (p *connPacer) wait(ctx context.Context) bool {
	if p.tokens == nil {
		return ctx.Err() == nil
	}
	select {
	case <-p.tokens:
		return true
	case <-ctx.Done():
		return false
	}
}

func (p *connPacer) stop() {
	if p.done != nil {
		close(p.done)
	}
}

// preconnectAddr resolves a URL to the dial target and whether it is TLS.
func preconnectAddr(rawURL string) (addr string, isTLS bool, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false, fmt.Errorf("preconnect: invalid URL: %w", err)
	}
	if u.Host == "" {
		return "", false, fmt.Errorf("preconnect: URL %q has no host", rawURL)
	}

	port := u.Port()
	switch u.Scheme {
	case "https":
		isTLS = true
		if port == "" {
			port = "443"
		}
	case "http":
		if port == "" {
			port = "80"
		}
	default:
		return "", false, fmt.Errorf("preconnect: unsupported scheme %q", u.Scheme)
	}
	return net.JoinHostPort(u.Hostname(), port), isTLS, nil
}

// preconnectOne opens a single warmed connection and registers it.
//
// An HTTP/2 connection is handed to the h2 pool, which runs the preface and
// SETTINGS exchange as part of adopting it. Anything else (cleartext, or a host
// whose ALPN selects http/1.1) has no equivalent injection point in
// net/http.Transport, so the connection is closed again after the handshake:
// the DNS entry, the TCP path and — for TLS — the session ticket are warm even
// though the socket itself is not reused.
func (t *Transport) preconnectOne(ctx context.Context, addr string, isTLS bool) error {
	if !isTLS || t.h2Transport == nil || t.forceH1 {
		conn, err := t.dialPreconnect(ctx, addr, isTLS)
		if err != nil {
			return err
		}
		return conn.Close()
	}

	conn, err := t.dialTLSForH2(ctx, "tcp", addr)
	if err != nil {
		if errors.Is(err, errAlpnHTTP1) {
			// dialTLSForH2 has already cached host->http/1.1 and closed the
			// conn; the h1 path will take it from here.
			return nil
		}
		return err
	}

	if err := t.h2Transport.AdoptConn(addr, conn); err != nil {
		conn.Close()
		return err
	}
	return nil
}

// dialPreconnect opens a connection without registering it anywhere.
func (t *Transport) dialPreconnect(ctx context.Context, addr string, isTLS bool) (net.Conn, error) {
	if isTLS {
		return t.dialTLS(ctx, "tcp", addr, []string{"http/1.1"})
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	conn, _, entry, err := t.dialRaw(ctx, "tcp", host, port)
	if err != nil {
		return nil, err
	}
	t.scoreProxy(entry, true)
	return conn, nil
}
