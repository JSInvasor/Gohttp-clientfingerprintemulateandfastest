package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// sendOne performs a single request and prints the result, splitting the timing
// into headers and body. The two are measured separately rather than reported
// as one number because they fail for different reasons: a slow header phase is
// the connection or the origin thinking, a slow body phase is transfer.
func sendOne(ctx context.Context, client *gofire.Client, o *options, target string, body []byte, headers map[string]string) error {
	start := time.Now()
	resp, err := client.DoWithContext(ctx, o.method, target, body, headers)
	if err != nil {
		return err
	}
	defer resp.Close()
	headerTime := time.Since(start)

	bodyStart := time.Now()
	data, bodyErr := resp.Bytes()
	bodyTime := time.Since(bodyStart)

	fmt.Fprintf(os.Stderr, "%s %d %s  headers %s  body %s  %d bytes\n",
		resp.Proto, resp.StatusCode(), statusText(resp.StatusCode()),
		round(headerTime), round(bodyTime), len(data))

	if o.showHeaders {
		names := make([]string, 0, len(resp.Header))
		for name := range resp.Header {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, v := range resp.Header[name] {
				fmt.Fprintf(os.Stderr, "%s: %s\n", name, v)
			}
		}
		fmt.Fprintln(os.Stderr)
	}

	if bodyErr != nil {
		return fmt.Errorf("read body: %w", bodyErr)
	}

	// A solve that earned a cookie and then got challenged anyway is the one
	// outcome this tool must not report as a plain 403 and a wall of HTML. It is
	// the exact symptom of two unrelated problems, and the difference decides
	// whether there is anything to fix here at all.
	if o.solve {
		reportRejectedClearance(o, target, resp.StatusCode(), resp.Header, data)
	}

	// A document with nothing following it is not what a page load looks like.
	// This runs after the timings above so the numbers still describe the
	// document alone.
	if o.assets {
		if docURL, err := url.Parse(target); err == nil {
			found := parseAssets(data, docURL, o.assetLimit)
			start := time.Now()
			ok, failed := fetchAssets(ctx, client, docURL, found, o.assetParallel)
			fmt.Fprintf(os.Stderr, "assets  %d referenced, %d fetched, %d failed  %s\n",
				len(found), ok, failed, round(time.Since(start)))
		}
	}

	switch {
	case o.outFile != "":
		if err := os.WriteFile(o.outFile, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", o.outFile, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(data), o.outFile)
	case !o.silent:
		os.Stdout.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			fmt.Println()
		}
	}
	return nil
}

// sendLoad runs the load phase and prints the summary.
func sendLoad(ctx context.Context, pool *sessionPool, o *options, target string, body []byte, headers map[string]string) error {
	st := newStats(o.count)

	// A duration run gets its own deadline; a count run ends when the counter
	// is exhausted. Both still honour the interrupt context above them.
	runCtx := ctx
	if o.duration > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, o.duration)
		defer cancel()
	}

	limiter := newLimiter(o.rate)
	defer limiter.stop()

	describeRun(o, pool, target)

	start := time.Now()
	var wg sync.WaitGroup
	var budget atomic.Int64
	budget.Store(int64(o.count))

	if o.mode == modePipeline {
		runPipeline(runCtx, pool, o, target, body, headers, st, limiter, &wg)
	} else if err := runWorkers(runCtx, pool, o, target, body, headers, st, limiter, &budget, &wg); err != nil {
		return err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	progress(done, st, o, start)
	elapsed := time.Since(start)

	// Before the summary, not after: a pipeline's bodies are read in a pool of
	// its own, and the run's waiter is satisfied by the last result rather than
	// by the last body. See sessionPool.closePipelines.
	pool.closePipelines()

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "interrupted after %d requests\n", st.sent.Load())
	}
	return report(st, elapsed, pool, o)
}

func describeRun(o *options, pool *sessionPool, target string) {
	scope := fmt.Sprintf("%d requests", o.count)
	if o.duration > 0 {
		scope = fmt.Sprintf("for %s", o.duration)
	}
	line := fmt.Sprintf("%s %s — %s, %d workers", o.method, target, scope, o.concurrency)
	if o.sessions > 1 {
		line += fmt.Sprintf(" across %d sessions", o.sessions)
	}
	if o.rate > 0 {
		line += fmt.Sprintf(", capped at %d req/s", o.rate)
	}
	line += fmt.Sprintf(", %s mode", o.mode)
	fmt.Fprintln(os.Stderr, line)
}

// runWorkers drives the client and fast modes: a fixed pool of goroutines, each
// bound to one session for the whole run.
//
// Binding rather than picking a session per request is deliberate. A session is
// an identity, and an identity that jumps between workers mid-run would
// interleave its cookies and its connection pool with everyone else's, which is
// the thing having separate sessions was supposed to prevent.
func runWorkers(ctx context.Context, pool *sessionPool, o *options, target string, body []byte, headers map[string]string, st *stats, lim *limiter, budget *atomic.Int64, wg *sync.WaitGroup) error {
	templates := make([]*http.Request, len(pool.sessions))
	if o.mode == modeFast {
		for i, s := range pool.sessions {
			tmpl, err := newFastTemplate(s.client, o.method, target, headers, body)
			if err != nil {
				// Returned rather than printed. This used to start no workers
				// and fall through to the summary, so a run that never sent a
				// request printed a tidy report of zero and exited 0.
				return fmt.Errorf("session %d: %w", i, err)
			}
			templates[i] = tmpl
		}
	}

	var index atomic.Int64
	for w := 0; w < o.concurrency; w++ {
		s := pool.sessions[w%len(pool.sessions)]
		template := templates[w%len(pool.sessions)]

		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				// A count run draws from a shared budget; a duration run has
				// none and stops on the context instead.
				if o.count > 0 && budget.Add(-1) < 0 {
					return
				}
				if ctx.Err() != nil || !lim.wait(ctx) {
					return
				}

				i := index.Add(1) - 1
				reqStart := time.Now()

				var (
					resp *gofire.Response
					err  error
				)
				if template != nil {
					// FastDo makes its own shallow copy and pulls a fresh body
					// from GetBody, so one template serves every worker.
					resp, err = s.client.FastDo(ctx, template)
				} else {
					resp, err = s.client.DoWithContext(ctx, o.method, target, body, headers)
				}
				if err != nil {
					if abortedByRun(ctx, err) {
						return
					}
					st.record(i, time.Since(reqStart), 0, err)
					continue
				}

				// Drain rather than abandon: a full read is what ends the
				// HTTP/2 stream with END_STREAM. Closing an unfinished body
				// makes the transport emit RST_STREAM, which Cloudflare and
				// Akamai score as an abusive client — so measuring throughput
				// must not be the thing that produces that signal.
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				st.bodyBytes.Add(n)
				st.record(i, time.Since(reqStart), resp.StatusCode(), nil)
			}
		}()
	}
	return nil
}

// runPipeline drives the pipeline mode. Each session owns a Pipeline sized to
// its share of the workers, and results arrive through OnResult rather than a
// channel per request — which is what keeps this the highest-throughput path
// that still reports per-request outcomes.
func runPipeline(ctx context.Context, pool *sessionPool, o *options, target string, body []byte, headers map[string]string, st *stats, lim *limiter, wg *sync.WaitGroup) {
	var index atomic.Int64
	var completed atomic.Int64

	for _, s := range pool.sessions {
		s := s
		// OnResult runs on pipeline workers, so it must not touch the body:
		// the pipeline drains it asynchronously in its own pool.
		s.pipeline.OnResult = func(resp *gofire.Response, err error, latency time.Duration) {
			if err != nil && abortedByRun(ctx, err) {
				completed.Add(1)
				return
			}
			i := index.Add(1) - 1
			code := 0
			if resp != nil {
				code = resp.StatusCode()
			}
			// No body accounting here. It used to add resp.ContentLength, which
			// is the *declared* length and is -1 on any response that does not
			// carry the header — which is every streamed HTTP/2 response, so
			// the guard dropped them all. Measured against a local h2 server
			// serving 20 responses of 8 KiB with no Content-Length: run.go
			// counted 0 bytes where 163840 were read off the wire.
			//
			// The body is drained by the pipeline's own pool, which already
			// counts what it read. sessionPool.drainedBytes reports that.
			st.record(i, latency, code, err)
			completed.Add(1)
		}
	}

	// One submitter per session. FireAndForget blocks when the pipeline's job
	// queue is full, so this is naturally back-pressured by the workers.
	var submitted atomic.Int64
	var budget atomic.Int64
	budget.Store(int64(o.count))

	var submitWG sync.WaitGroup
	for _, s := range pool.sessions {
		s := s
		submitWG.Add(1)
		go func() {
			defer submitWG.Done()
			for {
				if o.count > 0 && budget.Add(-1) < 0 {
					return
				}
				if ctx.Err() != nil || !lim.wait(ctx) {
					return
				}
				s.pipeline.FireAndForget(ctx, o.method, target, body, headers)
				submitted.Add(1)
			}
		}()
	}

	// The run is over when every submitted request has come back through
	// OnResult. Closing the pipelines before that would fail the queued jobs
	// rather than let them finish, so the wait is on the results, not on the
	// submitters.
	wg.Add(1)
	go func() {
		defer wg.Done()
		submitWG.Wait()

		target := submitted.Load()
		deadline := time.NewTimer(o.timeout + 5*time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for completed.Load() < target {
			select {
			case <-tick.C:
			case <-deadline.C:
				return
			case <-ctx.Done():
				// A cancelled or expired run stops waiting for stragglers, but
				// gives them a moment to land so the summary is not missing
				// requests that were already answered.
				time.Sleep(100 * time.Millisecond)
				return
			}
		}
	}()
}

// newFastTemplate builds the request FastDo replays.
//
// A body has to arrive as GetBody rather than as Body: the shallow copy FastDo
// makes shares the single reader, which is consumed after the first send, so a
// template carrying only Body would produce one real POST followed by a stream
// of empty ones.
func newFastTemplate(client *gofire.Client, method, target string, headers map[string]string, body []byte) (*http.Request, error) {
	req, err := client.PrepareRequest(method, target)
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	return req, nil
}

// abortedByRun reports whether err is a request the run itself killed on its
// way out, rather than something the target did.
//
// A -t run ends by cancelling its context, which aborts everything still in
// flight — one per worker. Counting those as failures made every duration run
// report a failure tally equal to its concurrency, which is noise that hides
// the real ones. The run's own context being done is what separates them from a
// genuine per-request -timeout, where it is not.
func abortedByRun(runCtx context.Context, err error) bool {
	if runCtx.Err() == nil {
		return false
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// limiter caps the whole run at a requests-per-second ceiling.
//
// Tokens are refilled in slices rather than one timer per request: Go's timers
// do not keep up much past ten thousand ticks a second, and this tool can
// otherwise drive far more than that, so a per-request ticker would silently
// become the ceiling instead of enforcing the requested one.
type limiter struct {
	tokens chan struct{}
	done   chan struct{}
}

const limiterSlicesPerSecond = 100

func newLimiter(rate int) *limiter {
	if rate <= 0 {
		return &limiter{}
	}
	l := &limiter{
		// One slice of burst, and never less than one token: enough that
		// workers are not serialised on the refill, small enough that the cap
		// holds over any visible window. The floor matters for a rate below one
		// per slice, where a zero-length bucket would have nowhere to put the
		// token when it comes.
		tokens: make(chan struct{}, max(rate/limiterSlicesPerSecond, 1)),
		done:   make(chan struct{}),
	}
	go func() {
		tick := time.NewTicker(time.Second / limiterSlicesPerSecond)
		defer tick.Stop()

		// carry is the fraction of a token left over from the previous slice.
		//
		// Without it the release per slice was rate/limiterSlicesPerSecond in
		// integer division, which got both ends of the range wrong. Any rate
		// below one per slice truncated to zero and was then floored back up to
		// one, so everything under 100 released a hundred a second — -rps 10
		// measured 100/s, ten times what was asked for, on the flag whose whole
		// purpose is to go easy on a target. And any rate that was not a
		// multiple of 100 rounded down: -rps 250 released 200, a fifth under.
		//
		// Carrying the remainder makes it exact on average — 250 goes 2, 3, 2,
		// 3, and 10 releases one token every tenth slice.
		carry := 0
		for {
			select {
			case <-l.done:
				return
			case <-tick.C:
				carry += rate
				release := carry / limiterSlicesPerSecond
				carry -= release * limiterSlicesPerSecond
				for i := 0; i < release; i++ {
					select {
					case l.tokens <- struct{}{}:
					default:
						// Bucket full: the run is slower than the cap, so
						// there is nothing to release. The rest of this slice
						// is dropped rather than saved into a later burst.
						i = release
					}
				}
			}
		}
	}()
	return l
}

// wait blocks until a token is available, reporting false if the run ended
// first.
func (l *limiter) wait(ctx context.Context) bool {
	if l.tokens == nil {
		return true
	}
	select {
	case <-l.tokens:
		return true
	case <-ctx.Done():
		return false
	}
}

func (l *limiter) stop() {
	if l.done != nil {
		close(l.done)
	}
}
