package gofire

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// PipelineResult holds the result of a pipelined request.
type PipelineResult struct {
	Response *Response
	Err      error
	Latency  time.Duration
}

// PipelineStats holds real-time statistics for a pipeline.
type PipelineStats struct {
	TotalSent  atomic.Int64
	TotalOK    atomic.Int64
	TotalErr   atomic.Int64
	TotalBytes atomic.Int64
}

// Pipeline sends through a fixed worker pool, pre-allocated and reusing
// connections, and reports every outcome through OnResult without a channel per
// request.
//
// It is not the fastest path, which it used to claim to be. Measured against a
// local server at 256, 1024 and 3000 workers, FastDo beat it at every one — by
// 19%, 29% and 12% — and cost 20-30% less CPU per request, because a pipelined
// request carries two extra channel hops and a goroutine handoff for the
// asynchronous body drain. What the pipeline buys is submission control and
// per-request results at high concurrency without a channel per request; if the
// goal is only throughput, PrepareRequest + FastDo is the shorter path.
type Pipeline struct {
	client  *Client
	workers int
	wg      sync.WaitGroup
	jobCh   chan *pipelineJob
	// stopCh is closed by Close() to signal senders to abandon their writes
	// to jobCh. Senders select on stopCh alongside jobCh so a concurrent
	// Close() can never cause a "send on closed channel" panic.
	stopCh chan struct{}
	Stats  PipelineStats
	closed atomic.Bool

	// inFlight counts submitters that have passed the closed check and may
	// still be writing to jobCh. Close waits for it to reach zero before
	// failing queued jobs, so no job can be enqueued after that sweep and be
	// left with nobody to answer it.
	inFlight atomic.Int64

	// OnResult is called for every completed request (both success and error).
	// When set, FireAndForget will invoke this callback instead of discarding results.
	// The callback must be set before sending any requests.
	// IMPORTANT: The callback should NOT call Response.Close() - the pipeline
	// drains response bodies asynchronously to avoid blocking workers.
	OnResult func(resp *Response, err error, latency time.Duration)

	// Pre-built request template for FastDo path (set via SetTemplate)
	// Uses atomic.Pointer for lock-free concurrent access during cookie refresh.
	template atomic.Pointer[http.Request]

	// Async body drain pool - workers hand off response bodies here
	// so they can immediately pick up the next request
	drainCh chan *http.Response
	drainWg sync.WaitGroup

	// drainMu guards whether drainCh is still open. asyncDrain holds it for
	// read across its send; Close takes it for write before closing.
	//
	// Nothing else keeps those two apart. Spray runs collect -> asyncDrain on
	// the CALLER's goroutine, which neither p.wg (workers only) nor p.inFlight
	// (submitters only) covers, so a collector parked on a full drainCh was
	// free to be sending at the moment Close closed the channel — "send on
	// closed channel", which is a panic, not an error.
	drainMu     sync.RWMutex
	drainClosed bool

	// Object pools to reduce GC pressure at high RPS
	jobPool    sync.Pool
	resultPool sync.Pool
}

type pipelineJob struct {
	ctx     context.Context
	method  string
	url     string
	body    []byte
	headers map[string]string
	result  chan<- *PipelineResult

	// blockResult makes the worker wait for the result to be received rather
	// than dropping it when the channel is full. Send gives every job its own
	// single-slot channel so the non-blocking send always lands, but Spray
	// shares one bounded channel across every request, where a dropped result
	// would silently corrupt its totals.
	blockResult bool
}

// PipelineConfig tunes pipeline internals beyond worker count.
//
// DrainWorkers controls how many goroutines read response bodies in the
// background. When 0, the pipeline picks workers/4 (with a 64 floor). Set
// equal to Workers for maximum throughput at the cost of more idle goroutines
// blocked in select; lower if memory/CPU is the bottleneck and bodies are
// small.
//
// JobBufferMultiplier sizes the request channel (workers*N). Default 16.
// DrainBufferMultiplier sizes the drain channel (workers*N). Default 4.
type PipelineConfig struct {
	Workers               int
	DrainWorkers          int
	JobBufferMultiplier   int
	DrainBufferMultiplier int
}

// newPipeline creates a new Pipeline with the specified number of workers.
// Workers run continuously, pulling jobs from a shared channel.
//
// How many workers is a function of latency, not of a target RPS. A worker is
// one request in flight, so by Little's Law the useful count is
// rate × round-trip time: 50k RPS against a target 5ms away needs ~250 in
// flight, and the same 50k against one 100ms away needs ~5000. Past that point
// the extra workers are not in flight, they are queued behind the same
// connection, and they cost scheduling and memory to sit there.
//
// The table that used to be here recommended 3000-5000 workers for 50-150k RPS
// with no mention of distance, which is badly wrong for a near target. Measured
// against a local server, two sessions, 120k requests:
//
//	 256 workers   45.7k req/s    80.6 us cpu/req
//	1024 workers   40.5k req/s    94.4 us cpu/req
//	3000 workers   23.5k req/s   163.0 us cpu/req
//
// — half the throughput at double the CPU, following the advice. Start from
// rate × RTT and measure; there is no number here that is right for every
// target.
func newPipeline(c *Client, workers int) *Pipeline {
	return newPipelineWithConfig(c, PipelineConfig{Workers: workers})
}

func newPipelineWithConfig(c *Client, cfg PipelineConfig) *Pipeline {
	workers := cfg.Workers
	if workers <= 0 {
		workers = 1000
	}

	// Drain workers default to workers/4 (floor 64). Previously 1:1 with
	// workers, but most loadtests we profiled had drain workers idle in
	// select 80%+ of the time. workers/4 absorbs typical body sizes without
	// the extra goroutine stacks (~8KB each) and select wakeups.
	// Callers with large response bodies or slow peers should raise this
	// explicitly via PipelineConfig.DrainWorkers.
	drainWorkers := cfg.DrainWorkers
	if drainWorkers <= 0 {
		drainWorkers = workers / 4
	}
	if drainWorkers < 64 {
		drainWorkers = 64
	}

	jobMult := cfg.JobBufferMultiplier
	if jobMult <= 0 {
		jobMult = 16
	}
	drainMult := cfg.DrainBufferMultiplier
	if drainMult <= 0 {
		drainMult = 4
	}

	p := &Pipeline{
		client:  c,
		workers: workers,
		// Large buffer prevents sender blocking under burst load.
		jobCh:  make(chan *pipelineJob, workers*jobMult),
		stopCh: make(chan struct{}),
		// Drain channel absorbs response handoffs without truncating bodies.
		drainCh: make(chan *http.Response, workers*drainMult),
		jobPool: sync.Pool{
			New: func() interface{} { return &pipelineJob{} },
		},
		resultPool: sync.Pool{
			New: func() interface{} { return &PipelineResult{} },
		},
	}

	// Launch body drain pool - these read response bodies so workers don't block
	p.drainWg.Add(drainWorkers)
	for i := 0; i < drainWorkers; i++ {
		go p.drainWorker()
	}

	// Launch request worker pool
	p.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go p.worker()
	}

	return p
}

// SetTemplate sets a pre-built request template for FastDo path.
// When set, workers use FastDo (direct transport.RoundTrip) instead of DoWithContext,
// bypassing cookie jar mutex, redirect handling, URL parsing, and header building.
func (p *Pipeline) SetTemplate(tmpl *http.Request) {
	p.template.Store(tmpl)
}

// drainBufPool reuses 32KB buffers across drain workers so io.CopyBuffer does
// not allocate one per response. At 100k+ RPS the per-call allocations from
// io.Copy's default buffer dominate the GC profile.
var drainBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

// drainWorker reads and discards response bodies asynchronously.
// This keeps HTTP/2 streams clean (END_STREAM not RST_STREAM) without blocking request workers.
//
// Drain reads to EOF (unbounded) so the stream closes via END_STREAM. Truncating
// the read causes net/http2 to send RST_STREAM, which Cloudflare/Akamai score as
// an "abusive client" signal — defeats the purpose of fingerprint emulation.
// Drain workers run in their own pool, so unbounded reads here do not block
// request workers.
//
// Skips the io.Copy entirely when Content-Length is 0 (HEAD, 204, 304, empty
// POST acks) — those still need Body.Close() to release the H2 stream, but
// reading zero bytes is wasted syscalls.
func (p *Pipeline) drainWorker() {
	defer p.drainWg.Done()
	for resp := range p.drainCh {
		if resp == nil || resp.Body == nil {
			continue
		}
		if resp.ContentLength == 0 {
			resp.Body.Close()
			continue
		}
		bufPtr := drainBufPool.Get().(*[]byte)
		n, _ := io.CopyBuffer(io.Discard, resp.Body, *bufPtr)
		drainBufPool.Put(bufPtr)
		resp.Body.Close()
		p.Stats.TotalBytes.Add(n)
	}
}

// asyncDrain hands off a response body to the drain pool for async reading.
// The worker can immediately proceed to the next request.
//
// Backpressure policy: if the drain channel is full we BLOCK the caller rather
// than truncate. Truncation issues RST_STREAM (CANCEL) which Cloudflare/Akamai
// score as an abusive client and respond with 403. Stalling is the lesser evil
// — it naturally throttles ingress until drain catches up.
//
// The send happens under drainMu.RLock and selects on stopCh, so a shutdown
// both wakes a parked sender and cannot close drainCh underneath one. Once the
// channel is gone the body is drained inline instead, which is slower but keeps
// the stream ending in END_STREAM either way.
func (p *Pipeline) asyncDrain(resp *Response) {
	if resp == nil || resp.Response == nil || resp.Response.Body == nil || resp.bodyRead {
		return
	}

	p.drainMu.RLock()
	if !p.drainClosed {
		select {
		case p.drainCh <- resp.Response:
			p.drainMu.RUnlock()
			return
		case <-p.stopCh:
			// Shutting down: drain inline rather than park on a channel that
			// is about to be closed.
		}
	}
	p.drainMu.RUnlock()

	n, _ := io.Copy(io.Discard, resp.Response.Body)
	resp.Response.Body.Close()
	p.Stats.TotalBytes.Add(n)
}

// worker processes jobs from the channel.
//
// Workers select on stopCh so Close() can shut them down without closing
// jobCh — closing jobCh would race with Send/FireAndForget writers and panic.
func (p *Pipeline) worker() {
	defer p.wg.Done()

	for {
		var job *pipelineJob
		// Prioritize stopCh so Close() takes effect promptly even when jobCh
		// is full and Go's select would otherwise round-robin.
		select {
		case <-p.stopCh:
			return
		default:
		}
		select {
		case <-p.stopCh:
			return
		case job = <-p.jobCh:
		}

		start := time.Now()
		p.Stats.TotalSent.Add(1)

		var resp *Response
		var err error
		if tmpl := p.template.Load(); tmpl != nil {
			resp, err = p.client.FastDo(job.ctx, tmpl)
		} else {
			resp, err = p.client.DoWithContext(job.ctx, job.method, job.url, job.body, job.headers)
		}

		latency := time.Since(start)

		if err != nil {
			p.Stats.TotalErr.Add(1)
		} else {
			p.Stats.TotalOK.Add(1)
		}

		if job.result != nil {
			result := p.resultPool.Get().(*PipelineResult)
			result.Response = resp
			result.Err = err
			result.Latency = latency

			delivered := false
			if job.blockResult {
				select {
				case job.result <- result:
					delivered = true
				case <-p.stopCh:
				case <-job.ctx.Done():
				}
			} else {
				select {
				case job.result <- result:
					delivered = true
				default:
				}
			}
			if !delivered {
				if resp != nil {
					p.asyncDrain(resp)
				}
				result.Response = nil
				result.Err = nil
				p.resultPool.Put(result)
			}
		} else if p.OnResult != nil {
			// Fire and forget with callback - drain body async
			p.OnResult(resp, err, latency)
			if resp != nil {
				p.asyncDrain(resp)
			}
		} else {
			// No result channel, no callback - drain async
			if resp != nil {
				p.asyncDrain(resp)
			}
		}

		// Return job to pool
		job.ctx = nil
		job.method = ""
		job.url = ""
		job.body = nil
		job.headers = nil
		job.result = nil
		job.blockResult = false
		p.jobPool.Put(job)
	}
}

// Send submits a request to the pipeline and returns a channel for the result.
// Respects context cancellation to avoid blocking when the pipeline is full.
func (p *Pipeline) Send(ctx context.Context, method, url string, body []byte, headers map[string]string) <-chan *PipelineResult {
	ch := make(chan *PipelineResult, 1)

	p.inFlight.Add(1)
	defer p.inFlight.Add(-1)

	if p.closed.Load() {
		ch <- &PipelineResult{Err: ErrPipelineClosed}
		return ch
	}

	job := p.jobPool.Get().(*pipelineJob)
	job.ctx = ctx
	job.method = method
	job.url = url
	job.body = body
	job.headers = headers
	job.result = ch

	select {
	case p.jobCh <- job:
	case <-ctx.Done():
		ch <- &PipelineResult{Err: ctx.Err()}
		p.jobPool.Put(job)
	case <-p.stopCh:
		ch <- &PipelineResult{Err: ErrPipelineClosed}
		p.jobPool.Put(job)
	}

	return ch
}

// FireAndForget submits a request without waiting for the result.
// Responses are automatically drained and closed.
// This is the fastest mode for maximum RPS.
func (p *Pipeline) FireAndForget(ctx context.Context, method, url string, body []byte, headers map[string]string) {
	p.inFlight.Add(1)
	defer p.inFlight.Add(-1)

	if p.closed.Load() {
		return
	}

	job := p.jobPool.Get().(*pipelineJob)
	job.ctx = ctx
	job.method = method
	job.url = url
	job.body = body
	job.headers = headers
	job.result = nil

	select {
	case p.jobCh <- job:
	case <-ctx.Done():
		p.jobPool.Put(job)
	case <-p.stopCh:
		p.jobPool.Put(job)
	}
}

// Spray sends n requests as fast as possible and returns aggregate results.
//
// Requests are submitted from a background goroutine and results are collected
// as they arrive, over a single bounded channel. The previous form allocated
// one result channel per request plus an n-entry slice before collecting
// anything, so the Spray(ctx, ..., 100000) from the README paid 100k channel
// allocations up front and a million-request run paid a million — all live at
// once. Memory now scales with the worker count, not with n.
//
// Response bodies are handed to the pipeline's drain pool rather than closed
// inline, so a slow body cannot stall the accounting loop.
func (p *Pipeline) Spray(ctx context.Context, method, url string, n int) *SprayResult {
	sr := &SprayResult{
		Total:      n,
		StartTime:  time.Now(),
		MinLatency: time.Duration(1<<63 - 1),
	}
	if n <= 0 {
		sr.EndTime = time.Now()
		sr.Total = 0
		sr.MinLatency = 0
		return sr
	}

	bufSize := p.workers * 2
	if bufSize > n {
		bufSize = n
	}
	if bufSize < 1 {
		bufSize = 1
	}
	results := make(chan *PipelineResult, bufSize)
	countCh := make(chan int, 1)

	go p.spraySubmit(ctx, method, url, n, results, countCh)

	var (
		received                     int
		submitted                    = -1
		okCount, errCount            int
		totalLatency, minLat, maxLat time.Duration
		observed                     bool
	)

	collect := func(result *PipelineResult) {
		received++
		if result.Err != nil {
			errCount++
		} else {
			okCount++
			if result.Response != nil {
				p.asyncDrain(result.Response)
			}
		}
		lat := result.Latency
		totalLatency += lat
		if !observed || lat < minLat {
			minLat = lat
		}
		if !observed || lat > maxLat {
			maxLat = lat
		}
		observed = true

		result.Response = nil
		result.Err = nil
		p.resultPool.Put(result)
	}

loop:
	for submitted < 0 || received < submitted {
		select {
		case c := <-countCh:
			submitted = c
			sr.Total = c
			countCh = nil // a nil channel blocks forever, so stop selecting it
		case result := <-results:
			collect(result)
		case <-ctx.Done():
			// A worker abandons its blockResult send once job.ctx is done (see
			// worker), draining the body itself instead. Those results never
			// reach us, so `received` can never catch up to `submitted` and
			// waiting on it here hung Spray forever on any cancelled or
			// timed-out context. Report what completed instead.
			break loop
		case <-p.stopCh:
			// Pipeline shut down mid-run; report what completed.
			break loop
		}
	}

	// Anything already buffered still owns a response body.
	for {
		select {
		case result := <-results:
			collect(result)
		default:
			goto done
		}
	}

done:
	// An early exit can leave the submitted count unread. Take it if it has
	// landed so Total reports what was actually queued rather than the n that
	// was asked for.
	if countCh != nil {
		select {
		case c := <-countCh:
			sr.Total = c
		default:
		}
	}

	sr.EndTime = time.Now()
	sr.Success = okCount
	sr.Failed = errCount
	sr.Duration = sr.EndTime.Sub(sr.StartTime)
	if sr.Duration.Seconds() > 0 {
		sr.RPS = float64(sr.Success) / sr.Duration.Seconds()
	}
	if total := okCount + errCount; total > 0 {
		sr.AvgLatency = totalLatency / time.Duration(total)
		sr.MinLatency = minLat
		sr.MaxLatency = maxLat
	} else {
		sr.MinLatency = 0
	}

	return sr
}

// spraySubmit queues n jobs that all report into results, then publishes how
// many were actually submitted so the collector knows when it is done.
func (p *Pipeline) spraySubmit(ctx context.Context, method, url string, n int, results chan<- *PipelineResult, countCh chan<- int) {
	p.inFlight.Add(1)
	defer p.inFlight.Add(-1)

	submitted := 0
	defer func() { countCh <- submitted }()

	for i := 0; i < n; i++ {
		if p.closed.Load() {
			return
		}
		job := p.jobPool.Get().(*pipelineJob)
		job.ctx = ctx
		job.method = method
		job.url = url
		job.body = nil
		job.headers = nil
		job.result = results
		job.blockResult = true

		select {
		case p.jobCh <- job:
			submitted++
		case <-ctx.Done():
			p.jobPool.Put(job)
			return
		case <-p.stopCh:
			p.jobPool.Put(job)
			return
		}
	}
}

// SprayResult holds the results of a Spray operation.
type SprayResult struct {
	Total      int
	Success    int
	Failed     int
	Duration   time.Duration
	RPS        float64
	StartTime  time.Time
	EndTime    time.Time
	AvgLatency time.Duration
	MinLatency time.Duration
	MaxLatency time.Duration
}

// Close shuts down the pipeline and waits for all workers to finish.
//
// We close stopCh and let workers exit via select; jobCh is NOT closed
// because a concurrent Send/FireAndForget that just passed the closed check
// could still race a close(jobCh) and panic ("send on closed channel").
//
// Jobs still queued in jobCh are answered with ErrPipelineClosed rather than
// discarded. Dropping them silently was safe only for FireAndForget: a Send
// caller is blocked on its result channel, and with the job thrown away
// nothing ever writes to it, so the caller waited forever.
func (p *Pipeline) Close() {
	if p.closed.CompareAndSwap(false, true) {
		close(p.stopCh)
		p.wg.Wait()

		// Wait out submitters that passed the closed check before it flipped;
		// each is blocked in a select whose stopCh case is now ready, so this
		// settles immediately.
		for p.inFlight.Load() > 0 {
			runtime.Gosched()
		}
		p.failQueuedJobs()

		// Close the drain pool under the write lock. Workers are done, but
		// Spray's collector calls asyncDrain from the caller's goroutine and is
		// covered by neither wg nor inFlight, so the lock is what guarantees no
		// send is in progress. Any sender parked in the select above has
		// already woken on stopCh, so this acquires immediately.
		p.drainMu.Lock()
		p.drainClosed = true
		close(p.drainCh)
		p.drainMu.Unlock()

		p.drainWg.Wait()
	}
}

// failQueuedJobs answers every job left in jobCh with ErrPipelineClosed. It
// must run only after all workers have exited and no submitter is in flight,
// so nothing can be added behind it.
func (p *Pipeline) failQueuedJobs() {
	for {
		select {
		case job := <-p.jobCh:
			if job.result != nil {
				select {
				case job.result <- &PipelineResult{Err: ErrPipelineClosed}:
				default:
					// Send gives each job an empty single-slot channel, so
					// this always lands for the caller that is waiting. The
					// fallback covers Spray's shared channel, whose collector
					// has its own shutdown path and is not waiting on us.
				}
			}
			job.ctx = nil
			job.body = nil
			job.headers = nil
			job.result = nil
			job.blockResult = false
			p.jobPool.Put(job)
		default:
			return
		}
	}
}

// ErrPipelineClosed is returned when sending to a closed pipeline.
var ErrPipelineClosed = fmt.Errorf("pipeline is closed")
