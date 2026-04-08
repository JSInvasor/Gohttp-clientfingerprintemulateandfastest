package gofire

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	TotalSent   atomic.Int64
	TotalOK     atomic.Int64
	TotalErr    atomic.Int64
	TotalBytes  atomic.Int64
}

// Pipeline provides maximum throughput request sending with a fixed worker pool.
// Workers are pre-allocated and reuse connections for minimal overhead.
//
// For 100k+ RPS, use 3000-5000 workers with FireAndForget mode.
type Pipeline struct {
	client  *Client
	workers int
	wg      sync.WaitGroup
	jobCh   chan *pipelineJob
	Stats   PipelineStats
	closed  atomic.Bool

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
}

// newPipeline creates a new Pipeline with the specified number of workers.
// Workers run continuously, pulling jobs from a shared channel.
//
// Recommended workers by target RPS:
//
//	1000-2000  → 10-50k RPS
//	3000-5000  → 50-150k RPS
//	5000-10000 → 150k+ RPS
func newPipeline(c *Client, workers int) *Pipeline {
	if workers <= 0 {
		workers = 1000
	}

	// Drain workers handle body reading asynchronously so request workers
	// aren't blocked by slow response body transfers.
	drainWorkers := workers / 2
	if drainWorkers < 64 {
		drainWorkers = 64
	}

	p := &Pipeline{
		client:  c,
		workers: workers,
		// Large buffer prevents sender blocking under burst load.
		jobCh: make(chan *pipelineJob, workers*16),
		// Drain channel: buffered to absorb bursts of completed responses
		drainCh: make(chan *http.Response, drainWorkers*4),
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

// drainWorker reads and discards response bodies asynchronously.
// This keeps HTTP/2 streams clean (END_STREAM not RST_STREAM) without blocking request workers.
func (p *Pipeline) drainWorker() {
	defer p.drainWg.Done()
	for resp := range p.drainCh {
		if resp != nil && resp.Body != nil {
			io.CopyN(io.Discard, resp.Body, 64*1024) //nolint:errcheck
			resp.Body.Close()
		}
	}
}

// asyncDrain hands off a response body to the drain pool for async reading.
// The worker can immediately proceed to the next request.
func (p *Pipeline) asyncDrain(resp *Response) {
	if resp == nil || resp.Response == nil || resp.Response.Body == nil || resp.bodyRead {
		return
	}
	select {
	case p.drainCh <- resp.Response:
		// Handed off to drain worker
	default:
		// Drain channel full - drain inline to avoid dropping
		io.CopyN(io.Discard, resp.Response.Body, 64*1024) //nolint:errcheck
		resp.Response.Body.Close()
	}
}

// worker processes jobs from the channel.
func (p *Pipeline) worker() {
	defer p.wg.Done()

	for job := range p.jobCh {
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

			select {
			case job.result <- result:
			default:
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
		p.jobPool.Put(job)
	}
}

// Send submits a request to the pipeline and returns a channel for the result.
// Respects context cancellation to avoid blocking when the pipeline is full.
func (p *Pipeline) Send(ctx context.Context, method, url string, body []byte, headers map[string]string) <-chan *PipelineResult {
	ch := make(chan *PipelineResult, 1)

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
	}

	return ch
}

// FireAndForget submits a request without waiting for the result.
// Responses are automatically drained and closed.
// This is the fastest mode for maximum RPS.
func (p *Pipeline) FireAndForget(ctx context.Context, method, url string, body []byte, headers map[string]string) {
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
	}
}

// Spray sends n requests as fast as possible and returns aggregate results.
// Uses a fixed collector pool instead of spawning n goroutines to avoid
// GC pressure at high request counts.
func (p *Pipeline) Spray(ctx context.Context, method, url string, n int) *SprayResult {
	sr := &SprayResult{
		Total:      n,
		StartTime:  time.Now(),
		MinLatency: time.Duration(1<<63 - 1),
	}

	var okCount, errCount atomic.Int64
	var totalLatencyNs atomic.Int64
	var minLatencyNs, maxLatencyNs atomic.Int64
	minLatencyNs.Store(int64(sr.MinLatency))

	// Use a bounded collector pool instead of n goroutines.
	// collectors = min(n, workers) ensures we don't create more collectors than needed.
	collectors := p.workers
	if collectors > n {
		collectors = n
	}

	// Result channels fed by pipeline workers, consumed by collectors
	resultChs := make([]<-chan *PipelineResult, 0, n)

	// Submit all jobs
	submitted := 0
	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			sr.Total = i
			goto collect
		default:
		}
		resultChs = append(resultChs, p.Send(ctx, method, url, nil, nil))
		submitted++
	}

collect:
	// Collect results using a fixed pool of collector goroutines
	var wg sync.WaitGroup
	chunkSize := (submitted + collectors - 1) / collectors
	if chunkSize < 1 {
		chunkSize = 1
	}

	for start := 0; start < submitted; start += chunkSize {
		end := start + chunkSize
		if end > submitted {
			end = submitted
		}
		chunk := resultChs[start:end]

		wg.Add(1)
		go func(channels []<-chan *PipelineResult) {
			defer wg.Done()
			for _, ch := range channels {
				result := <-ch
				if result.Err != nil {
					errCount.Add(1)
				} else {
					okCount.Add(1)
					if result.Response != nil {
						result.Response.Close()
					}
				}

				latNs := int64(result.Latency)
				totalLatencyNs.Add(latNs)

				// Update min latency (CAS loop)
				for {
					cur := minLatencyNs.Load()
					if latNs >= cur || minLatencyNs.CompareAndSwap(cur, latNs) {
						break
					}
				}
				// Update max latency (CAS loop)
				for {
					cur := maxLatencyNs.Load()
					if latNs <= cur || maxLatencyNs.CompareAndSwap(cur, latNs) {
						break
					}
				}

				// Return result to pool
				result.Response = nil
				result.Err = nil
				p.resultPool.Put(result)
			}
		}(chunk)
	}

	wg.Wait()
	sr.EndTime = time.Now()
	sr.Success = int(okCount.Load())
	sr.Failed = int(errCount.Load())
	sr.Duration = sr.EndTime.Sub(sr.StartTime)
	if sr.Duration.Seconds() > 0 {
		sr.RPS = float64(sr.Success) / sr.Duration.Seconds()
	}
	total := sr.Success + sr.Failed
	if total > 0 {
		sr.AvgLatency = time.Duration(totalLatencyNs.Load() / int64(total))
		sr.MinLatency = time.Duration(minLatencyNs.Load())
		sr.MaxLatency = time.Duration(maxLatencyNs.Load())
	} else {
		sr.MinLatency = 0
	}

	return sr
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
func (p *Pipeline) Close() {
	if p.closed.CompareAndSwap(false, true) {
		close(p.jobCh)
		p.wg.Wait()
		// Close drain pool after all workers are done
		close(p.drainCh)
		p.drainWg.Wait()
	}
}

// ErrPipelineClosed is returned when sending to a closed pipeline.
var ErrPipelineClosed = fmt.Errorf("pipeline is closed")
