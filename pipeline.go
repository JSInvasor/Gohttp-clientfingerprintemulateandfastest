package gofire

import (
	"context"
	"fmt"
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
type Pipeline struct {
	client  *Client
	workers int
	wg      sync.WaitGroup
	jobCh   chan *pipelineJob
	Stats   PipelineStats
	closed  atomic.Bool
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
// For max RPS, set workers to 2000-5000 depending on your system.
func newPipeline(c *Client, workers int) *Pipeline {
	if workers <= 0 {
		workers = 1000
	}

	p := &Pipeline{
		client:  c,
		workers: workers,
		jobCh:   make(chan *pipelineJob, workers*2),
	}

	// Launch worker pool
	p.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go p.worker()
	}

	return p
}

// worker processes jobs from the channel.
func (p *Pipeline) worker() {
	defer p.wg.Done()

	for job := range p.jobCh {
		start := time.Now()
		p.Stats.TotalSent.Add(1)

		resp, err := p.client.DoWithContext(job.ctx, job.method, job.url, job.body, job.headers)

		result := &PipelineResult{
			Response: resp,
			Err:      err,
			Latency:  time.Since(start),
		}

		if err != nil {
			p.Stats.TotalErr.Add(1)
		} else {
			p.Stats.TotalOK.Add(1)
		}

		if job.result != nil {
			select {
			case job.result <- result:
			default:
				// Result channel full, discard to avoid blocking
				if resp != nil {
					resp.Close()
				}
			}
		} else {
			// No result channel - fire and forget, close response
			if resp != nil {
				resp.Close()
			}
		}
	}
}

// Send submits a request to the pipeline and returns a channel for the result.
func (p *Pipeline) Send(ctx context.Context, method, url string, body []byte, headers map[string]string) <-chan *PipelineResult {
	ch := make(chan *PipelineResult, 1)

	if p.closed.Load() {
		ch <- &PipelineResult{Err: ErrPipelineClosed}
		return ch
	}

	p.jobCh <- &pipelineJob{
		ctx:     ctx,
		method:  method,
		url:     url,
		body:    body,
		headers: headers,
		result:  ch,
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

	p.jobCh <- &pipelineJob{
		ctx:     ctx,
		method:  method,
		url:     url,
		body:    body,
		headers: headers,
		result:  nil, // no result channel
	}
}

// Spray sends n requests as fast as possible and returns aggregate results.
// This is designed for maximum throughput testing.
func (p *Pipeline) Spray(ctx context.Context, method, url string, n int) *SprayResult {
	sr := &SprayResult{
		Total:     n,
		StartTime: time.Now(),
	}

	var wg sync.WaitGroup
	var okCount, errCount atomic.Int64

	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			sr.Total = i
			goto done
		default:
		}

		wg.Add(1)
		ch := p.Send(ctx, method, url, nil, nil)

		go func() {
			defer wg.Done()
			result := <-ch
			if result.Err != nil {
				errCount.Add(1)
			} else {
				okCount.Add(1)
				if result.Response != nil {
					result.Response.Close()
				}
			}
		}()
	}

done:
	wg.Wait()
	sr.EndTime = time.Now()
	sr.Success = int(okCount.Load())
	sr.Failed = int(errCount.Load())
	sr.Duration = sr.EndTime.Sub(sr.StartTime)
	if sr.Duration.Seconds() > 0 {
		sr.RPS = float64(sr.Success) / sr.Duration.Seconds()
	}

	return sr
}

// SprayResult holds the results of a Spray operation.
type SprayResult struct {
	Total     int
	Success   int
	Failed    int
	Duration  time.Duration
	RPS       float64
	StartTime time.Time
	EndTime   time.Time
}

// Close shuts down the pipeline and waits for all workers to finish.
func (p *Pipeline) Close() {
	if p.closed.CompareAndSwap(false, true) {
		close(p.jobCh)
		p.wg.Wait()
	}
}

// ErrPipelineClosed is returned when sending to a closed pipeline.
var ErrPipelineClosed = fmt.Errorf("pipeline is closed")
