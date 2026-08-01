package gofire

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestPipelineCloseAnswersQueuedSends covers a shutdown hang.
//
// Close discarded whatever was still buffered in jobCh. That is harmless for
// FireAndForget, but a Send caller is parked on its result channel and nothing
// else ever writes to it, so every queued Send blocked forever.
func TestPipelineCloseAnswersQueuedSends(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	p := client.NewPipeline(2)

	// Stay inside jobCh's capacity (workers*16) so every Send lands in the
	// queue instead of blocking: two run, the rest sit there for Close to deal
	// with, which is the situation under test.
	const total = 20
	chans := make([]<-chan *PipelineResult, 0, total)
	for i := 0; i < total; i++ {
		chans = append(chans, p.Send(context.Background(), "GET", server.URL, nil, nil))
	}

	closed := make(chan struct{})
	go func() {
		p.Close()
		close(closed)
	}()

	// Let the in-flight requests finish so workers can observe stopCh.
	close(release)

	select {
	case <-closed:
	case <-time.After(20 * time.Second):
		t.Fatal("Close did not return")
	}

	// Every caller must be answered, whether the request ran or was dropped.
	for i, ch := range chans {
		select {
		case result := <-ch:
			if result == nil {
				t.Fatalf("request %d: nil result", i)
			}
			if result.Response != nil {
				result.Response.Close()
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d: Send caller never woke up after Close", i)
		}
	}
}

// TestSprayHandlesMoreRequestsThanWorkers exercises the streaming collector.
// The previous implementation allocated one result channel per request and an
// n-entry slice before collecting anything, so its memory scaled with n rather
// than with the worker count.
func TestSprayHandlesMoreRequestsThanWorkers(t *testing.T) {
	var served atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.Write([]byte("hello")) //nolint:errcheck
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	p := client.NewPipeline(8)
	defer p.Close()

	const n = 2000
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sr := p.Spray(ctx, "GET", server.URL, n)

	if sr.Total != n {
		t.Errorf("Total = %d, want %d", sr.Total, n)
	}
	if sr.Success+sr.Failed != n {
		t.Errorf("Success+Failed = %d, want %d (Success=%d Failed=%d)",
			sr.Success+sr.Failed, n, sr.Success, sr.Failed)
	}
	if sr.Failed != 0 {
		t.Errorf("Failed = %d, want 0", sr.Failed)
	}
	if got := served.Load(); got != n {
		t.Errorf("server saw %d requests, want %d", got, n)
	}
	if sr.MinLatency <= 0 || sr.MaxLatency < sr.MinLatency {
		t.Errorf("latency stats look wrong: min=%v max=%v", sr.MinLatency, sr.MaxLatency)
	}
}

// TestSprayZero pins the degenerate input.
func TestSprayZero(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	p := client.NewPipeline(2)
	defer p.Close()

	sr := p.Spray(context.Background(), "GET", "http://127.0.0.1:1/", 0)
	if sr.Total != 0 || sr.Success != 0 || sr.Failed != 0 {
		t.Fatalf("Spray(0) = %+v, want all zero", sr)
	}
}

// TestRetryDelay pins the backoff shape.
//
// The old form, base * (1 << (attempt-1)), overflowed int64 once attempt got
// large and wrapped negative. time.After of a negative duration fires
// immediately, so the backoff turned into a hot retry loop exactly when the
// server was least able to absorb one.
func TestRetryDelay(t *testing.T) {
	base := 100 * time.Millisecond

	for attempt := 1; attempt < 200; attempt++ {
		d := retryDelay(base, attempt)
		if d <= 0 {
			t.Fatalf("attempt %d: delay %v is not positive", attempt, d)
		}
		if d > maxRetryDelay {
			t.Fatalf("attempt %d: delay %v exceeds the %v cap", attempt, d, maxRetryDelay)
		}
	}

	// Full jitter: repeated draws for one attempt must not all be identical,
	// or a fleet that failed together retries together.
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		seen[retryDelay(base, 4)] = true
	}
	if len(seen) < 2 {
		t.Error("retryDelay has no jitter; simultaneous failures would stampede")
	}

	if got := retryDelay(0, 3); got != 0 {
		t.Errorf("retryDelay with zero base = %v, want 0", got)
	}
}

func TestIsIdempotent(t *testing.T) {
	yes := []string{"", "GET", "get", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"}
	no := []string{"POST", "post", "PATCH", "CONNECT"}

	for _, m := range yes {
		if !isIdempotent(m) {
			t.Errorf("isIdempotent(%q) = false, want true", m)
		}
	}
	for _, m := range no {
		if isIdempotent(m) {
			t.Errorf("isIdempotent(%q) = true, want false", m)
		}
	}
}

// TestRetrySkipsNonIdempotentOnNetworkError pins that a POST is not replayed
// after a transport error. The server may have processed the request before the
// connection broke, so a retry can duplicate an order or a payment.
func TestRetrySkipsNonIdempotentOnNetworkError(t *testing.T) {
	var attempts atomic.Int64
	// A server that accepts the connection and closes it without replying
	// produces a transport error on every attempt.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}))
	defer server.Close()

	client, err := NewClient(WithRetry(3, 10*time.Millisecond, 503))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	attempts.Store(0)
	if _, err := client.DoWithContext(ctx, "POST", server.URL, []byte(`{}`),
		map[string]string{"Content-Type": "application/json"}); err == nil {
		t.Fatal("expected a transport error")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("POST was sent %d times; a non-idempotent request must not be replayed", got)
	}

	attempts.Store(0)
	if _, err := client.GetWithContext(ctx, server.URL); err == nil {
		t.Fatal("expected a transport error")
	}
	if got := attempts.Load(); got < 2 {
		t.Errorf("GET was sent %d times; an idempotent request should be retried", got)
	}
}

// TestFloodRespectsContextCancellation pins that a cancelled context stops the
// submit loop. Acquiring the concurrency slot used to be an uncancellable send,
// so the loop kept going until in-flight requests released slots.
func TestFloodRespectsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	done := make(chan struct{})
	var responses []*Response
	var errs []error
	go func() {
		responses, errs = client.Flood(ctx, "GET", server.URL, 500, 4)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Flood ignored the cancelled context")
	}

	for _, r := range responses {
		if r != nil {
			r.Close()
		}
	}
	if len(errs) != 500 {
		t.Fatalf("got %d error slots, want 500", len(errs))
	}
	var cancelled int
	for _, err := range errs {
		if errors.Is(err, context.Canceled) {
			cancelled++
		}
	}
	if cancelled == 0 {
		t.Error("no slot reports context.Canceled")
	}
}

// TestPipelineStatsTotalBytes pins that the counter is actually maintained. It
// was part of the public API while nothing ever wrote to it.
func TestPipelineStatsTotalBytes(t *testing.T) {
	const body = "0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body)) //nolint:errcheck
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	p := client.NewPipeline(4)

	const n = 20
	var completed atomic.Int64
	done := make(chan struct{})
	p.OnResult = func(resp *Response, err error, latency time.Duration) {
		if completed.Add(1) == n {
			close(done)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := 0; i < n; i++ {
		p.FireAndForget(ctx, "GET", server.URL, nil, nil)
	}

	// Close abandons whatever is still queued, so let every request finish
	// before shutting down — otherwise nothing is ever drained.
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("only %d of %d requests completed", completed.Load(), n)
	}
	p.Close() // waits for workers and the drain pool

	if got := p.Stats.TotalBytes.Load(); got == 0 {
		t.Fatal("TotalBytes stayed at zero")
	} else if got > int64(n*len(body)) {
		t.Fatalf("TotalBytes = %d, more than the %d bytes served", got, n*len(body))
	}
}

// TestErrPipelineClosedMessage guards the sentinel used above.
func TestErrPipelineClosedMessage(t *testing.T) {
	if !strings.Contains(ErrPipelineClosed.Error(), "closed") {
		t.Fatalf("unexpected sentinel text: %v", ErrPipelineClosed)
	}
}
