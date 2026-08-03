package gofire

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// blockedBody parks a drain worker on Read until the test releases it.
type blockedBody struct{ release chan struct{} }

func (b *blockedBody) Read(p []byte) (int, error) {
	<-b.release
	return 0, io.EOF
}
func (b *blockedBody) Close() error { return nil }

func blockedResponse(release chan struct{}) *Response {
	return &Response{Response: &http.Response{
		StatusCode: 200,
		// -1 keeps drainWorker off its "Content-Length is 0, skip the copy"
		// shortcut so the worker really does park in io.CopyBuffer.
		ContentLength: -1,
		Body:          &blockedBody{release: release},
		Header:        http.Header{},
	}}
}

// TestPipelineCloseWithParkedDrainSender covers a panic.
//
// Spray runs collect -> asyncDrain on the CALLER's goroutine. Close waits for
// p.wg (workers) and p.inFlight (submitters), neither of which covers that
// goroutine, so a collector parked on a full drainCh was still sending when
// Close closed the channel: "panic: send on closed channel".
func TestPipelineCloseWithParkedDrainSender(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	p := client.NewPipeline(4)

	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()

	// Saturate the pool: 64 drain workers (the floor) each park on a body,
	// then fill the workers*4 buffer behind them.
	for i := 0; i < 64+16; i++ {
		p.asyncDrain(blockedResponse(release))
	}
	time.Sleep(300 * time.Millisecond) // let every drain worker claim one

	panicked := make(chan any, 1)
	returned := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked <- r
			}
			close(returned)
		}()
		p.asyncDrain(blockedResponse(release)) // parks on the full drainCh
	}()

	time.Sleep(300 * time.Millisecond) // ensure it is parked in the send

	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()

	// Close has signalled stopCh by the time it reaches the drain shutdown, so
	// the parked sender has already woken and fallen back to draining inline.
	// Let the bodies finish so that drain — and the 64 parked workers behind
	// it — can actually complete.
	time.Sleep(300 * time.Millisecond)
	releaseOnce()

	select {
	case r := <-panicked:
		t.Fatalf("asyncDrain panicked during Close: %v", r)
	case <-returned:
	case <-time.After(15 * time.Second):
		t.Fatal("asyncDrain never returned after Close")
	}

	select {
	case <-closed:
	case <-time.After(15 * time.Second):
		t.Fatal("Close deadlocked against the parked drain sender")
	}
}

// TestSprayReturnsOnContextCancel covers a hang.
//
// A worker abandons its blockResult send once job.ctx is done, so those results
// never reach the collector. The collector's select watched only countCh,
// results and stopCh, so `received < submitted` stayed true forever and Spray
// never returned on a cancelled or timed-out context.
func TestSprayReturnsOnContextCancel(t *testing.T) {
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

	p := client.NewPipeline(8)
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *SprayResult, 1)
	go func() { done <- p.Spray(ctx, "GET", server.URL, 2000) }()

	time.Sleep(300 * time.Millisecond) // let requests get in flight
	cancel()

	select {
	case sr := <-done:
		if sr == nil {
			t.Fatal("nil SprayResult")
		}
		if sr.Success+sr.Failed > sr.Total {
			t.Fatalf("counted %d results for %d submitted", sr.Success+sr.Failed, sr.Total)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Spray never returned after context cancellation")
	}
}

// TestSprayCompletesNormally guards the fix above against the opposite error:
// bailing out early when the context is perfectly healthy.
func TestSprayCompletesNormally(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer server.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	p := client.NewPipeline(8)
	defer p.Close()

	const n = 200
	sr := p.Spray(context.Background(), "GET", server.URL, n)
	if sr.Total != n {
		t.Fatalf("Total = %d, want %d", sr.Total, n)
	}
	if sr.Success+sr.Failed != n {
		t.Fatalf("accounted %d results, want %d (success=%d failed=%d)",
			sr.Success+sr.Failed, n, sr.Success, sr.Failed)
	}
	if sr.Success != n {
		t.Fatalf("Success = %d, want %d", sr.Success, n)
	}
}
