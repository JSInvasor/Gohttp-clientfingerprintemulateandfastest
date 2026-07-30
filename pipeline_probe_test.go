package gofire

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestSendResolvesAfterClose covers the contract Send makes with its caller.
//
// Send hands back a channel and the caller blocks on it. Close() stops workers
// via stopCh without draining jobCh, so a job already queued when Close lands is
// dropped and nothing is ever written to its channel. The caller does not get an
// error — it waits forever. Spray is worse: it blocks on every channel it
// created, so one dropped job hangs the whole call.
func TestSendResolvesAfterClose(t *testing.T) {
	// A handler slow enough that the single worker is still busy while the rest
	// of the jobs pile up in jobCh.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c, err := NewClient()
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	p := c.NewPipeline(1)

	chans := make([]<-chan *PipelineResult, 0, 5)
	for i := 0; i < 5; i++ {
		chans = append(chans, p.Send(context.Background(), "GET", srv.URL, nil, nil))
	}

	// Let the worker pick up the first job so the rest are queued behind it.
	time.Sleep(50 * time.Millisecond)
	p.Close()

	for i, ch := range chans {
		select {
		case res := <-ch:
			if res == nil {
				t.Errorf("job %d: nil result", i)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("job %d never resolved after Close(): the caller is blocked "+
				"forever on a channel nothing will ever write to", i)
		}
	}
}

// TestSprayResolvesAfterClose is the same defect reached through Spray, which
// is where a caller is most likely to meet it: Spray blocks on every channel it
// created, so a single dropped job hangs the call and its goroutines.
func TestSprayResolvesAfterClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c, err := NewClient()
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	p := c.NewPipeline(1)

	done := make(chan *SprayResult, 1)
	go func() { done <- p.Spray(context.Background(), "GET", srv.URL, 8) }()

	time.Sleep(50 * time.Millisecond)
	p.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Spray never returned after Close(): it is blocked on result " +
			"channels for jobs that were dropped from the queue")
	}
}
