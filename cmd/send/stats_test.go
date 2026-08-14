package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// record() runs on every request of every worker, so the one field it reads
// without the lock has to be safe to read that way.
//
// It was not. stride was a plain int64: read on line one of record() to decide
// whether the lock is worth taking, and written under the lock when the latency
// sample fills and has to be halved. A data race on the hot path of every load
// run — and `go test -race` in CI never saw it, because nothing drove record()
// concurrently past the two million samples it takes to trigger the write.
//
// The sample is pre-filled to just under the threshold so the widening happens
// immediately rather than after 2M calls; the race window is the same one, and
// this finishes in milliseconds instead of a quarter of a minute.
func TestStatsRecordIsSafeWhenTheSampleWidens(t *testing.T) {
	st := newStats(0)
	st.latencies = make([]time.Duration, maxLatencySamples-1)

	var index atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				st.record(index.Add(1)-1, time.Millisecond, 200, nil)
			}
		}()
	}
	wg.Wait()

	if got := st.sent.Load(); got != 8*2000 {
		t.Errorf("sent = %d, want %d", got, 8*2000)
	}
	// The widening happened, and happened once per halving rather than once per
	// goroutine that noticed the sample was full.
	if stride := st.stride.Load(); stride != 2 {
		t.Errorf("stride = %d after one halving, want 2", stride)
	}
	if n := len(st.latencies); n >= maxLatencySamples {
		t.Errorf("the sample was not halved: %d entries", n)
	}
}

// The stride is what keeps a very long run from turning percentile collection
// into its memory ceiling, and it must never be zero — index%0 panics.
func TestStatsStrideIsSizedFromTheExpectedCount(t *testing.T) {
	if got := newStats(0).stride.Load(); got != 1 {
		t.Errorf("a duration run starts at stride %d, want 1", got)
	}
	if got := newStats(1000).stride.Load(); got != 1 {
		t.Errorf("a short count run starts at stride %d, want 1", got)
	}
	if got := newStats(maxLatencySamples * 4).stride.Load(); got != 4 {
		t.Errorf("a 4x-oversized run starts at stride %d, want 4", got)
	}
}
