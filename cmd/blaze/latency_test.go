package main

import (
	"testing"
	"time"
)

// The percentile of a small sample has to name the bucket the sample is in.
//
// It truncated total*p instead of rounding up, so anything below one sample gave
// a target of 0 — and `seen >= 0` is true on the first pass whether or not
// bucket 0 holds anything. Every percentile came back as bucket 0's 1.5ms
// regardless of where the samples were. Large counts hide it, which is why a
// live stats line refreshing every second did; the first tick of every run does
// not.
func TestLatencyPercentileOfASmallSample(t *testing.T) {
	var lt latencyTracker
	lt.record(1200 * time.Millisecond) // bucket 10: 1024..2048ms

	// 1.5 * 1024ms = 1536ms.
	want := 1536 * time.Millisecond
	for _, p := range []float64{0.50, 0.99} {
		if got := lt.percentile(p); got != want {
			t.Errorf("p%.0f of one 1.2s sample = %s, want %s", p*100, got, want)
		}
	}
}

// Nearest rank: of three samples the median is the second, not the first.
func TestLatencyPercentileUsesNearestRank(t *testing.T) {
	var lt latencyTracker
	lt.record(1 * time.Millisecond)   // bucket 0
	lt.record(64 * time.Millisecond)  // bucket 6
	lt.record(512 * time.Millisecond) // bucket 9

	if got, want := lt.percentile(0.50), 96*time.Millisecond; got != want {
		t.Errorf("p50 = %s, want %s (the middle sample's bucket)", got, want)
	}
	if got, want := lt.percentile(0.99), 768*time.Millisecond; got != want {
		t.Errorf("p99 = %s, want %s (the slowest sample's bucket)", got, want)
	}
}

// An empty tracker has nothing to report rather than a made-up floor.
func TestLatencyPercentileOfNothing(t *testing.T) {
	var lt latencyTracker
	if got := lt.percentile(0.50); got != 0 {
		t.Errorf("p50 of an empty tracker = %s, want 0", got)
	}
}

// Buckets are 2^i..2^(i+1) ms, and anything under a millisecond lands in the
// first one rather than underflowing.
//
// Bucket 0 reports 1ms rather than the 1.5ms the mid-bucket rule would give:
// (1<<0)*3/2 is integer arithmetic. Half a millisecond of estimate at the bottom
// of the range is not worth a float, but it is worth pinning so the next reader
// does not "fix" it into a change.
func TestLatencyRecordBuckets(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want time.Duration
	}{
		{0, 1 * time.Millisecond},
		{1 * time.Millisecond, 1 * time.Millisecond},
		{2 * time.Millisecond, 3 * time.Millisecond},
		{3 * time.Millisecond, 3 * time.Millisecond},
		{4 * time.Millisecond, 6 * time.Millisecond},
	} {
		var lt latencyTracker
		lt.record(tc.d)
		if got := lt.percentile(0.50); got != tc.want {
			t.Errorf("record(%s) -> p50 %s, want %s", tc.d, got, tc.want)
		}
	}
}
