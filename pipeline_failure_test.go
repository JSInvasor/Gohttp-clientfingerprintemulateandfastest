package gofire

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Spray's accounting is covered on the happy path and only there.
//
// TestSprayCompletesNormally and TestSprayHandlesMoreRequestsThanWorkers both
// assert Failed == 0, so the counter has never been watched while it counts.
// The arithmetic that has to hold is Success+Failed == Total whichever way the
// requests go, and half of that identity was untested — a run where results are
// lost rather than counted looks identical to a run that succeeded, since the
// only thing saying otherwise is a number nothing checks.

// closedAddr returns an address with nothing listening on it, so every dial is
// refused immediately rather than timing out.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// Every request failing has to be counted as failing, not quietly dropped.
func TestSprayCountsTransportFailures(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	p := client.NewPipeline(8)
	defer p.Close()

	const n = 60
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sr := p.Spray(ctx, "GET", "http://"+closedAddr(t)+"/", n)

	if sr.Total != n {
		t.Errorf("Total = %d, want %d", sr.Total, n)
	}
	if sr.Success != 0 {
		t.Errorf("Success = %d, want 0 — nothing was listening", sr.Success)
	}
	if sr.Failed != n {
		t.Errorf("Failed = %d, want %d", sr.Failed, n)
	}
	if sr.Success+sr.Failed != sr.Total {
		t.Errorf("accounted %d results against a Total of %d: results are being lost rather than counted",
			sr.Success+sr.Failed, sr.Total)
	}
	// RPS divides by Success, so an all-failed run reports zero rather than
	// something that reads like throughput.
	if sr.RPS != 0 {
		t.Errorf("RPS = %v on a run where nothing succeeded", sr.RPS)
	}
}

// A server that answers is a success even when it answers 500.
//
// Failed counts transport failures — no connection, no response, a broken
// stream — and not HTTP status codes. That is the right split for a load tool,
// and it is the kind of thing a reader assumes the other way round, so it is
// worth a test that says which one it is.
func TestSprayCountsAnErrorStatusAsASuccess(t *testing.T) {
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	p := client.NewPipeline(8)
	defer p.Close()

	const n = 40
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sr := p.Spray(ctx, "GET", srv.URL, n)

	if got := served.Load(); got != n {
		t.Fatalf("server saw %d requests, want %d", got, n)
	}
	if sr.Failed != 0 {
		t.Errorf("Failed = %d, want 0: a 500 is a response, not a transport failure", sr.Failed)
	}
	if sr.Success != n {
		t.Errorf("Success = %d, want %d", sr.Success, n)
	}
	if sr.Success+sr.Failed != sr.Total {
		t.Errorf("accounted %d results against a Total of %d", sr.Success+sr.Failed, sr.Total)
	}
}

// Successes and failures in the same run still have to add up.
//
// One pipeline, two targets, so both counters move within a single Spray's
// bookkeeping rather than in runs that only ever exercise one of them.
func TestSprayAccountsForAMixedRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer srv.Close()

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	p := client.NewPipeline(8)
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const good, bad = 40, 40
	okRun := p.Spray(ctx, "GET", srv.URL, good)
	badRun := p.Spray(ctx, "GET", "http://"+closedAddr(t)+"/", bad)

	for _, tc := range []struct {
		name string
		sr   *SprayResult
		want int
	}{
		{"reachable", okRun, good},
		{"refused", badRun, bad},
	} {
		if tc.sr.Success+tc.sr.Failed != tc.want {
			t.Errorf("%s: accounted %d results, want %d (success=%d failed=%d)",
				tc.name, tc.sr.Success+tc.sr.Failed, tc.want, tc.sr.Success, tc.sr.Failed)
		}
	}
	if okRun.Success != good {
		t.Errorf("reachable run: Success = %d, want %d", okRun.Success, good)
	}
	if badRun.Failed != bad {
		t.Errorf("refused run: Failed = %d, want %d", badRun.Failed, bad)
	}
}

// The latency summary has to describe the sample it was taken from.
//
// MinLatency starts at the maximum duration as a sentinel, so a run that
// reported it verbatim would claim 292 years. The zero case is already pinned by
// TestSprayZero; this pins the ordinary one, on a run where every request fails
// — the path where the latencies come from failed sends rather than replies.
func TestSprayLatencySummaryIsWithinItsSample(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	p := client.NewPipeline(4)
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sr := p.Spray(ctx, "GET", "http://"+closedAddr(t)+"/", 20)

	if sr.MinLatency <= 0 {
		t.Errorf("MinLatency = %v, want a real measurement", sr.MinLatency)
	}
	if sr.MinLatency == time.Duration(1<<63-1) {
		t.Error("MinLatency is the sentinel it was initialised to, so nothing overwrote it")
	}
	if sr.MaxLatency < sr.MinLatency {
		t.Errorf("MaxLatency %v is below MinLatency %v", sr.MaxLatency, sr.MinLatency)
	}
	if sr.AvgLatency < sr.MinLatency || sr.AvgLatency > sr.MaxLatency {
		t.Errorf("AvgLatency %v falls outside [%v, %v]", sr.AvgLatency, sr.MinLatency, sr.MaxLatency)
	}
}
