package main

import (
	"bytes"
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// -rps is the flag for going easy on a target, so releasing more than it asks
// for is the one failure it must not have. It used to: the release per slice was
// rate/100 in integer division, so everything under 100 floored to one token a
// slice — a hundred a second — and -rps 10 ran ten times over.
func TestLimiterHoldsTheRate(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	for _, rate := range []int{10, 50, 99, 100, 250} {
		l := newLimiter(rate)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

		start := time.Now()
		n := 0
		for time.Since(start) < time.Second {
			if !l.wait(ctx) {
				break
			}
			n++
		}
		elapsed := time.Since(start)
		l.stop()
		cancel()

		got := float64(n) / elapsed.Seconds()
		// A ticker cannot be exact over one second, and the bucket carries one
		// slice of burst, so the window is generous on both sides — but nowhere
		// near the 10x this used to be.
		if lo, hi := float64(rate)*0.85, float64(rate)*1.15; got < lo || got > hi {
			t.Errorf("-rps %d released %.0f/s, want between %.0f and %.0f", rate, got, lo, hi)
		}
	}
}

// Rate 0 is "as fast as it will go", not "stop".
func TestLimiterUncappedNeverBlocks(t *testing.T) {
	l := newLimiter(0)
	defer l.stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := 0; i < 10000; i++ {
		if !l.wait(ctx) {
			t.Fatalf("an uncapped limiter blocked at call %d", i)
		}
	}
}

// A cancelled run has to stop workers waiting on a token, or the run cannot end.
func TestLimiterReleasesOnCancel(t *testing.T) {
	l := newLimiter(1) // one token a second: the second wait will be parked
	defer l.stop()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan bool, 1)
	go func() {
		l.wait(ctx)
		done <- l.wait(ctx)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case ok := <-done:
		if ok {
			t.Error("wait reported a token after the run was cancelled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled wait never returned")
	}
}

// splitArgs has to know which flags take no value, or one of them swallows the
// argument after it — `send -solve https://site` consuming the URL and then
// reporting that no URL was given. It reads that from the FlagSet now; this is
// what keeps it honest for every flag at once, including ones added later.
func TestNoBoolFlagSwallowsTheNextArgument(t *testing.T) {
	o := &options{}
	fs := newFlagSet(o)

	var bools []string
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			bools = append(bools, f.Name)
		}
	})
	if len(bools) < 10 {
		t.Fatalf("only found %d bool flags (%v) — the FlagSet is not being read", len(bools), bools)
	}

	for _, name := range bools {
		_, target, err := parseFlags([]string{"-" + name, "https://site.test"})
		if err != nil {
			t.Errorf("-%s https://site.test: %v", name, err)
			continue
		}
		if target != "https://site.test" {
			t.Errorf("-%s swallowed the URL: target = %q", name, target)
		}
	}
}

// The counterpart: a flag that does take a value must still consume it, or the
// value lands in the positional dials.
func TestValueFlagsStillTakeTheirValue(t *testing.T) {
	o, target, err := parseFlags([]string{"-lang", "tr-TR", "-solve-parallel", "3", "https://site.test", "30s"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if o.lang != "tr-TR" || o.solveParallel != 3 {
		t.Errorf("lang=%q solveParallel=%d", o.lang, o.solveParallel)
	}
	if target != "https://site.test" || o.duration != 30*time.Second {
		t.Errorf("target=%q duration=%s", target, o.duration)
	}
}

// -solve-ip-check "" is how the address measurement is turned off, and an empty
// value must not be mistaken for a missing one.
func TestEmptyFlagValueIsAccepted(t *testing.T) {
	o, _, err := parseFlags([]string{"-solve-ip-check", "", "https://site.test"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if o.exitCheck != "" {
		t.Errorf("exitCheck = %q, want it cleared", o.exitCheck)
	}
}

// A template that cannot be built is a run that sends nothing. It used to print
// and fall through to the summary, so the report said zero requests and the
// process exited 0.
func TestFastTemplateFailureFailsTheRun(t *testing.T) {
	o := &options{
		method: "GET", mode: modeFast, concurrency: 1, sessions: 1, count: 1,
		timeout: time.Second, handshake: time.Second, maxBody: -1, silent: true,
	}
	pool, err := newSessionPool(o, gofire.Chrome151, "https://site.test/")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// A method with a space in it cannot go in a request line.
	o.method = "GET POST"
	err = sendLoad(context.Background(), pool, o, "https://site.test/", nil, nil)
	if err == nil {
		t.Fatal("a run that could not build its template reported success")
	}
	if !strings.Contains(err.Error(), "session 0") {
		t.Errorf("error %q does not name the session that failed", err)
	}
}

// What a pipeline run says it transferred has to be what it transferred.
//
// It was not. OnResult added resp.ContentLength, the length the origin
// *declared*, guarded by `> 0` — and ContentLength is -1 on any response with no
// Content-Length header, which is every streamed HTTP/2 response. So the guard
// dropped all of them and the mode built for the highest throughput reported no
// body at all.
//
// The bytes exist, they are just counted elsewhere: the pipeline drains bodies
// in a pool of its own and totals what it read. This asserts the run reports
// that number rather than the declared one.
func TestPipelineReportsTheBytesItActuallyRead(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 8192)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately no Content-Length, and flushed: a streamed origin, which
		// is the ordinary case this used to miss entirely.
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write(payload)
		w.(http.Flusher).Flush()
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	const requests = 20
	o := &options{
		mode:        modePipeline,
		method:      "GET",
		count:       requests,
		concurrency: 4,
		sessions:    1,
		timeout:     10 * time.Second,
		handshake:   10 * time.Second,
		insecure:    true,
	}
	pool, err := newSessionPool(o, gofire.Chrome151, srv.URL)
	if err != nil {
		t.Fatalf("session pool: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st := newStats(o.count)
	lim := newLimiter(0)
	defer lim.stop()

	var wg sync.WaitGroup
	runPipeline(ctx, pool, o, srv.URL, nil, nil, st, lim, &wg)
	wg.Wait()
	// The same step sendLoad takes before it reports: the drain pool is
	// asynchronous, so the last result is not the last body.
	pool.closePipelines()

	if sent := st.sent.Load(); sent != requests {
		t.Fatalf("recorded %d results, want %d", sent, requests)
	}

	drained, ok := pool.drainedBytes()
	if !ok {
		t.Fatal("a pipeline run reported no pipeline to read bytes from")
	}
	if want := int64(requests * len(payload)); drained != want {
		t.Errorf("drained %d bytes, want %d", drained, want)
	}
	// And the source that used to be reported is exactly the zero this exists
	// to stop being printed.
	if n := st.bodyBytes.Load(); n != 0 {
		t.Errorf("the per-request counter is %d; pipeline mode does not read bodies at the call site", n)
	}
}
