package solver

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// Tearing a session down has to end its tab, not just its browsing context.
//
// Target.disposeBrowserContext ends the page in the browser but tells this side
// nothing: the tab's pump goroutine stays parked on its condition and its entry
// stays in the connection's session map. Both leak for the life of the process,
// and this is the path a batch takes — one browser, one context per exit — so
// the leak scales with the proxy list batch mode was written for.
//
// Goroutine count is the instrument because the pump is the thing being leaked
// and there is nothing else to ask.
func TestContextSessionCloseEndsTab(t *testing.T) {
	requireBrowser(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	l := Launcher{Profile: DefaultProfile(), Headless: true}
	b, err := l.launch(ctx, nil)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer b.Close()

	// One cycle first, so the browser's own lazily-started goroutines are up
	// before the baseline is taken.
	s, err := l.newContextSession(b, nil)(ctx)
	if err != nil {
		t.Fatalf("warmup session: %v", err)
	}
	s.close()
	quiesce()
	before := runtime.NumGoroutine()

	const cycles = 8
	for i := 0; i < cycles; i++ {
		s, err := l.newContextSession(b, nil)(ctx)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		s.close()
	}

	// A pump exits asynchronously once Close broadcasts, so this waits for the
	// count to come back down rather than sampling the instant the loop ends.
	if got, ok := settledAt(before + 2); !ok {
		t.Fatalf("goroutines went from %d to %d over %d session cycles; the tabs' pumps are not exiting",
			before, got, cycles)
	}
}

// The single-exit path closes the whole browser, which does not end the pump
// either — the goroutine is on this side of the pipe.
func TestBrowserSessionCloseEndsTab(t *testing.T) {
	requireBrowser(t)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	l := Launcher{Profile: DefaultProfile(), Headless: true}

	s, err := l.newBrowserSession(nil)(ctx)
	if err != nil {
		t.Fatalf("warmup session: %v", err)
	}
	s.close()
	quiesce()
	before := runtime.NumGoroutine()

	const cycles = 3
	for i := 0; i < cycles; i++ {
		s, err := l.newBrowserSession(nil)(ctx)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		s.close()
	}

	if got, ok := settledAt(before + 2); !ok {
		t.Fatalf("goroutines went from %d to %d over %d launch cycles; the tabs' pumps are not exiting",
			before, got, cycles)
	}
}

// quiesce gives teardown a moment to finish before a baseline is taken.
func quiesce() { time.Sleep(500 * time.Millisecond) }

// settledAt waits for the goroutine count to come down to limit, reporting the
// last count it saw and whether it got there.
func settledAt(limit int) (int, bool) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= limit {
			return n, true
		}
		if time.Now().After(deadline) {
			return n, false
		}
		time.Sleep(200 * time.Millisecond)
	}
}
