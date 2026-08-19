package cdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// waitReady has to end when the server dies, not when the deadline does.
//
// The version this covers tested cmd.ProcessState, which stays nil until
// cmd.Wait() is called — and nothing called it, so the guard could not fire
// once. An Xvfb that exited immediately cost the full ten seconds, and
// startXvfb's twenty attempts turned that into a caller's whole budget spent
// discovering nothing. The lock file is never created here, so reaching the
// deadline is exactly the old behaviour.
func TestXvfbWaitReadyEndsOnEarlyExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group teardown is a unix path")
	}
	cmd := exec.Command("/bin/sh", "-c", "exit 3")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	x := &xvfbDisplay{
		cmd:     cmd,
		display: ":999",
		// A lock path nothing will ever create, so only the exit can end the wait.
		lock:   t.TempDir() + "/.X999-lock",
		exited: make(chan struct{}),
	}
	go func() { x.waitErr = cmd.Wait(); close(x.exited) }()

	start := time.Now()
	err := x.waitReady()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("waitReady reported a server that had already exited as ready")
	}
	if !strings.Contains(err.Error(), "exited during startup") {
		t.Fatalf("waitReady error = %q, want it to name the exit", err)
	}
	// The old code could only reach the 10s deadline. Anything near it means
	// the exit was not observed and the timeout answered instead.
	if elapsed > 2*time.Second {
		t.Fatalf("waitReady took %s to notice a dead server; it is timing out, not observing the exit", elapsed)
	}
}

// stop must not reap a process the startXvfb goroutine is already waiting on.
// Two Waits on one process is a race whichever way it lands.
func TestXvfbStopWaitsForReaper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group teardown is a unix path")
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	x := &xvfbDisplay{cmd: cmd, display: ":998", lock: t.TempDir() + "/.X998-lock", exited: make(chan struct{})}
	reaped := make(chan struct{})
	go func() { x.waitErr = cmd.Wait(); close(x.exited); close(reaped) }()

	done := make(chan struct{})
	go func() { x.stop(); close(done) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("stop did not return")
	}
	select {
	case <-reaped:
	default:
		t.Fatal("stop returned before the process was collected")
	}
}

// A handler registered per call has to be removable, or every navigation on a
// tab leaves the previous one's handler running beside it.
func TestTabHandlerRemoval(t *testing.T) {
	tab := &Tab{events: make(map[string][]tabHandler)}
	tab.wake = sync.NewCond(&tab.mu)

	var mu sync.Mutex
	var fired []string
	record := func(name string) func(json.RawMessage) {
		return func(json.RawMessage) {
			mu.Lock()
			fired = append(fired, name)
			mu.Unlock()
		}
	}

	removeA := tab.on("Test.event", record("a"))
	tab.on("Test.event", record("b"))

	dispatch := func() {
		tab.mu.Lock()
		hs := append([]tabHandler{}, tab.events["Test.event"]...)
		tab.mu.Unlock()
		for _, h := range hs {
			h.fn(nil)
		}
	}

	dispatch()
	removeA()
	dispatch()
	// Removing twice must not take the other handler with it.
	removeA()
	dispatch()

	mu.Lock()
	got := strings.Join(fired, ",")
	mu.Unlock()
	if want := "a,b,b,b"; got != want {
		t.Fatalf("handlers fired %q, want %q", got, want)
	}

	tab.mu.Lock()
	n := len(tab.events["Test.event"])
	tab.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d handlers left registered, want 1", n)
	}
}

// Navigate registers a lifecycle handler on every call. Against a real browser:
// navigate repeatedly and the registration count must not grow with it.
func TestNavigateDoesNotAccumulateHandlers(t *testing.T) {
	b := testBrowser(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tab, err := b.DefaultContext().NewTab(ctx)
	if err != nil {
		t.Fatalf("new tab: %v", err)
	}
	defer tab.Close(ctx)

	for i := 0; i < 5; i++ {
		if err := tab.Navigate(ctx, srv.URL); err != nil {
			t.Fatalf("navigate %d: %v", i, err)
		}
	}

	tab.mu.Lock()
	n := len(tab.events["Page.domContentEventFired"])
	tab.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d Page.domContentEventFired handlers left after 5 navigations, want 0", n)
	}
}

// Close has to end the pump goroutine. Without it a batch that solves a proxy
// list parks one goroutine per exit for the life of the process.
func TestTabCloseEndsPump(t *testing.T) {
	b := testBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	before := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		tab, err := b.DefaultContext().NewTab(ctx)
		if err != nil {
			t.Fatalf("new tab %d: %v", i, err)
		}
		if err := tab.Close(ctx); err != nil {
			t.Fatalf("close tab %d: %v", i, err)
		}
	}

	// The pumps exit asynchronously once Close broadcasts, so this waits rather
	// than sampling once.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("goroutines went from %d to %d over 5 open/close cycles; the pumps are not exiting",
		before, runtime.NumGoroutine())
}
