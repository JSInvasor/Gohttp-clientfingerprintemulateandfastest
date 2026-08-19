package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// proxyFile writes a proxy list and returns its path.
func proxyFile(t *testing.T, proxies ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(path, []byte(strings.Join(proxies, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write proxy file: %v", err)
	}
	return path
}

func fleetOptions(t *testing.T, solve func(o *options, target, proxy string) (*solveResult, error),
	sessions int, proxies ...string) *options {
	t.Helper()
	stubSolver(t, solve)
	o := solveOptions()
	o.solve = true
	o.solveParallel = 2
	o.solveCache = t.TempDir()
	o.solveMaxAge = 30 * time.Minute
	o.sessions = sessions
	o.proxyFile = proxyFile(t, proxies...)
	// These exits are fictional, so there is nothing to measure. The grouping
	// and rotation checks have their own tests against real sockets in
	// exitip_test.go; here every entry is meant to stand for its own exit.
	o.exitCheck = ""
	// A browser per exit, which is what these stubs speak. The shared-browser
	// path has the same invariants pinned against a batch-speaking stub in
	// solvebatch_test.go.
	o.solveIsolate = true
	return o
}

// alwaysFails is a solve that never succeeds, for the cases where running at all
// is the failure being asserted.
func alwaysFails(msg string) func(*options, string, string) (*solveResult, error) {
	return func(*options, string, string) (*solveResult, error) {
		return nil, errors.New("solver: " + msg)
	}
}

// The whole point of the fleet: session i replays the cookie exit i earned, and
// not one its neighbour earned. A cookie on the wrong exit is a 403 that looks
// exactly like the target blocking the client, so this is the invariant worth
// pinning.
func TestSolveAcrossProxiesPairsSeedsWithExits(t *testing.T) {
	o := fleetOptions(t, echoProxySolve, 3, "http://a.test:1", "http://b.test:2", "http://c.test:3")

	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAcrossProxies: %v", err)
	}
	if len(o.solveSeeds) != 3 || len(o.proxyList) != 3 {
		t.Fatalf("%d seeds for %d exits, want 3 of each", len(o.solveSeeds), len(o.proxyList))
	}
	for i, seed := range o.solveSeeds {
		if seed.proxy != o.proxyList[i] {
			t.Errorf("seed %d is for %q but sits at exit %q", i, seed.proxy, o.proxyList[i])
		}
		want := "cf_clearance=for-" + o.proxyList[i]
		if len(seed.cookies) != 1 || seed.cookies[0] != want {
			t.Errorf("seed %d cookies = %v, want %q", i, seed.cookies, want)
		}
		// seedFor is what newSession uses, so the pairing has to survive it too.
		if got := o.seedFor(i); got.proxy != o.proxyList[i] {
			t.Errorf("seedFor(%d) = %q, want %q", i, got.proxy, o.proxyList[i])
		}
	}

	// The run's shared cookie list stays empty: these belong to one session
	// each, and seeding them globally would put every cf_clearance on every
	// exit.
	if len(o.cookies) != 0 {
		t.Errorf("cookies = %v, want the seeds kept per session", o.cookies)
	}
}

// More sessions than exits is legitimate — two sessions on one exit share its
// IP, UA and fingerprint, so they may share its cookie. What they may not do is
// drift off the modulo the proxy pinning uses.
func TestSeedForWrapsWithTheProxyPinning(t *testing.T) {
	o := &options{solveSeeds: []solveSeed{{proxy: "a"}, {proxy: "b"}}}
	for i, want := range []string{"a", "b", "a", "b", "a"} {
		if got := o.seedFor(i); got.proxy != want {
			t.Errorf("seedFor(%d) = %q, want %q", i, got.proxy, want)
		}
	}
	if (&options{}).seedFor(0) != nil {
		t.Error("a run with no seeds returned one")
	}
}

// Only the exits a session actually pins are worth a browser launch and a
// challenge. Solving the rest buys cookies nothing replays.
func TestSolveAcrossProxiesSolvesOnlyWhatSessionsPin(t *testing.T) {
	o := fleetOptions(t, echoProxySolve, 2, "http://a.test:1", "http://b.test:2", "http://c.test:3")

	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAcrossProxies: %v", err)
	}
	if len(o.solveSeeds) != 2 {
		t.Fatalf("%d seeds for 2 sessions, want 2", len(o.solveSeeds))
	}
	if len(o.proxyList) != 2 || o.proxyList[1] != "http://b.test:2" {
		t.Errorf("proxyList = %v, want the first two exits", o.proxyList)
	}
}

// An exit that cannot get past the challenge in a browser will not get past it
// in this client either. Leaving it in the rotation spends a session's whole
// share of the run on 403s, so it comes out of the list the pool is built from.
func TestSolveAcrossProxiesDropsExitsThatFailed(t *testing.T) {
	// b.test reports an error; everything else solves.
	failOnB := func(o *options, target, proxy string) (*solveResult, error) {
		if strings.Contains(proxy, "b.test") {
			return nil, errors.New("solver: challenge not solved")
		}
		return echoProxySolve(o, target, proxy)
	}
	o := fleetOptions(t, failOnB, 3, "http://a.test:1", "http://b.test:2", "http://c.test:3")

	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAcrossProxies: %v", err)
	}
	if len(o.proxyList) != 2 {
		t.Fatalf("proxyList = %v, want the failed exit dropped", o.proxyList)
	}
	for i, p := range o.proxyList {
		if strings.Contains(p, "b.test") {
			t.Errorf("proxyList = %v, still holds the exit that failed", o.proxyList)
		}
		if o.solveSeeds[i].proxy != p {
			t.Errorf("after the drop, seed %d is for %q but sits at exit %q",
				i, o.solveSeeds[i].proxy, p)
		}
		if want := "cf_clearance=for-" + p; o.solveSeeds[i].cookies[0] != want {
			t.Errorf("after the drop, seed %d carries %v, want %q", i, o.solveSeeds[i].cookies, want)
		}
	}
}

// Every exit failing is not a run worth starting: every session would replay
// nothing at a target that demanded a cookie.
func TestSolveAcrossProxiesFailsWhenNoExitSolved(t *testing.T) {
	o := fleetOptions(t, alwaysFails("challenge not solved"), 2,
		"http://a.test:1", "http://b.test:2")

	err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/")
	if err == nil {
		t.Fatal("a run with no solved exit was allowed to start")
	}
	if !strings.Contains(err.Error(), "challenge not solved") {
		t.Errorf("error %q does not carry the solver's message", err)
	}
}

// The cache is keyed by host and proxy, so a second run pays for nothing it
// already has. Without that, a fleet solve would be unusable: it is one
// challenge per exit.
func TestSolveAcrossProxiesReusesThePerExitCache(t *testing.T) {
	o := fleetOptions(t, echoProxySolve, 2, "http://a.test:1", "http://b.test:2")
	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("first solve: %v", err)
	}

	// Second run, same cache, a solver that would fail if it ran at all.
	again := fleetOptions(t, alwaysFails("should not have run"), 2,
		"http://a.test:1", "http://b.test:2")
	again.solveCache = o.solveCache

	if err := solveAcrossProxies(context.Background(), again, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("second solve did not come from the cache: %v", err)
	}
	for i, seed := range again.solveSeeds {
		want := "cf_clearance=for-" + again.proxyList[i]
		if len(seed.cookies) != 1 || seed.cookies[0] != want {
			t.Errorf("cached seed %d = %v, want %q", i, seed.cookies, want)
		}
	}
}

// -solve-parallel is what keeps a 40-proxy list from launching 40 Chromiums on
// a box with room for two.
func TestSolveFleetHonoursTheParallelCeiling(t *testing.T) {
	// Each stub records its own start and end, so the test can count how many
	// were alive at once without depending on timing.
	var mu sync.Mutex
	live, peak := 0, 0
	counting := func(o *options, target, proxy string) (*solveResult, error) {
		mu.Lock()
		live++
		peak = max(peak, live)
		mu.Unlock()

		time.Sleep(150 * time.Millisecond)

		mu.Lock()
		live--
		mu.Unlock()
		return echoProxySolve(o, target, proxy)
	}

	o := fleetOptions(t, counting, 6,
		"http://a.test:1", "http://b.test:2", "http://c.test:3",
		"http://d.test:4", "http://e.test:5", "http://f.test:6")
	o.solveParallel = 2

	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAcrossProxies: %v", err)
	}
	if len(o.solveSeeds) != 6 {
		t.Fatalf("%d seeds, want all 6 exits solved", len(o.solveSeeds))
	}

	mu.Lock()
	defer mu.Unlock()
	if peak > o.solveParallel {
		t.Errorf("%d solvers ran at once, want at most %d", peak, o.solveParallel)
	}
	if peak < 2 {
		t.Errorf("peak concurrency %d — the solves serialised instead of overlapping", peak)
	}
}

// An interrupt during a solve is not a partial success to carry into a run: the
// sessions whose exits had not been reached yet would have no cookie at all.
func TestSolveAcrossProxiesStopsOnCancel(t *testing.T) {
	o := fleetOptions(t, echoProxySolve, 2, "http://a.test:1", "http://b.test:2")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := solveAcrossProxies(ctx, o, gofire.Chrome151, "https://site.test/"); err == nil {
		t.Fatal("a cancelled solve reported success")
	}
	if len(o.solveSeeds) != 0 || len(o.proxyList) != 0 {
		t.Errorf("a cancelled solve left %d seed(s) and %d exit(s) behind",
			len(o.solveSeeds), len(o.proxyList))
	}
}

// -solve with -proxy-file used to be refused outright. It is the combination the
// fleet exists for, so the flags have to reach normalize intact.
func TestSolveWithProxyFileIsAccepted(t *testing.T) {
	o, target, err := parseFlags([]string{"-solve", "-proxy-file", "p.txt", "-t", "30s",
		"-s", "4", "-c", "8", "https://site.test"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if target != "https://site.test" || o.proxyFile != "p.txt" || !o.solve {
		t.Fatalf("target=%q proxyFile=%q solve=%v", target, o.proxyFile, o.solve)
	}
	if o.solveParallel != 2 {
		t.Errorf("solveParallel = %d, want the default 2", o.solveParallel)
	}
}
