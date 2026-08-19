package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// stubSolverBatch replaces the batch solve for the length of one test.
//
// The batch used to be a Node process reading a job list from stdin and writing
// one NDJSON line per exit, and the stubs here spoke that protocol. In-process
// there is no protocol — the pairing this exercises is a callback — so the stub
// is a function that answers per exit.
func stubSolverBatch(t *testing.T, fn func(o *options, target string, e exit) (*solveResult, error)) {
	t.Helper()
	previous := runSolverBatch
	runSolverBatch = func(_ context.Context, o *options, target string, exits []exit,
		onResult func(exit, *solveResult, error)) error {
		for _, e := range exits {
			res, err := fn(o, target, e)
			onResult(e, res, err)
		}
		return nil
	}
	t.Cleanup(func() { runSolverBatch = previous })
}

// batchSolvesEveryExit answers every exit with a cookie naming it, so a test can
// check the pairing survived the round trip.
func batchSolvesEveryExit(o *options, target string, e exit) (*solveResult, error) {
	return &solveResult{
		Exit:          e.identity(),
		Status:        "ok",
		URL:           target,
		UserAgent:     "UA-151",
		Proxy:         e.proxy,
		DurationMS:    10,
		Attempts:      1,
		Chromium:      "Chrome/151.0.0.0",
		ChromiumMajor: 151,
		CookieList: []solvedCookie{
			{Name: "cf_clearance", Value: "for-" + e.identity(), Domain: "site.test"},
		},
	}, nil
}

func batchOptions(t *testing.T, solve func(o *options, target string, e exit) (*solveResult, error),
	sessions int, proxies ...string) *options {
	t.Helper()
	// The per-browser stub is installed too: solveAcrossProxies falls back to it
	// for a single pending exit, so a batch test that ends up there must not
	// reach a real browser either.
	o := fleetOptions(t, func(*options, string, string) (*solveResult, error) {
		return nil, errors.New("solver: the batch path was expected")
	}, sessions, proxies...)
	stubSolverBatch(t, solve)
	o.solveIsolate = false // the shared-browser path, which is the default
	return o
}

// The invariant the whole feature rests on, through the batch: every exit ends
// up with the cookie its own proxy earned. One browser serves them all, so this
// is where a shared cookie jar would show up as one exit holding another's
// clearance.
func TestBatchPairsSeedsWithExits(t *testing.T) {
	o := batchOptions(t, batchSolvesEveryExit, 3, "http://a.test:1", "http://b.test:2", "http://c.test:3")

	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAcrossProxies: %v", err)
	}
	if len(o.solveSeeds) != 3 {
		t.Fatalf("%d seeds, want 3", len(o.solveSeeds))
	}
	for i, seed := range o.solveSeeds {
		if seed.proxy != o.proxyList[i] {
			t.Errorf("seed %d is for %q but sits at exit %q", i, seed.proxy, o.proxyList[i])
		}
		// The stub keys the cookie on the exit id, which is the identity the Go
		// side chose — so this also pins that the id round-trips intact.
		want := "cf_clearance=for-" + o.proxyList[i]
		if len(seed.cookies) != 1 || seed.cookies[0] != want {
			t.Errorf("seed %d cookies = %v, want %q", i, seed.cookies, want)
		}
	}
}

// An exit the batch reports an error for is dropped, exactly as it is on the
// per-browser path — one browser must not mean one verdict for the whole list.
func TestBatchDropsExitsThatFailed(t *testing.T) {
	failOnB := func(o *options, target string, e exit) (*solveResult, error) {
		if strings.Contains(e.proxy, "b.test") {
			return nil, errors.New("solver: challenge not solved")
		}
		return batchSolvesEveryExit(o, target, e)
	}
	o := batchOptions(t, failOnB, 3, "http://a.test:1", "http://b.test:2", "http://c.test:3")

	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAcrossProxies: %v", err)
	}
	if len(o.proxyList) != 2 {
		t.Fatalf("proxyList = %v, want the failed exit dropped", o.proxyList)
	}
	for i, p := range o.proxyList {
		if strings.Contains(p, "b.test") {
			t.Errorf("proxyList = %v still holds the exit that failed", o.proxyList)
		}
		if o.solveSeeds[i].proxy != p {
			t.Errorf("after the drop, seed %d is for %q but sits at %q", i, o.solveSeeds[i].proxy, p)
		}
	}
}

// An exit the batch never mentions is a dropped exit, not an absent one. A
// solver killed at exit 3 of 5 leaves two with no line at all, and inferring
// success from silence would pair a session with no cookie.
func TestBatchTreatsMissingExitsAsFailures(t *testing.T) {
	// Answers for the first exit only, then stops — the shape a batch that dies
	// partway leaves behind.
	o := batchOptions(t, nil, 3, "http://a.test:1", "http://b.test:2", "http://c.test:3")
	previous := runSolverBatch
	t.Cleanup(func() { runSolverBatch = previous })
	runSolverBatch = func(_ context.Context, opts *options, target string, exits []exit,
		onResult func(exit, *solveResult, error)) error {
		first := exits[0]
		res, _ := batchSolvesEveryExit(opts, target, first)
		onResult(first, res, nil)
		for _, e := range exits[1:] {
			onResult(e, nil, errors.New("the batch ended without reporting this exit"))
		}
		return nil
	}

	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAcrossProxies: %v", err)
	}
	if len(o.proxyList) != 1 || o.proxyList[0] != "http://a.test:1" {
		t.Fatalf("proxyList = %v, want only the exit that was reported", o.proxyList)
	}
}

// A solver that dies before saying anything fails every exit with its own
// message rather than a generic one.
func TestBatchReportsAFailedSolverForEveryExit(t *testing.T) {
	o := batchOptions(t, func(*options, string, exit) (*solveResult, error) {
		return nil, errors.New("the batch ended before reporting this exit: browser did not start")
	}, 2, "http://a.test:1", "http://b.test:2")

	err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/")
	if err == nil {
		t.Fatal("a batch that never ran was allowed to start a run")
	}
	if !strings.Contains(err.Error(), "did not start") {
		t.Errorf("error %q does not carry the reason the batch failed", err)
	}
}

// The cache is consulted before anything is launched, so a fully cached list
// never starts a browser. Without that, a warm cache would still pay a launch.
func TestBatchSkipsTheBrowserWhenEverythingIsCached(t *testing.T) {
	o := batchOptions(t, batchSolvesEveryExit, 2, "http://a.test:1", "http://b.test:2")
	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("first solve: %v", err)
	}

	// Second run over the same cache, with a solver that fails if it runs at all.
	again := batchOptions(t, func(*options, string, exit) (*solveResult, error) {
		return nil, errors.New("solver: should not have run")
	}, 2, "http://a.test:1", "http://b.test:2")
	again.solveCache = o.solveCache

	if err := solveAcrossProxies(context.Background(), again, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("a fully cached list still started the solver: %v", err)
	}
	if len(again.solveSeeds) != 2 {
		t.Fatalf("%d seeds from cache, want 2", len(again.solveSeeds))
	}
}

// Proxy credentials used to be the reason the job list went over stdin rather
// than argv: /proc/<pid>/cmdline is world-readable for as long as the solve runs,
// and a solve runs for minutes.
//
// There is no second process any more, so there is no argv and no pipe — the
// credentials never leave this address space. What is still worth pinning is the
// half that remains observable: the exit reaches the solve with its credentials
// intact, because the browser needs them to authenticate, while everything that
// gets printed carries the redacted label instead.
func TestBatchKeepsCredentialsOutOfWhatItPrints(t *testing.T) {
	const withSecret = "http://user:hunter2@a.test:1"

	var given string
	o := batchOptions(t, func(_ *options, target string, e exit) (*solveResult, error) {
		given = e.proxy
		return &solveResult{
			Exit: e.identity(), Status: "ok", UserAgent: "UA-151",
			// Proxy is what a result line reports, and it is the label rather
			// than the URL for exactly this reason.
			Proxy:      e.label(),
			CookieList: []solvedCookie{{Name: "cf_clearance", Value: "v", Domain: "site.test"}},
		}, nil
	}, 2, withSecret, "http://user:hunter2@b.test:2")

	var reported string
	exits := []exit{{proxy: withSecret, ip: "203.0.113.1"}}
	err := runSolverBatch(context.Background(), o, "https://site.test/", exits,
		func(_ exit, res *solveResult, err error) {
			if err == nil && res != nil {
				reported = res.Proxy
			}
		})
	if err != nil {
		t.Fatalf("runSolverBatch: %v", err)
	}
	if given != withSecret {
		t.Errorf("the solve was given %q, want the credentials it needs to authenticate", given)
	}
	if strings.Contains(reported, "hunter2") {
		t.Errorf("the reported exit carries the password: %q", reported)
	}
	if strings.Contains(redactProxy(withSecret), "hunter2") {
		t.Errorf("redactProxy leaked the password: %q", redactProxy(withSecret))
	}
}

// -solve-isolate goes back to a browser per exit, which is the escape hatch if a
// shared browser ever turns out to be measurably different.
func TestSolveIsolateParses(t *testing.T) {
	o, target, err := parseFlags([]string{"-solve", "-solve-isolate", "https://site.test"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if target != "https://site.test" {
		t.Errorf("target = %q", target)
	}
	if !o.solveIsolate {
		t.Error("-solve-isolate was not set")
	}
}

// The batch budget is per exit and the exits run in rounds, so a list longer
// than -solve-parallel needs more wall clock than one budget. Sizing it for one
// killed every batch at the first round boundary.
func TestBatchBudgetScalesWithRounds(t *testing.T) {
	// Six exits, two at a time, is three rounds — so three budgets, not one.
	o := batchOptions(t, batchSolvesEveryExit, 6,
		"http://a:1", "http://b:2", "http://c:3", "http://d:4", "http://e:5", "http://f:6")
	o.solveParallel = 2
	o.solveTimeout = 30 * time.Second

	start := time.Now()
	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAcrossProxies: %v", err)
	}
	if len(o.solveSeeds) != 6 {
		t.Fatalf("%d seeds, want all 6", len(o.solveSeeds))
	}
	// The stub answers immediately; this only guards against the budget being
	// mistaken for a wait.
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("a batch of instant results took %s", elapsed)
	}
}
