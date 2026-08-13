package main

import (
	"context"
	"strings"
	"testing"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// batchStubJS is a solver that speaks the batch protocol: it reads the job list
// from stdin and answers one NDJSON line per exit, naming the proxy it was given
// so a test can check the pairing survived the round trip.
//
// A line per exit rather than one object at the end is the contract that lets
// the Go side report as results land, so the stub has to stream too.
const batchStubJS = `let raw = "";
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  const job = JSON.parse(raw);
  for (const e of job.exits) {
    process.stdout.write(JSON.stringify({
      exit: e.id, status: "ok", url: process.argv[2], user_agent: "UA-151",
      proxy: e.proxy, duration_ms: 10, attempts: 1,
      chromium_version: "Chrome/151.0.0.0", chromium_major: 151,
      cookie_list: [{name: "cf_clearance", value: "for-" + e.id, domain: "site.test"}],
    }) + "\n");
  }
});
`

func batchOptions(t *testing.T, script string, sessions int, proxies ...string) *options {
	t.Helper()
	o := fleetOptions(t, script, sessions, proxies...)
	o.solveIsolate = false // the shared-browser path, which is the default
	return o
}

// The invariant the whole feature rests on, through the batch: every exit ends
// up with the cookie its own proxy earned. One browser serves them all, so this
// is where a shared cookie jar would show up as one exit holding another's
// clearance.
func TestBatchPairsSeedsWithExits(t *testing.T) {
	o := batchOptions(t, batchStubJS, 3, "http://a.test:1", "http://b.test:2", "http://c.test:3")

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
	const script = `let raw = "";
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  const job = JSON.parse(raw);
  for (const e of job.exits) {
    const bad = e.proxy.includes("b.test");
    process.stdout.write(JSON.stringify(bad
      ? {exit: e.id, status: "error", error: "challenge not solved"}
      : {exit: e.id, status: "ok", user_agent: "UA-151", proxy: e.proxy,
         cookie_list: [{name: "cf_clearance", value: "for-" + e.id, domain: "site.test"}]}) + "\n");
  }
});
`
	o := batchOptions(t, script, 3, "http://a.test:1", "http://b.test:2", "http://c.test:3")

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
	// Answers for the first exit only, then exits cleanly.
	const script = `let raw = "";
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  const job = JSON.parse(raw);
  const e = job.exits[0];
  process.stdout.write(JSON.stringify({exit: e.id, status: "ok", user_agent: "UA-151",
    proxy: e.proxy, cookie_list: [{name: "cf_clearance", value: "for-" + e.id, domain: "site.test"}]}) + "\n");
});
`
	o := batchOptions(t, script, 3, "http://a.test:1", "http://b.test:2", "http://c.test:3")

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
	o := batchOptions(t, `process.exit(3);`, 2, "http://a.test:1", "http://b.test:2")

	err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/")
	if err == nil {
		t.Fatal("a batch that never ran was allowed to start a run")
	}
	if !strings.Contains(err.Error(), "exited") {
		t.Errorf("error %q does not say the solver exited", err)
	}
}

// The cache is consulted before anything is launched, so a fully cached list
// never starts a browser. Without that, a warm cache would still pay a launch.
func TestBatchSkipsTheBrowserWhenEverythingIsCached(t *testing.T) {
	o := batchOptions(t, batchStubJS, 2, "http://a.test:1", "http://b.test:2")
	if err := solveAcrossProxies(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("first solve: %v", err)
	}

	// Second run over the same cache, with a solver that fails if it runs at all.
	again := batchOptions(t, `process.exit(3);`, 2, "http://a.test:1", "http://b.test:2")
	again.solveCache = o.solveCache

	if err := solveAcrossProxies(context.Background(), again, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("a fully cached list still started the solver: %v", err)
	}
	if len(again.solveSeeds) != 2 {
		t.Fatalf("%d seeds from cache, want 2", len(again.solveSeeds))
	}
}

// The job list goes over stdin because it carries proxy credentials, and argv is
// world-readable in /proc for as long as the solve runs.
func TestBatchKeepsCredentialsOutOfArgv(t *testing.T) {
	const script = `let raw = "";
process.stdin.on("data", (d) => (raw += d));
process.stdin.on("end", () => {
  const job = JSON.parse(raw);
  for (const e of job.exits) {
    process.stdout.write(JSON.stringify({exit: e.id, status: "ok", user_agent: "UA-151",
      // argv is echoed back so the test can assert the secret is not in it.
      url: process.argv.join(" "), proxy: e.proxy,
      cookie_list: [{name: "cf_clearance", value: "v", domain: "site.test"}]}) + "\n");
  }
});
`
	o := batchOptions(t, script, 2,
		"http://user:hunter2@a.test:1", "http://user:hunter2@b.test:2")

	var argv string
	exits := []exit{{proxy: "http://user:hunter2@a.test:1", ip: "203.0.113.1"},
		{proxy: "http://user:hunter2@b.test:2", ip: "203.0.113.2"}}
	err := runSolverBatch(context.Background(), o, "https://site.test/", exits,
		func(_ exit, res *solveResult, err error) {
			if err == nil && res != nil {
				argv = res.URL
			}
		})
	if err != nil {
		t.Fatalf("runSolverBatch: %v", err)
	}
	if argv == "" {
		t.Fatal("the stub reported no argv")
	}
	if strings.Contains(argv, "hunter2") {
		t.Errorf("the proxy password reached argv: %q", argv)
	}
	// The batch flag has to be there, or the solver would read the job list as
	// a single-exit run and hang on stdin nobody drains.
	if !strings.Contains(argv, "--batch") {
		t.Errorf("argv %q does not carry --batch", argv)
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
	o := batchOptions(t, batchStubJS, 6,
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
