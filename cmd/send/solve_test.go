package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// stubSolverDir writes an index.js that prints script verbatim, plus the
// node_modules directory runSolver checks for.
//
// Stubbing the script rather than launching a real browser is deliberate: this
// exercises the part that can actually be wrong in CI — process invocation,
// environment passthrough, output parsing, error propagation and the seeding
// that follows — without needing Chromium, a display, or network. Whether a
// real challenge is solvable is not something a test can assert.
func stubSolverDir(t *testing.T, script string) string {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not in PATH")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(script), 0o644); err != nil {
		t.Fatalf("write index.js: %v", err)
	}
	return dir
}

// printJS is a stub body that writes out and nothing else.
func printJS(out string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`, "\r", `\r`)
	return "process.stdout.write('" + r.Replace(out) + "');\n"
}

func solveOptions(dir string) *options {
	return &options{solverDir: dir, solveTimeout: 30 * time.Second}
}

const okSolve = `{"status":"ok","url":"https://site.test/","user_agent":"UA-151",` +
	`"cookies":"cf_clearance=abc; __cf_bm=xyz",` +
	`"cookie_list":[{"name":"cf_clearance","value":"abc","domain":"site.test"},` +
	`{"name":"__cf_bm","value":"xyz","domain":"site.test"}],` +
	`"duration_ms":8500,"attempts":1,"chromium_version":"Chrome/151.0.0.0","chromium_major":151,"proxy":""}`

func TestParseSolveOutputCleanLine(t *testing.T) {
	res, err := parseSolveOutput([]byte(okSolve))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Status != "ok" || res.UserAgent != "UA-151" || len(res.CookieList) != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

// A dependency in puppeteer's tree can print a deprecation banner before the
// result. A solve that worked must not be discarded over a warning.
func TestParseSolveOutputIgnoresPreamble(t *testing.T) {
	noisy := "(node:1) Warning: something deprecated\n{\"not\":\"ours\"}\n" + okSolve + "\n"
	res, err := parseSolveOutput([]byte(noisy))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Status != "ok" {
		t.Fatalf("status = %q, want ok", res.Status)
	}
}

func TestParseSolveOutputRejectsJunk(t *testing.T) {
	if _, err := parseSolveOutput(nil); err == nil {
		t.Error("empty output parsed without error")
	}
	if _, err := parseSolveOutput([]byte("chromium failed to start\n")); err == nil {
		t.Error("non-JSON output parsed without error")
	}
	// A JSON object with no status is a stray line from a dependency, not a result.
	if _, err := parseSolveOutput([]byte(`{"hello":"world"}`)); err == nil {
		t.Error("statusless JSON parsed without error")
	}
}

func TestRunSolverOK(t *testing.T) {
	o := solveOptions(stubSolverDir(t, printJS(okSolve)))
	res, err := runSolver(context.Background(), o, "https://site.test/")
	if err != nil {
		t.Fatalf("runSolver: %v", err)
	}
	if cf, ok := res.clearance(); !ok || cf.Value != "abc" {
		t.Fatalf("clearance() = %+v, %v", cf, ok)
	}
}

// A solver that reports an error must fail the run rather than letting it start
// against a target it never got past.
func TestRunSolverPropagatesError(t *testing.T) {
	o := solveOptions(stubSolverDir(t, printJS(`{"status":"error","error":"watchdog timeout"}`)))
	_, err := runSolver(context.Background(), o, "https://site.test/")
	if err == nil {
		t.Fatal("a solver error did not fail the run")
	}
	if !strings.Contains(err.Error(), "watchdog timeout") {
		t.Errorf("error %q does not carry the solver's message", err)
	}
}

// The missing-install case is the one a first-time user hits, and Node's own
// module-resolution error says nothing about how to fix it.
func TestRunSolverMissingNodeModules(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not in PATH")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("//\n"), 0o644); err != nil {
		t.Fatalf("write index.js: %v", err)
	}
	_, err := runSolver(context.Background(), solveOptions(dir), "https://site.test/")
	if err == nil || !strings.Contains(err.Error(), "npm install") {
		t.Fatalf("error = %v, want a message pointing at npm install", err)
	}
}

// cf_clearance is bound to the IP that earned it, so -proxy has to reach the
// browser. Nothing else in the pipeline would notice if it stopped doing so.
func TestRunSolverPassesProxyThrough(t *testing.T) {
	stub := "process.stdout.write(JSON.stringify({status:'ok',user_agent:'UA-151'," +
		"cookie_list:[],proxy:process.env.SOLVER_PROXY||''}));\n"
	o := solveOptions(stubSolverDir(t, stub))
	o.proxy = "http://user:pass@exit.test:8080"

	res, err := runSolver(context.Background(), o, "https://site.test/")
	if err != nil {
		t.Fatalf("runSolver: %v", err)
	}
	if res.Proxy != o.proxy {
		t.Errorf("solver saw SOLVER_PROXY=%q, want %q", res.Proxy, o.proxy)
	}
}

func TestSolveAndSeedSeedsCookiesAndUA(t *testing.T) {
	o := solveOptions(stubSolverDir(t, printJS(okSolve)))
	if err := solveAndSeed(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAndSeed: %v", err)
	}
	want := []string{"cf_clearance=abc", "__cf_bm=xyz"}
	if len(o.cookies) != len(want) {
		t.Fatalf("cookies = %v, want %v", o.cookies, want)
	}
	for i, c := range want {
		if o.cookies[i] != c {
			t.Errorf("cookie %d = %q, want %q", i, o.cookies[i], c)
		}
	}
	// The UA the cookie was issued to has to be the UA that replays it.
	if o.userAgent != "UA-151" {
		t.Errorf("userAgent = %q, want the solver's UA", o.userAgent)
	}
}

// An explicit -ua is a deliberate choice. Overwriting it would hide the
// mismatch instead of surfacing it.
func TestSolveAndSeedKeepsExplicitUA(t *testing.T) {
	o := solveOptions(stubSolverDir(t, printJS(okSolve)))
	o.userAgent = "mine"
	if err := solveAndSeed(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAndSeed: %v", err)
	}
	if o.userAgent != "mine" {
		t.Errorf("userAgent = %q, want the explicit override to survive", o.userAgent)
	}
}

// Base64 cookie values contain '=' and padding. newSession splits on the first
// one, so the value has to survive the round trip intact.
func TestSolveAndSeedPreservesValuesContainingEquals(t *testing.T) {
	const padded = `{"status":"ok","user_agent":"UA-151","cookie_list":` +
		`[{"name":"cf_clearance","value":"a=b==","domain":"site.test"}]}`
	o := solveOptions(stubSolverDir(t, printJS(padded)))
	if err := solveAndSeed(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAndSeed: %v", err)
	}
	if len(o.cookies) != 1 || o.cookies[0] != "cf_clearance=a=b==" {
		t.Fatalf("cookies = %v, want the value kept whole", o.cookies)
	}
	name, value, _ := strings.Cut(o.cookies[0], "=")
	if name != "cf_clearance" || value != "a=b==" {
		t.Errorf("round trip gave %q = %q", name, value)
	}
}

// Bot Fight Mode never issues a clearance cookie, so a solve without one still
// carries a usable __cf_bm and must not abort the run.
func TestSolveAndSeedContinuesWithoutClearance(t *testing.T) {
	const noClearance = `{"status":"no_clearance","user_agent":"UA-151","cookie_list":` +
		`[{"name":"__cf_bm","value":"xyz","domain":"site.test"}]}`
	o := solveOptions(stubSolverDir(t, printJS(noClearance)))
	if err := solveAndSeed(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("no_clearance aborted the run: %v", err)
	}
	if len(o.cookies) != 1 || o.cookies[0] != "__cf_bm=xyz" {
		t.Fatalf("cookies = %v, want the captured __cf_bm", o.cookies)
	}
}

func TestSolveFlagValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"rotator", []string{"-solve", "-proxy-file", "p.txt", "https://site.test"}, "-proxy-file"},
		{"timeout floor", []string{"-solve", "-solve-timeout", "1s", "https://site.test"}, "solve-timeout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseFlags(tc.args)
			if err == nil {
				t.Fatalf("args %v were accepted", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// splitArgs has to know -solve takes no value. A bool missing from its
// boolFlags map swallows the argument after it, so `send -solve URL` would
// consume the URL and then report that no URL was given.
func TestSolveDoesNotSwallowTheURL(t *testing.T) {
	for _, args := range [][]string{
		{"-solve", "https://site.test"},
		{"-solve", "https://site.test", "30s", "100"},
		{"https://site.test", "-solve"},
		{"-solve", "-p", "chrome", "https://site.test"},
	} {
		o, target, err := parseFlags(args)
		if err != nil {
			t.Errorf("args %v: %v", args, err)
			continue
		}
		if target != "https://site.test" {
			t.Errorf("args %v: target = %q, want https://site.test", args, target)
		}
		if !o.solve {
			t.Errorf("args %v: -solve was not set", args)
		}
	}
}

// The positional dials still have to arrive intact with -solve in front of
// them, since that is the combination the usage text shows.
func TestSolveWithPositionalLoadShape(t *testing.T) {
	o, target, err := parseFlags([]string{"-solve", "site.test", "30s", "100", "8", "500"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if target != "https://site.test" {
		t.Errorf("target = %q", target)
	}
	if o.duration != 30*time.Second || o.concurrency != 100 || o.sessions != 8 || o.rate != 500 {
		t.Errorf("duration=%s threads=%d clients=%d rate=%d",
			o.duration, o.concurrency, o.sessions, o.rate)
	}
	if !o.solve {
		t.Error("-solve was not set")
	}
}

// -solve implies the Chrome profile, because the cookie is earned by a real
// Chromium — but only when the user did not pick a profile themselves.
func TestSolveDefaultsToChromeProfile(t *testing.T) {
	o, _, err := parseFlags([]string{"-solve", "https://site.test"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if o.profile != "chrome" {
		t.Errorf("profile = %q, want chrome", o.profile)
	}

	o, _, err = parseFlags([]string{"-solve", "-p", "safari", "https://site.test"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if o.profile != "safari" {
		t.Errorf("profile = %q, want the explicit safari to survive so run() can reject it", o.profile)
	}
}
