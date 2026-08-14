package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// echoProxyJS reports the exit it was told to solve through, and seeds a cookie
// naming it — which is what lets a fleet test assert that every session ended up
// with the cookie its own proxy earned rather than a neighbour's.
const echoProxyJS = `const p = process.env.SOLVER_PROXY || "";
process.stdout.write(JSON.stringify({
  status: "ok", url: "https://site.test/", user_agent: "UA-151", proxy: p,
  cookie_list: [{name: "cf_clearance", value: "for-" + p, domain: "site.test"}],
}));
`

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
	res, err := runSolver(context.Background(), o, "https://site.test/", "")
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
	_, err := runSolver(context.Background(), o, "https://site.test/", "")
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
	_, err := runSolver(context.Background(), solveOptions(dir), "https://site.test/", "")
	if err == nil || !strings.Contains(err.Error(), "npm install") {
		t.Fatalf("error = %v, want a message pointing at npm install", err)
	}
}

// cf_clearance is bound to the IP that earned it, so the exit has to reach the
// browser. Nothing else in the pipeline would notice if it stopped doing so.
func TestRunSolverPassesProxyThrough(t *testing.T) {
	o := solveOptions(stubSolverDir(t, echoProxyJS))
	const proxy = "http://user:pass@exit.test:8080"

	res, err := runSolver(context.Background(), o, "https://site.test/", proxy)
	if err != nil {
		t.Fatalf("runSolver: %v", err)
	}
	if res.Proxy != proxy {
		t.Errorf("solver saw SOLVER_PROXY=%q, want %q", res.Proxy, proxy)
	}
}

// A solve without a proxy must not inherit one from the environment: an exported
// SOLVER_PROXY would send a direct run through an exit it never asked for, and
// cache the cookie under the wrong key.
func TestRunSolverNoProxyMeansDirect(t *testing.T) {
	t.Setenv("SOLVER_PROXY", "http://stale.test:8080")
	o := solveOptions(stubSolverDir(t, echoProxyJS))

	res, err := runSolver(context.Background(), o, "https://site.test/", "")
	if err != nil {
		t.Fatalf("runSolver: %v", err)
	}
	if res.Proxy != "" {
		t.Errorf("solver saw SOLVER_PROXY=%q, want it unset", res.Proxy)
	}
}

// The solve and the replay have to ask for the same language. The solver had no
// way to know what the run would advertise, so it used whatever the box's locale
// produced — which on a localised image is not what gofire replays with.
func TestRunSolverPassesLanguageThrough(t *testing.T) {
	const stub = `process.stdout.write(JSON.stringify({status: "ok", user_agent: "UA-151",
  cookie_list: [], url: process.env.SOLVER_LANG || ""}));
`
	o := solveOptions(stubSolverDir(t, stub))

	// Unset, the run replays the library's default, so that is what the solve
	// has to advertise.
	res, err := runSolver(context.Background(), o, "https://site.test/", "")
	if err != nil {
		t.Fatalf("runSolver: %v", err)
	}
	if res.URL != gofire.DefaultAcceptLanguage {
		t.Errorf("solver saw SOLVER_LANG=%q, want the library default %q",
			res.URL, gofire.DefaultAcceptLanguage)
	}

	// -lang moves both halves together.
	o.lang = "tr-TR,tr;q=0.9"
	res, err = runSolver(context.Background(), o, "https://site.test/", "")
	if err != nil {
		t.Fatalf("runSolver: %v", err)
	}
	if res.URL != o.lang {
		t.Errorf("solver saw SOLVER_LANG=%q, want -lang %q", res.URL, o.lang)
	}
}

// The solver has always measured the Chromium it drives and printed it as
// chromium_major. Nothing read it, so the one binding that can be checked
// without a capture — the TLS fingerprint moving between Chrome majors — went
// unreported until a run started failing under load.
func TestChromiumDriftIsReported(t *testing.T) {
	pinned := chromeMajorFromUA(gofire.Chrome151UserAgent)
	if pinned == 0 {
		t.Fatal("no Chrome major in the pinned UA")
	}

	// The solver's own output has to reach the seed, or there is nothing to
	// compare in the first place.
	o := solveOptions(stubSolverDir(t, printJS(okSolve)))
	seed, err := solveOne(context.Background(), o, "https://site.test/", exit{})
	if err != nil {
		t.Fatalf("solveOne: %v", err)
	}
	if seed.chromiumMajor != 151 {
		t.Errorf("seed.chromiumMajor = %d, want the solver's 151", seed.chromiumMajor)
	}

	if got := stderrOf(func() { reportChromiumDrift(pinned - 10) }); !strings.Contains(got, "under load") {
		t.Errorf("a Chromium %d against a pin of %d produced no warning: %q", pinned-10, pinned, got)
	}
	if got := stderrOf(func() { reportChromiumDrift(pinned) }); got != "" {
		t.Errorf("a matching Chromium warned anyway: %q", got)
	}
	// 0 is "not reported" — an older solver, or a cache entry from before this
	// was recorded. Absence of a measurement is not evidence of drift.
	if got := stderrOf(func() { reportChromiumDrift(0) }); got != "" {
		t.Errorf("an unreported version warned: %q", got)
	}
}

func TestChromeMajorFromUA(t *testing.T) {
	if got := chromeMajorFromUA(gofire.Chrome151UserAgent); got != 151 {
		t.Errorf("pinned UA major = %d, want 151", got)
	}
	for _, ua := range []string{"", "Mozilla/5.0", "Chrome/", "Chrome/abc"} {
		if got := chromeMajorFromUA(ua); got != 0 {
			t.Errorf("chromeMajorFromUA(%q) = %d, want 0", ua, got)
		}
	}
}

// stderrOf captures what fn writes to stderr.
func stderrOf(fn func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		return "pipe: " + err.Error()
	}
	saved := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var buf strings.Builder
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	w.Close()
	os.Stderr = saved
	out := <-done
	r.Close()
	return out
}

// Credentials in a proxy list end up in whatever the run's stderr is piped to.
func TestRedactProxy(t *testing.T) {
	for raw, want := range map[string]string{
		"http://user:pass@exit.test:8080": "http://user:xxxxx@exit.test:8080",
		"socks5://exit.test:1080":         "socks5://exit.test:1080",
		"1.2.3.4:8080:user:pass":          "1.2.3.4:8080",
		"1.2.3.4:8080":                    "1.2.3.4:8080",
		"":                                "",
	} {
		if got := redactProxy(raw); got != want {
			t.Errorf("redactProxy(%q) = %q, want %q", raw, got, want)
		}
		if strings.Contains(redactProxy(raw), "pass") {
			t.Errorf("redactProxy(%q) leaked the password", raw)
		}
	}
}

// The clearance is seeded; Cloudflare's per-session bookkeeping beside it is
// not. __cf_bm is minted for the browser session that earned it and read back by
// the edge on the next request, so replaying it from this client hands the edge
// a token describing a session this connection is not.
func TestSolveAndSeedSeedsCookiesAndUA(t *testing.T) {
	o := solveOptions(stubSolverDir(t, printJS(okSolve)))
	if err := solveAndSeed(context.Background(), o, gofire.Chrome151, "https://site.test/"); err != nil {
		t.Fatalf("solveAndSeed: %v", err)
	}
	want := []string{"cf_clearance=abc"}
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
		{"timeout floor", []string{"-solve", "-solve-timeout", "1s", "https://site.test"}, "solve-timeout"},
		{"parallel floor", []string{"-solve", "-solve-parallel", "0", "https://site.test"}, "solve-parallel"},
		{"two proxy sources", []string{"-solve", "-proxy", "http://a.test:1",
			"-proxy-file", "p.txt", "https://site.test"}, "not both"},
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

// The exact header Chrome 151 produced when --accept-lang was handed a finished
// Accept-Language instead of the preference list it takes. It went out on the
// request that earns cf_clearance, and nothing noticed.
func TestMalformedLanguageIsCaught(t *testing.T) {
	tests := []struct {
		name, header string
		wantBad      bool
	}{
		{"what chrome 151 sent", "en-US,en;q=0.9,en;q=0.9;q=0.8", true},
		{"a doubled quality parameter", "en-US,en;q=0.9;q=0.8", true},
		{"a repeated tag", "tr-TR,tr;q=0.9,tr;q=0.8", true},
		{"chrome's own default", "en-US,en;q=0.9", false},
		{"a single tag", "en", false},
		{"three real languages", "en-US,fr;q=0.9,de;q=0.8", false},
		{"spaces after the commas", "en-US, en;q=0.9", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bad := malformedLanguage(tc.header)
			if (bad != "") != tc.wantBad {
				t.Errorf("malformedLanguage(%q) = %q, want malformed=%v", tc.header, bad, tc.wantBad)
			}
		})
	}
}

// A solve that earns a cookie and is then challenged anyway must not be
// reported as a plain 403 and a wall of interstitial HTML. Measured on a live
// zone, that outcome came from something no fingerprint work here could touch —
// and someone reading a 403 has no way to know it.
func TestRejectedClearanceIsExplained(t *testing.T) {
	challenge := []byte(`<html><head><title>Just a moment...</title></head>` +
		`<body><script>window._cf_chl_opt={cType:'managed'};</script></body></html>`)

	stderr := captureStderr(t, func() {
		reportRejectedClearance(
			&options{solve: true, solverDir: "solver"},
			"https://site.test",
			http.StatusForbidden,
			http.Header{"Cf-Mitigated": []string{"challenge"}},
			challenge,
		)
	})

	for _, want := range []string{
		"earned a cf_clearance", // says the solve worked
		"not a failed solve",    // and that this is not that
		"replay.js",             // names the one command that decides
		"https://site.test",     // with the target filled in
		"-proxy",                // and the answer when it is the address
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the explanation does not mention %q:\n%s", want, stderr)
		}
	}
}

// An ordinary response after a solve says nothing: the note is for the one
// outcome that is genuinely ambiguous, and printing it on a 200 would train
// people to ignore it.
func TestRejectedClearanceIsQuietWhenNothingWasRejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"the page arrived", 200, "<html><body>the real page</body></html>"},
		{"a plain refusal", 403, "<html><body>Forbidden</body></html>"},
		{"an ordinary error", 500, "<html><body>oops</body></html>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stderr := captureStderr(t, func() {
				reportRejectedClearance(&options{solve: true, solverDir: "solver"},
					"https://site.test", tc.status, http.Header{}, []byte(tc.body))
			})
			if stderr != "" {
				t.Errorf("said something about a clearance nothing rejected:\n%s", stderr)
			}
		})
	}
}

// The header the server reads and the page object the challenge's own script
// reads have to name the same languages. This repo has shipped both halves of
// that wrong — a shim asserting a list the browser was not asking for, and then
// its removal leaving the browser reporting one tag while the header advertised
// two — and neither time did anything say so.
func TestLanguageSplitIsReported(t *testing.T) {
	t.Run("silent when they agree", func(t *testing.T) {
		for _, tc := range []struct {
			header string
			page   []string
		}{
			{"en-US,en;q=0.9", []string{"en-US", "en"}},
			{"tr-TR,tr;q=0.9", []string{"tr-TR", "tr"}},
			{"en", []string{"en"}},
			// Nothing to compare against is not a disagreement.
			{"en-US,en;q=0.9", nil},
			{"", []string{"en-US", "en"}},
		} {
			stderr := captureStderr(t, func() { reportLanguageSplit(tc.header, tc.page) })
			if stderr != "" {
				t.Errorf("%q vs %v was reported as a split:\n%s", tc.header, tc.page, stderr)
			}
		}
	})

	t.Run("names both sides when they do not", func(t *testing.T) {
		// The exact shape of the regression: the header offers "en", the page
		// object does not list it.
		stderr := captureStderr(t, func() {
			reportLanguageSplit("en-US,en;q=0.9", []string{"en-US"})
		})
		for _, want := range []string{"en-US,en;q=0.9", "[en-US en]", "[en-US]", "setUserAgentOverride"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("the note does not mention %q:\n%s", want, stderr)
			}
		}
	})

	t.Run("order is part of the comparison", func(t *testing.T) {
		stderr := captureStderr(t, func() {
			reportLanguageSplit("en-US,en;q=0.9", []string{"en", "en-US"})
		})
		if stderr == "" {
			t.Error("the same tags in a different order were accepted as agreement")
		}
	})
}

func TestLanguageTags(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   []string
	}{
		{"en-US,en;q=0.9", []string{"en-US", "en"}},
		{"tr-TR,tr;q=0.9,en;q=0.8", []string{"tr-TR", "tr", "en"}},
		{" en-US , en ; q=0.9 ", []string{"en-US", "en"}},
		{"en", []string{"en"}},
		{"", nil},
	} {
		if got := languageTags(tc.header); !slices.Equal(got, tc.want) {
			t.Errorf("languageTags(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

// What the solve captures and what the client may replay are not the same set.
// The rule is about what each cookie is for — a token minted for one browser
// session is not a credential another client can present — and not about any
// measured effect on a challenge; see splitSolvedCookies for why that
// distinction is drawn so firmly.
func TestSplitSolvedCookies(t *testing.T) {
	jar := func(names ...string) []solvedCookie {
		out := make([]solvedCookie, 0, len(names))
		for _, n := range names {
			out = append(out, solvedCookie{Name: n, Value: "v"})
		}
		return out
	}
	names := func(cookies []solvedCookie) []string {
		var out []string
		for _, c := range cookies {
			out = append(out, c.Name)
		}
		return out
	}

	t.Run("the clearance and the site's own cookies travel", func(t *testing.T) {
		kept, dropped := splitSolvedCookies(
			jar("cf_clearance", "__cf_bm", "session_id", "cf_chl_rc_m", "__cf_chl_tk", "__cflb"), false)
		if want := []string{"cf_clearance", "session_id"}; !slices.Equal(names(kept), want) {
			t.Errorf("kept %v, want %v", names(kept), want)
		}
		if want := []string{"__cf_bm", "cf_chl_rc_m", "__cf_chl_tk", "__cflb"}; !slices.Equal(names(dropped), want) {
			t.Errorf("dropped %v, want %v", names(dropped), want)
		}
	})

	// cf_clearance shares its prefix with the challenge cookies being excluded,
	// so the order of the checks decides whether the whole feature works.
	t.Run("cf_clearance is not caught by the cf_chl prefix", func(t *testing.T) {
		kept, _ := splitSolvedCookies(jar("cf_clearance"), false)
		if len(kept) != 1 {
			t.Fatalf("the clearance itself was held back: %v", names(kept))
		}
	})

	// Bot Fight Mode issues no clearance, and there __cf_bm is not bookkeeping
	// beside a credential — it is the only thing the solve earned. Holding it
	// back would leave the run with nothing and no way to tell.
	t.Run("without a clearance there is nothing to hold it back for", func(t *testing.T) {
		kept, dropped := splitSolvedCookies(jar("__cf_bm", "session_id"), false)
		if want := []string{"__cf_bm", "session_id"}; !slices.Equal(names(kept), want) {
			t.Errorf("kept %v, want %v", names(kept), want)
		}
		if len(dropped) != 0 {
			t.Errorf("held back %v with no clearance to hold it back for", names(dropped))
		}
	})

	t.Run("-solve-all-cookies sends everything", func(t *testing.T) {
		kept, dropped := splitSolvedCookies(jar("cf_clearance", "__cf_bm"), true)
		if len(kept) != 2 || len(dropped) != 0 {
			t.Errorf("kept %v, dropped %v", names(kept), names(dropped))
		}
	})
}

// The report names the cookies and never their values: it goes to stderr, and
// stderr ends up in log files and pasted issue reports.
func TestCookieNamesCarryNoValues(t *testing.T) {
	got := cookieNames([]solvedCookie{
		{Name: "cf_clearance", Value: "secret-value"},
		{Name: "__cf_bm", Value: "another-secret"},
	})
	if want := "cf_clearance, __cf_bm"; got != want {
		t.Errorf("cookieNames = %q, want %q", got, want)
	}
	for _, secret := range []string{"secret-value", "another-secret"} {
		if strings.Contains(got, secret) {
			t.Errorf("the report leaked a cookie value: %q", got)
		}
	}
	if got := cookieNames(nil); got != "no cookies" {
		t.Errorf("an empty jar rendered as %q", got)
	}
}

// captureStderr collects what f writes to os.Stderr.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		io.Copy(&sb, r) //nolint:errcheck
		done <- sb.String()
	}()

	f()
	w.Close()
	os.Stderr = saved
	return <-done
}
