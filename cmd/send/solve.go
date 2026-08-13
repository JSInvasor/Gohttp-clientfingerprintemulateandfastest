package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// -solve earns a cf_clearance with the real browser in solver/ and seeds it
// into every session before the run starts.
//
// The three things Cloudflare binds that cookie to — User-Agent, JA3/JA4, and
// source IP — all have to survive the handover from the browser that earned it
// to the client that replays it:
//
//   - the UA comes back in the solver's output and is pinned onto the run,
//     rather than assumed to match.
//   - the TLS layer is why this only runs against the Chrome profile. The
//     solver drives a real Chromium; replaying its cookie from the Safari
//     profile presents a JA4 the cookie was never issued to.
//   - the IP is why the proxy is handed to the solver. Solving from this box and
//     replaying from an exit node fails exactly like a UA mismatch does, and
//     just as quietly. With -proxy-file that binding is per exit rather than per
//     run, which is what solvefleet.go is about.
//
// A mismatch in any of them does not fail loudly. It produces a cookie that
// works for the first request and dies under load, which is indistinguishable
// from the target simply blocking the client.

// minSolveTimeout is the smallest -solve-timeout worth accepting. Chromium
// under Xvfb takes several seconds to come up before the challenge is even
// requested.
const minSolveTimeout = 10 * time.Second

// defaultSolveTimeout is generous on purpose. Chromium under Xvfb takes ~20s to
// come up and that comes out of every attempt, so the old 75s left a managed
// challenge almost no time to actually solve in. Measured against a live UAM:
// 75s failed with no cookie, 150s+ solved on the first attempt in 71s. It is a
// ceiling, not a wait — a fast box finishes early.
const defaultSolveTimeout = 150 * time.Second

// solveResult is what solver/index.js prints.
type solveResult struct {
	Status     string         `json:"status"`
	Error      string         `json:"error"`
	URL        string         `json:"url"`
	UserAgent  string         `json:"user_agent"`
	Cookies    string         `json:"cookies"`
	CookieList []solvedCookie `json:"cookie_list"`
	DurationMS int64          `json:"duration_ms"`
	Attempts   int            `json:"attempts"`
	Chromium   string         `json:"chromium_version"`
	Proxy      string         `json:"proxy"`
	LaunchMS   int64          `json:"launch_ms"`
}

type solvedCookie struct {
	Name    string  `json:"name"`
	Value   string  `json:"value"`
	Domain  string  `json:"domain"`
	Expires float64 `json:"expires"`
}

// solveSeed is one solved identity: the cookies one exit earned, the UA they
// were issued to, and the proxy that has to replay them.
//
// A run with a single exit has one of these and it covers every session. A run
// with -proxy-file has one per exit, and a session may only ever use its own —
// the source IP is part of what the cookie is bound to, so the pairing has to
// hold all the way into the session pool.
type solveSeed struct {
	proxy     string
	userAgent string
	cookies   []string
}

// solveLog serialises the progress lines. Exits solve in parallel, and a
// message assembled from several writes would interleave with another exit's.
var solveLog sync.Mutex

// logSolve prints a message tagged with the exit it came from. Credentials are
// stripped: a proxy list is usually user:pass@host, and a run's stderr ends up
// in terminals, log files and pasted issue reports.
//
// Every line gets the tag, not just the first. A warning under a bare margin
// belongs to whichever exit the reader last saw a tag for, which during a
// parallel solve is not the one that raised it.
func logSolve(proxy, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if proxy != "" {
		tag := redactProxy(proxy) + ": "
		msg = tag + strings.ReplaceAll(msg, "\n", "\n"+tag)
	}
	solveLog.Lock()
	defer solveLog.Unlock()
	fmt.Fprintln(os.Stderr, msg)
}

// redactProxy renders a proxy URL without its password.
func redactProxy(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Redacted()
	}
	// The host:port:user:pass shorthand is not a URL, so url.Parse leaves it
	// alone rather than redacting it. Cut it by shape instead of printing the
	// credentials.
	if parts := strings.SplitN(raw, ":", 4); len(parts) == 4 {
		return parts[0] + ":" + parts[1]
	}
	return raw
}

// clearance returns the cf_clearance cookie, if the solve produced one.
func (r *solveResult) clearance() (solvedCookie, bool) {
	for _, c := range r.CookieList {
		if c.Name == "cf_clearance" {
			return c, true
		}
	}
	return solvedCookie{}, false
}

// runSolver shells out to solver/index.js and returns what it solved.
//
// It is a separate process rather than a library call because the solve needs a
// real browser: the whole point is that a genuine Chromium TLS handshake and JS
// runtime answer the challenge, which is precisely what this client cannot do.
//
// The exit is a parameter rather than a field of o because a -proxy-file run
// calls this once per proxy, concurrently. One process solves through one exit;
// the browser has a single --proxy-server and there is nothing to rotate inside
// it.
func runSolver(ctx context.Context, o *options, target, proxy string) (*solveResult, error) {
	script := filepath.Join(o.solverDir, "index.js")
	if _, err := os.Stat(script); err != nil {
		return nil, fmt.Errorf("%s not found: %w", script, err)
	}
	// index.js imports puppeteer-real-browser, so a missing install fails with a
	// Node module-resolution error that says nothing about how to fix it.
	if _, err := os.Stat(filepath.Join(o.solverDir, "node_modules")); err != nil {
		return nil, fmt.Errorf("%s/node_modules not found — run `npm install` in %s first",
			o.solverDir, o.solverDir)
	}

	// The solver gets its own budget plus a margin: it has its own watchdog at
	// timeout+30s, and killing it from here first would leave the Chromium tree
	// to its exit handlers rather than letting it report what it found.
	solveCtx, cancel := context.WithTimeout(ctx, o.solveTimeout+45*time.Second)
	defer cancel()

	seconds := int(o.solveTimeout.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	cmd := exec.CommandContext(solveCtx, "node", script, target, strconv.Itoa(seconds))
	cmd.Stderr = os.Stderr // puppeteer's launch diagnostics are worth seeing

	// The exit is set on the environment rather than inherited from it. An
	// exported SOLVER_PROXY used to reach the browser on its own, so a solve
	// this run believed was direct went out through an exit it never asked for —
	// and the cookie was cached under "direct" and replayed from this box, which
	// is the silent 403 the whole file is about.
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "SOLVER_PROXY=")
	})
	if proxy != "" {
		env = append(env, "SOLVER_PROXY="+proxy)
	}
	cmd.Env = env

	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("node not found in PATH; -solve needs Node.js")
		}
		return nil, fmt.Errorf("run %s: %w", script, err)
	}

	res, perr := parseSolveOutput(out)
	if perr != nil {
		return nil, fmt.Errorf("parse %s output: %w", script, perr)
	}
	if res.Status == "error" {
		msg := res.Error
		if msg == "" {
			msg = "solve failed"
		}
		return nil, fmt.Errorf("solver: %s", msg)
	}
	return res, nil
}

// parseSolveOutput extracts the result object from the script's stdout.
//
// index.js prints one JSON object and nothing else, so the whole output
// normally parses directly. The line fallback exists because a dependency deep
// in puppeteer's tree can print a banner first, and a solve that worked should
// not be thrown away over a warning. Scanning backwards means the result —
// always last — wins over any preamble.
func parseSolveOutput(out []byte) (*solveResult, error) {
	if res, err := decodeSolve(out); err == nil {
		return res, nil
	}
	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if res, err := decodeSolve([]byte(line)); err == nil {
			return res, nil
		}
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, errors.New("the solver produced no output")
	}
	return nil, fmt.Errorf("no JSON object in %q", truncate(strings.TrimSpace(string(out)), 200))
}

// decodeSolve unmarshals one result object, rejecting anything without a status
// so a stray JSON line from a dependency is not mistaken for the result.
func decodeSolve(b []byte) (*solveResult, error) {
	var res solveResult
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	if res.Status == "" {
		return nil, errors.New("JSON object has no status field")
	}
	return &res, nil
}

// solveAndSeed earns one identity for the whole run and folds it into the
// options the session pool is about to be built from, so the solved cookies and
// UA arrive through the same paths -cookie and -ua already use.
//
// This is the single-exit path: no proxy at all, or one -proxy every session
// shares. A -proxy-file run goes through solveAcrossProxies instead, because
// there the identity is per session rather than per run.
func solveAndSeed(ctx context.Context, o *options, target string) error {
	seed, err := solveOne(ctx, o, target, o.proxy)
	if err != nil {
		return err
	}
	reportUADrift(seed.userAgent)

	// The UA the cookie was issued to wins over the profile's default, but not
	// over an explicit -ua: an override the user typed is a deliberate choice,
	// and silently replacing it would hide the mismatch rather than surface it.
	switch {
	case o.userAgent == "":
		o.userAgent = seed.userAgent
	case seed.userAgent != "" && o.userAgent != seed.userAgent:
		fmt.Fprintf(os.Stderr, "warning: -ua differs from the UA the cookie was issued to.\n"+
			"  issued to %s\n  replaying %s\n", seed.userAgent, o.userAgent)
	}

	o.cookies = append(o.cookies, seed.cookies...)
	return nil
}

// solveOne earns the identity for one exit — or reuses a cached one — and
// returns it without touching the run's options.
//
// It is the unit both paths are built from, so a single-exit run and one exit of
// a fleet cost, cache and report the same thing. It holds no shared state:
// solveAcrossProxies calls it from several goroutines at once.
func solveOne(ctx context.Context, o *options, target, proxy string) (*solveSeed, error) {
	// A cookie that is still valid is worth more than a fresh one: it costs
	// nothing and it is the same cookie. Most of a solve is the edge's own
	// challenge, so this is the only real answer to "the solve takes too long".
	if !o.solveRefresh {
		if e := loadSolveCache(o.solveCache, target, proxy, o.solveMaxAge); e != nil {
			return seedFromCache(proxy, e), nil
		}
	}

	where := "direct"
	if proxy != "" {
		where = "via " + redactProxy(proxy)
	}
	logSolve(proxy, "solving %s with the browser in %s/ (%s, up to %s)",
		target, o.solverDir, where, o.solveTimeout)

	res, err := runSolver(ctx, o, target, proxy)
	if err != nil {
		return nil, err
	}

	cf, gotClearance := res.clearance()
	// Assembled and printed as one write. The exits of a -proxy-file run solve
	// in parallel, and a report built from four Fprintf calls arrives
	// interleaved with three other exits' — which is how a warning ends up
	// under the wrong proxy.
	report := fmt.Sprintf("solved in %s, %d attempt(s), %d cookie(s), chromium %s",
		round(time.Duration(res.DurationMS)*time.Millisecond), res.Attempts,
		len(res.CookieList), res.Chromium)

	// The budget is what the browser startup does not eat. A challenge with a
	// Turnstile widget needs 15-30s of it, and a launch on a small VPS takes
	// 20s of every attempt — which is how a run fails with no cookie at all
	// while looking like the target simply refused.
	if launch := time.Duration(res.LaunchMS) * time.Millisecond; launch > 0 {
		if solving := o.solveTimeout - launch*time.Duration(max(res.Attempts, 1)); solving < 20*time.Second {
			report += fmt.Sprintf("\nnote: browser startup took %s of the %s budget — "+
				"raise -solve-timeout if the challenge does not clear", round(launch), o.solveTimeout)
		}
	}

	switch {
	case gotClearance:
		report += fmt.Sprintf("\ncf_clearance issued for %s", cf.Domain)
	default:
		// Worth continuing: a site behind Bot Fight Mode alone never issues a
		// clearance cookie, and the __cf_bm the solve did earn is still the
		// thing that carries the session.
		report += "\nwarning: no cf_clearance — the target may not use UAM, " +
			"or the challenge was not solved. Seeding what was captured anyway."
	}
	logSolve(proxy, "%s", report)

	seed := &solveSeed{proxy: proxy, userAgent: res.UserAgent}
	for _, c := range res.CookieList {
		seed.cookies = append(seed.cookies, c.Name+"="+c.Value)
	}
	if gotClearance {
		storeSolveCache(o.solveCache, target, proxy, res)
	}
	return seed, nil
}

// reportUADrift compares the UA a solve came back with against the one this
// client pins for the platform the solver runs on, and says so rather than
// silently living with the difference.
//
// The comparison is against the pinned UA for that platform, not the profile's
// default: the solver claims the OS it actually has — a Linux VPS stays Linux —
// and Sec-Ch-Ua-Platform follows the UA, so that difference is expected and
// already handled. A difference in the browser identity is not.
//
// A fleet solve calls this once rather than once per exit. Every exit drives the
// same local Chromium, so drift is a property of this box, and repeating it per
// proxy would bury the per-exit results under copies of one warning.
func reportUADrift(ua string) {
	if ua == "" {
		return
	}
	platform := gofire.PlatformFromUserAgent(ua)
	switch want, ok := gofire.ChromeUserAgentFor(platform); {
	case !ok:
		fmt.Fprintf(os.Stderr, "warning: the solver runs on %q, which this client has no "+
			"pinned Chrome UA for — replaying its UA verbatim\n", platform)
	case want != ua:
		fmt.Fprintf(os.Stderr, "warning: solver UA and the pinned Chrome UA for %s differ —\n"+
			"  solver %s\n  pinned %s\n"+
			"  run `go run ./cmd/fpcheck -via-chromium -profile chrome` to see what else drifted\n",
			platform, ua, want)
	}
}

// truncate shortens s for an error message.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
