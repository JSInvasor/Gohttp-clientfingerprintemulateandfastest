package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
//   - the IP is why -proxy is handed to the solver. Solving from this box and
//     replaying from an exit node fails exactly like a UA mismatch does, and
//     just as quietly.
//
// A mismatch in any of them does not fail loudly. It produces a cookie that
// works for the first request and dies under load, which is indistinguishable
// from the target simply blocking the client.

// minSolveTimeout is the smallest -solve-timeout worth accepting. Chromium
// under Xvfb takes several seconds to come up before the challenge is even
// requested.
const minSolveTimeout = 10 * time.Second

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
}

type solvedCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
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
func runSolver(ctx context.Context, o *options, target string) (*solveResult, error) {
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
	if o.proxy != "" {
		cmd.Env = append(os.Environ(), "SOLVER_PROXY="+o.proxy)
	}

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

// solveAndSeed runs the solver and folds the result into the options the
// session pool is about to be built from, so the solved cookies and UA arrive
// through the same paths -cookie and -ua already use.
func solveAndSeed(ctx context.Context, o *options, profile gofire.BrowserProfile, target string) error {
	where := "direct"
	if o.proxy != "" {
		where = "via " + o.proxy
	}
	fmt.Fprintf(os.Stderr, "solving %s with the browser in %s/ (%s, up to %s)\n",
		target, o.solverDir, where, o.solveTimeout)

	res, err := runSolver(ctx, o, target)
	if err != nil {
		return err
	}

	cf, gotClearance := res.clearance()
	fmt.Fprintf(os.Stderr, "solved in %s, %d attempt(s), %d cookie(s), chromium %s\n",
		round(time.Duration(res.DurationMS)*time.Millisecond), res.Attempts,
		len(res.CookieList), res.Chromium)

	switch {
	case gotClearance:
		fmt.Fprintf(os.Stderr, "cf_clearance issued for %s\n", cf.Domain)
	default:
		// Worth continuing: a site behind Bot Fight Mode alone never issues a
		// clearance cookie, and the __cf_bm the solve did earn is still the
		// thing that carries the session.
		fmt.Fprintln(os.Stderr, "warning: no cf_clearance — the target may not use UAM, "+
			"or the challenge was not solved. Seeding what was captured anyway.")
	}

	// The UA the cookie was issued to wins over the profile's default, but not
	// over an explicit -ua: an override the user typed is a deliberate choice,
	// and silently replacing it would hide the mismatch rather than surface it.
	switch {
	case o.userAgent == "":
		o.userAgent = res.UserAgent
	case o.userAgent != res.UserAgent:
		fmt.Fprintf(os.Stderr, "warning: -ua differs from the UA the cookie was issued to.\n"+
			"  issued to %s\n  replaying %s\n", res.UserAgent, o.userAgent)
	}

	// Report drift rather than silently living with it. The comparison is
	// against the pinned UA for the platform the solver runs on, not the
	// profile's default: the solver claims the OS it actually has — a Linux VPS
	// stays Linux — and Sec-Ch-Ua-Platform follows the UA, so that difference is
	// expected and already handled. A difference in the browser identity is not.
	if res.UserAgent != "" {
		platform := gofire.PlatformFromUserAgent(res.UserAgent)
		switch want, ok := gofire.ChromeUserAgentFor(platform); {
		case !ok:
			fmt.Fprintf(os.Stderr, "warning: the solver runs on %q, which this client has no "+
				"pinned Chrome UA for — replaying its UA verbatim\n", platform)
		case want != res.UserAgent:
			fmt.Fprintf(os.Stderr, "warning: solver UA and the pinned Chrome UA for %s differ —\n"+
				"  solver %s\n  pinned %s\n"+
				"  run `go run ./cmd/fpcheck -via-chromium -profile chrome` to see what else drifted\n",
				platform, res.UserAgent, want)
		}
	}

	for _, c := range res.CookieList {
		o.cookies = append(o.cookies, c.Name+"="+c.Value)
	}
	return nil
}

// truncate shortens s for an error message.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
