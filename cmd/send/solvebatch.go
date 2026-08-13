package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// One browser for the whole list instead of one per exit.
//
// A solve is a browser launch plus a challenge, and only the second of those is
// unavoidable. Chromium under Xvfb takes ~20s to come up on the kind of box this
// runs on, and paying that per exit is most of an hour's startup across a
// hundred of them — for a browser that differs from the last one only in which
// proxy it dials.
//
// Chrome takes a proxy per BrowserContext (Target.createBrowserContext), not
// only on the command line, so one browser can serve every exit: a context each,
// with its own cookie jar, its own storage and its own egress. Measured against
// this repo's own solver with a real Chromium, the launch that cost 612ms per
// exit becomes 102-192ms of context creation — the same arithmetic that is 20s
// against 0.2s on a small VPS.
//
// It also changes what -solve-parallel costs. Four at a time used to mean four
// Chromiums resident at once, which is what kept the default at 2; four contexts
// in one browser is four tabs.
//
// Results stream back as NDJSON, one line per exit as it finishes, so a batch
// that runs for minutes reports as it goes rather than at the end — and a batch
// that dies halfway has already handed over the exits that solved.

// solverJob is the batch the solver reads from stdin.
//
// stdin rather than argv or the environment because these carry proxy
// credentials, and /proc/<pid>/cmdline is world-readable for as long as the
// solve runs. See solver/jobs.js.
type solverJob struct {
	Exits    []solverJobExit `json:"exits"`
	Parallel int             `json:"parallel"`
}

type solverJobExit struct {
	ID    string `json:"id"`
	Proxy string `json:"proxy"`
}

// runSolverBatch solves every exit in one browser, calling onResult as each
// finishes.
//
// onResult is called from this goroutine, in completion order, so it is free to
// print. An exit the solver never reported comes back as an error rather than
// as silence: the caller pairs cookies with proxies, and a missing pairing has
// to be a dropped exit rather than an absent one.
func runSolverBatch(ctx context.Context, o *options, target string, exits []exit,
	onResult func(e exit, res *solveResult, err error)) error {

	script := filepath.Join(o.solverDir, "index.js")
	if err := checkSolverDir(o); err != nil {
		return err
	}

	parallel := min(o.solveParallel, len(exits))
	if parallel < 1 {
		parallel = 1
	}
	job := solverJob{Parallel: parallel}
	for _, e := range exits {
		job.Exits = append(job.Exits, solverJobExit{ID: e.identity(), Proxy: e.proxy})
	}
	payload, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("encode job list: %w", err)
	}

	// The budget is per exit, and the exits run in rounds of `parallel`, so the
	// wall clock is that many budgets. Sizing this for a single one is how a
	// batch of more than -solve-parallel exits would be killed at the first
	// round boundary — and it would have looked like the target hanging. The
	// solver arms its own watchdog the same way; the margin is so it reports
	// first rather than being killed mid-sentence.
	rounds := (len(exits) + parallel - 1) / parallel
	budget := time.Duration(rounds)*o.solveTimeout + 45*time.Second
	batchCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	seconds := max(int(o.solveTimeout.Seconds()), 1)
	cmd := exec.CommandContext(batchCtx, "node", script, target, strconv.Itoa(seconds), "--batch")
	cmd.Stderr = os.Stderr
	cmd.Stdin = strings.NewReader(string(payload))
	cmd.Env = solverEnv("", acceptLanguage(o))

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("solver stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("node not found in PATH; -solve needs Node.js")
		}
		return fmt.Errorf("run %s: %w", script, err)
	}

	byID := make(map[string]exit, len(exits))
	for _, e := range exits {
		byID[e.identity()] = e
	}
	seen := make(map[string]bool, len(exits))

	// Read as they land rather than after the process exits. A batch runs for
	// minutes and this is the only progress there is; it is also what keeps a
	// solver that dies at exit 90 of 100 from taking the first 89 with it.
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var lastErr error
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue // a dependency's banner, not a result
		}
		res, err := decodeSolve([]byte(line))
		if err != nil {
			continue
		}
		if res.Exit == "" {
			// A statusful line with no exit is the solver reporting about the
			// batch itself — a fatal error before any exit ran.
			if res.Status == "error" && res.Error != "" {
				lastErr = fmt.Errorf("solver: %s", res.Error)
			}
			continue
		}
		e, ok := byID[res.Exit]
		if !ok || seen[res.Exit] {
			continue
		}
		seen[res.Exit] = true
		if res.Status == "error" {
			msg := res.Error
			if msg == "" {
				msg = "solve failed"
			}
			onResult(e, nil, fmt.Errorf("solver: %s", msg))
			continue
		}
		onResult(e, res, nil)
	}

	waitErr := cmd.Wait()

	// Anything the solver never reported on. A batch that was killed, or that
	// died partway, leaves exits with no line at all — and the caller must hear
	// about those as failures rather than infer them from a short list.
	for _, e := range exits {
		if seen[e.identity()] {
			continue
		}
		err := lastErr
		if err == nil {
			err = batchExitError(batchCtx, waitErr)
		}
		onResult(e, nil, err)
	}
	return nil
}

// batchExitError explains an exit that produced no result at all.
func batchExitError(ctx context.Context, waitErr error) error {
	switch {
	case ctx.Err() != nil:
		return errors.New("the batch ran out of time before this exit was reached")
	case waitErr != nil:
		return fmt.Errorf("the solver exited before reporting this exit: %w", waitErr)
	default:
		return errors.New("the solver exited without reporting this exit")
	}
}

// checkSolverDir reports the two ways solver/ is usually not ready, in terms of
// what to do about it.
func checkSolverDir(o *options) error {
	script := filepath.Join(o.solverDir, "index.js")
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("%s not found: %w", script, err)
	}
	// index.js imports puppeteer-real-browser, so a missing install fails with a
	// Node module-resolution error that says nothing about how to fix it.
	if _, err := os.Stat(filepath.Join(o.solverDir, "node_modules")); err != nil {
		return fmt.Errorf("%s/node_modules not found — run `npm install` in %s first",
			o.solverDir, o.solverDir)
	}
	return nil
}

// solverEnv builds the child environment, setting the solver's identity rather
// than inheriting it.
//
// An exported SOLVER_PROXY used to reach the browser on its own, so a solve this
// run believed was direct went out through an exit it never asked for — and the
// cookie was cached under "direct" and replayed from this box, which is the
// silent 403 all of this exists to prevent.
func solverEnv(proxy, lang string) []string {
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "SOLVER_PROXY=") || strings.HasPrefix(kv, "SOLVER_LANG=")
	})
	if proxy != "" {
		env = append(env, "SOLVER_PROXY="+proxy)
	}
	return append(env, "SOLVER_LANG="+lang)
}
