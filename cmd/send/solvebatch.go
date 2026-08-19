package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/solver"
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
// Results come back as each exit finishes rather than at the end, so a batch
// that runs for minutes reports as it goes — and a batch that dies halfway has
// already handed over the exits that solved. That used to be NDJSON on a pipe;
// in-process it is a callback, and the exit-that-was-never-reported case it
// guarded is now only reachable through cancellation.

// runSolverBatch solves every exit in one browser, calling onResult as each
// finishes.
//
// onResult is called in completion order and serialised, so it is free to print.
// An exit the solver never reported comes back as an error rather than as
// silence: the caller pairs cookies with proxies, and a missing pairing has to be
// a dropped exit rather than an absent one.
//
// A variable for the same reason runSolver is: the pairing this feeds is the
// part worth testing, and it does not need a browser to be wrong.
var runSolverBatch = solveBatchWithBrowser

func solveBatchWithBrowser(ctx context.Context, o *options, target string, exits []exit,
	onResult func(e exit, res *solveResult, err error)) error {

	if err := checkSolverDir(o); err != nil {
		return err
	}

	jobs := make([]solver.Exit, 0, len(exits))
	byID := make(map[string]exit, len(exits))
	for _, e := range exits {
		jobs = append(jobs, solver.Exit{ID: e.identity(), Proxy: e.proxy})
		byID[e.identity()] = e
	}
	batch, err := solver.NewBatch(jobs, o.solveParallel)
	if err != nil {
		return err
	}

	// The budget is per exit, and the exits run in rounds of `parallel`, so the
	// wall clock is that many budgets. Sizing this for a single one is how a
	// batch of more than -solve-parallel exits would be killed at the first
	// round boundary — and it would have looked like the target hanging. The
	// margin is so the last exit reports rather than being cancelled
	// mid-teardown.
	rounds := (len(exits) + batch.Parallel - 1) / batch.Parallel
	budget := time.Duration(rounds)*o.solveTimeout + 45*time.Second
	batchCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	// Results are delivered as each exit finishes rather than at the end. A
	// batch runs for minutes and this is the only progress there is; it is also
	// what keeps a batch that dies at exit 90 of 100 from taking the first 89
	// with it.
	seen := make(map[string]bool, len(exits))
	var mu sync.Mutex

	err = solver.SolveBatch(batchCtx, solverOptions(o, target), batch, func(r solver.BatchResult) {
		e, ok := byID[r.Exit.ID]
		if !ok {
			return
		}
		mu.Lock()
		if seen[r.Exit.ID] {
			mu.Unlock()
			return
		}
		seen[r.Exit.ID] = true
		mu.Unlock()

		if r.Result == nil || r.Result.Status == solver.StatusError {
			msg := "solve failed"
			if r.Result != nil && r.Result.Error != "" {
				msg = r.Result.Error
			}
			onResult(e, nil, fmt.Errorf("solver: %s", msg))
			return
		}
		res := fromSolverResult(r.Result)
		res.Exit = r.Exit.ID
		onResult(e, res, nil)
	})

	// Anything the batch never reported on. A run that was cancelled leaves
	// exits with no result at all — and the caller must hear about those as
	// failures rather than infer them from a short list.
	for _, e := range exits {
		if seen[e.identity()] {
			continue
		}
		reason := err
		if reason == nil {
			reason = batchExitError(batchCtx, nil)
		}
		onResult(e, nil, reason)
	}
	return nil
}

// batchExitError explains an exit that produced no result at all.
func batchExitError(ctx context.Context, cause error) error {
	switch {
	case ctx.Err() != nil:
		return errors.New("the batch ran out of time before this exit was reached")
	case cause != nil:
		return fmt.Errorf("the batch ended before reporting this exit: %w", cause)
	default:
		return errors.New("the batch ended without reporting this exit")
	}
}

// checkSolverDir reports the one way solving is usually not ready, in terms of
// what to do about it.
//
// It used to check for solver/index.js and its node_modules, because the solve
// was a Node process. There is no script and no npm tree any more — the solver
// is compiled into this binary — so the only prerequisite left is a browser to
// drive. The name is kept because -solve-isolate, the batch path and the tests
// all call it, and what it means has not changed: "can this run solve at all".
func checkSolverDir(o *options) error {
	if _, err := solver.CheckBrowser(o.chromePath); err != nil {
		return fmt.Errorf("-solve needs a browser to drive: %w", err)
	}
	return nil
}
