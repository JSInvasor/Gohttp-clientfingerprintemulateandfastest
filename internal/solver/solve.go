package solver

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/cdp"
)

// maxAttempts is how many times one exit is tried.
//
// Two, because many Cloudflare protections rotate the challenge after a
// soft-fail: a fresh context often gets a different variant and succeeds where
// the first did not. A third has never been observed to help.
const maxAttempts = 2

// DefaultTimeout is one exit's whole share of the clock.
//
// 75 was too small on a real box. Chromium under Xvfb takes ~20s to come up, the
// budget is split across two attempts, and the launch is charged against each —
// so a 75s budget left one attempt 25s of solving and the other 9s, and a
// managed challenge with a Turnstile widget needs 15-30s. Measured against a live
// UAM: 75s failed with no cookie at all, 180s solved on the first attempt in 71s.
// This is the value that works unattended; a fast machine simply finishes early,
// since the budget is a ceiling and not a wait.
const DefaultTimeout = 150 * time.Second

// Options is one solve run.
type Options struct {
	// Target is the URL to earn a clearance for.
	Target string
	// Timeout is each exit's budget. Zero means DefaultTimeout.
	Timeout time.Duration
	// Profile is the identity to solve as. The zero value means DefaultProfile.
	Profile *Profile
	// Headless runs without a display. The default is headful under Xvfb.
	Headless bool
	// ExecPath overrides browser discovery.
	ExecPath string
	// Stderr receives the browser's own diagnostics. nil discards them.
	Stderr *os.File
}

func (o Options) launcher() Launcher {
	p := DefaultProfile()
	if o.Profile != nil {
		p = *o.Profile
	}
	return Launcher{Profile: p, Headless: o.Headless, ExecPath: o.ExecPath, Stderr: o.Stderr}
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

// Solve earns a clearance for one exit, through its own browser.
//
// proxy may be empty for a direct solve. The returned Result is never nil unless
// err is: a run that failed still reports what it collected, because on a zone
// with no UAM the __cf_bm the challenge page set is the whole of what a solve can
// produce.
func Solve(ctx context.Context, o Options, proxy string) (*Result, error) {
	parsed, err := ParseProxy(proxy)
	if err != nil {
		return nil, err
	}
	l := o.launcher()
	// The Client Hints are built before anything can launch: Metadata fails on
	// an inconsistent pin, and finding that out after a 150-second solve would
	// be an expensive way to learn it.
	if _, err := l.Profile.Metadata(""); err != nil {
		return nil, err
	}
	return solveExit(ctx, l, o, l.newBrowserSession(parsed), parsed.Label()), nil
}

// BatchResult is one exit's answer as it comes back.
type BatchResult struct {
	Exit   Exit
	Result *Result
}

// SolveBatch works a list of exits through one browser, calling onResult as each
// finishes.
//
// The launch is paid once instead of once per exit, which is the entire saving:
// on a small VPS Chromium takes ~20s to come up, so a hundred exits spent over
// half an hour doing nothing but starting browsers. Contexts cost milliseconds.
//
// onResult is called from the worker that finished the exit, so it must be safe
// to call concurrently; results arrive in completion order rather than list
// order. It is called for every exit exactly once, including the ones that
// failed — a caller pairing cookies with proxies has to hear about a dropped
// exit rather than infer it from a short list.
func SolveBatch(ctx context.Context, o Options, batch *Batch, onResult func(BatchResult)) error {
	l := o.launcher()
	if _, err := l.Profile.Metadata(""); err != nil {
		return err
	}

	// The browser has no proxy of its own: every exit's is on its context. A
	// browser-level one would be the wrong exit for all but the first.
	launchCtx, cancel := context.WithTimeout(ctx, o.timeout())
	b, err := l.launch(launchCtx, nil)
	cancel()
	if err != nil {
		return err
	}
	defer b.Close()

	var (
		mu   sync.Mutex
		next int
		wg   sync.WaitGroup
		emit sync.Mutex
	)
	worker := func() {
		defer wg.Done()
		for {
			mu.Lock()
			if next >= len(batch.Exits) {
				mu.Unlock()
				return
			}
			exit := batch.Exits[next]
			next++
			mu.Unlock()

			proxy, err := ParseProxy(exit.Proxy)
			var res *Result
			if err != nil {
				// NewBatch already rejected these, so reaching here means the
				// list was built by hand. Report it as this exit's failure
				// rather than taking the batch down with it.
				res = &Result{Status: StatusError, Error: err.Error()}
			} else {
				res = solveExit(ctx, l, o, l.newContextSession(b, proxy), proxy.Label())
			}

			emit.Lock()
			onResult(BatchResult{Exit: exit, Result: res})
			emit.Unlock()
		}
	}

	wg.Add(batch.Parallel)
	for i := 0; i < batch.Parallel; i++ {
		go worker()
	}
	wg.Wait()
	return nil
}

// solveExit works one exit to a conclusion.
//
// budget is this exit's whole share of the clock. In a batch every exit gets the
// same share, and the rounds they run in are what the caller sizes its own
// timeout against.
func solveExit(ctx context.Context, l Launcher, o Options, open newSession, proxyLabel string) *Result {
	start := time.Now()
	budget := o.timeout()

	// One overall deadline shared by every attempt, so an exit cannot overshoot
	// the budget the caller sized its own timeout against. The per-attempt split
	// below is what keeps a slow first attempt from leaving the retry with none.
	overall, cancelOverall := context.WithTimeout(ctx, budget)
	defer cancelOverall()

	var best *Result
	attempts := 0

	for i := 1; i <= maxAttempts; i++ {
		if overall.Err() != nil {
			break
		}

		// A non-final attempt gets only part of what is left, so a first attempt
		// that sits on a challenge until the deadline cannot leave the retry
		// with no time to run in. The last attempt gets everything that remains.
		attemptCtx := overall
		var cancelAttempt context.CancelFunc
		if i < maxAttempts {
			deadline, ok := overall.Deadline()
			if ok {
				remaining := time.Until(deadline)
				attemptCtx, cancelAttempt = context.WithTimeout(overall, remaining*6/10)
			}
		}

		res, challenged := attempt(attemptCtx, l, open, o.Target, i)
		if cancelAttempt != nil {
			cancelAttempt()
		}
		attempts = i
		// Keep the best attempt, not the most recent one.
		best = betterResult(best, res)

		if res.Status == StatusOK {
			res.DurationMS = time.Since(start).Milliseconds()
			res.Attempts = i
			res.Proxy = proxyLabel
			return res
		}

		// A site that presented no challenge at all has already given us
		// everything it is going to. Relaunching for it costs another cold start
		// — ~20s on the boxes this is tuned for — and cannot produce a different
		// answer, so the retry is spent only when there is a challenge to retry.
		//
		// The Node solver documented this rule on the flag and then never
		// applied it: the flag decided whether to skip the behaviour simulation,
		// and the retry loop keyed on status alone. So every unchallenged site
		// paid two full budgets to learn the same thing twice.
		if !challenged {
			break
		}

		// Still challenged with another attempt left: a small jittered backoff,
		// so the retry hits the edge with a clean PoP rotation — but only if
		// there is meaningful time left to run in.
		if i < maxAttempts {
			if deadline, ok := overall.Deadline(); ok && time.Until(deadline) > 3*time.Second {
				nap(overall, 800, 1500)
			}
		}
	}

	out := exhaustedResult(best, exhaustedDefaults{
		URL:            o.Target,
		UserAgent:      l.Profile.UserAgent,
		AcceptLanguage: ExpectedAcceptLanguage(l.Profile.Language),
	})
	out.DurationMS = time.Since(start).Milliseconds()
	out.Attempts = attempts
	out.Proxy = proxyLabel
	if best != nil {
		out.ChromiumVer = best.ChromiumVer
		out.ChromiumMajor = best.ChromiumMajor
		out.LaunchMS = best.LaunchMS
	}
	return out
}

// attempt is one full try: open a session, navigate, wait for clearance,
// simulate behaviour, capture cookies.
//
// Two structural notes, both of which were bugs in the version this replaces:
//
//   - opening the session is inside the recovery path. A failed launch (no
//     Xvfb, no Chromium, a port race) used to escape the attempt entirely and
//     abort the run, so the retry never covered the one failure a retry helps
//     most with.
//   - the session is closed here rather than handed back for the caller to
//     close. The caller then had to clear its own handle too, and the check that
//     did so compared against a field it had already cleared — so the graceful
//     close always ran against a dead handle.
//
// The second return says whether this attempt found a challenge at all, which
// is what tells the caller whether a retry has anything to retry. A failure to
// open a session or to navigate reports true: nothing was learned about the
// site, so the retry is still worth having.
func attempt(ctx context.Context, l Launcher, open newSession, target string, n int) (*Result, bool) {
	s, err := open(ctx)
	if err != nil {
		return &Result{Status: StatusError, Error: describeErr(err)}, true
	}
	defer s.close()

	fail := func(err error) *Result {
		// Harvest before giving up. A navigation timeout is not a reason to
		// throw away cookies the challenge page already set — a run whose
		// navigation timed out reported nothing at all, when the jar held the
		// challenge's own cookies.
		salvaged := l.harvest(context.Background(), s, target)
		salvaged.Status = statusAfterThrow(salvaged)
		// The error is kept beside the status rather than instead of it. Nothing
		// reads it on a successful line, and discarding it would lose the only
		// record of why the attempt ended early.
		salvaged.Error = describeErr(err)
		return salvaged
	}

	if err := s.tab.Navigate(ctx, target); err != nil {
		return fail(err), true
	}

	// The page is occupied for the whole time the challenge is running, not
	// only after it clears. A challenge that scores mouse movement, time to
	// first interaction and scroll position decides during this window and
	// submits as soon as its own work finishes — so activity that starts after
	// the verdict is activity the verdict never saw. See startAttention.
	stopAttention := startAttention(ctx, s.tab)
	attentionStopped := false
	endAttention := func() {
		if !attentionStopped {
			attentionStopped = true
			stopAttention()
		}
	}
	defer endAttention()

	// The click that used to be here is inside waitForPassage now, and it had to
	// move to happen at all. It ran only when the wait came back challenged and
	// the context was still live — but the wait comes back challenged only when
	// the context is done, so the second half of that condition was false every
	// single time. Pressing a widget after the budget is spent is not a thing
	// worth doing anyway: the click is what starts a managed challenge, so it
	// belongs where there is still time left to solve in.
	outcome := waitForPassage(ctx, s, target)

	if !outcome.cleared && outcome.challenged && n < maxAttempts {
		// Still challenged with a retry left. A fresh context often gets a
		// different variant, so skip the behaviour simulation and let the caller
		// start over — but read the jar first. __cf_bm is set by the challenge
		// page itself, and abandoning the attempt used to throw it away, so a
		// run whose retry also failed reported nothing when it had in fact
		// collected something usable.
		endAttention()
		return l.harvest(ctx, s, target), true
	}

	// The drift stops here so the post-clearance choreography is the only thing
	// moving the pointer: two of them at once is a hand in two places.
	endAttention()

	// Whether clearance was present or not, give the behavioural scoring
	// something to sample: on a bot-fight-mode-only zone this is what makes the
	// __cf_bm strong enough to survive.
	simulateHumanBehavior(ctx, s.tab)

	// Re-read after the behaviour, which can elevate __cf_bm.
	res := l.harvest(ctx, s, target)
	// harvest decides the status from the jar, which only knows about
	// cf_clearance. A target that let us through without issuing one is still a
	// target we got through to, and reporting that as no_clearance is what made
	// every non-Cloudflare success look like a failure.
	if outcome.cleared {
		res.Status = StatusOK
	}
	return res, outcome.cleared || outcome.challenged
}

// ErrNoBrowser is what a caller gets when there is nothing to drive.
var ErrNoBrowser = errors.New("no Chrome or Chromium found")

// CheckBrowser reports whether a browser is available to solve with, so a caller
// can say so before it has spent a budget finding out.
func CheckBrowser(execPath string) (string, error) {
	if execPath != "" {
		if _, err := os.Stat(execPath); err != nil {
			return "", err
		}
		return execPath, nil
	}
	path, err := cdp.Find()
	if err != nil {
		return "", err
	}
	return path, nil
}
