package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// -solve with -proxy-file: one solve per exit, and every session replays only
// the cookies its own exit earned.
//
// This used to be refused, and the reason it was refused is still true: one
// solve earns one cookie bound to one IP, while a rotator hands each session a
// different exit. What was wrong was the conclusion. A single solve cannot cover
// a list, so this does not try to — it solves the list, and then keeps each
// cookie with the address it was issued to.
//
// Three things have to hold for that pairing to survive into the run:
//
//   - one solve per exit a session will actually pin, so no session is left
//     replaying somebody else's cookie. Exits past that count are not solved,
//     because nothing would use them.
//   - an exit that fails to solve is dropped from the list rather than run
//     without a cookie. A proxy that cannot get past the challenge in a browser
//     will not get past it in this client either, and leaving it in would spend
//     a session's whole share of the run on 403s.
//   - the surviving sessions are hard-pinned (ProxyRotator.PinnedOnly), so a
//     proxy that dies mid-run fails its own session's requests instead of
//     quietly rotating its cookie onto a sibling's IP.
//
// The cost is real: a solve is mostly Cloudflare's own challenge, and this pays
// it once per exit. -solve-parallel decides how many browsers that is at a time,
// and the per-exit cache (keyed by host and proxy already) is what keeps the
// second run from paying it again.

// solveAcrossProxies earns one identity per exit and leaves the run holding the
// exits that worked, paired with what they earned.
func solveAcrossProxies(ctx context.Context, o *options, target string) error {
	// Loaded here rather than taken from the session pool because the pool is
	// built after the solve — and it is built from what this leaves behind,
	// which is a narrower list than the file.
	rotator, err := gofire.NewProxyRotatorFromFile(o.proxyFile)
	if err != nil {
		return fmt.Errorf("proxy file: %w", err)
	}
	proxies := rotator.ProxyURLs()

	// Sessions pin proxies[i % len(proxies)], so only the first -s entries are
	// ever a session's own exit. Solving the rest would cost a browser launch
	// and a challenge each for cookies nothing replays.
	n := min(len(proxies), o.sessions)
	if len(proxies) > n {
		fmt.Fprintf(os.Stderr, "%d proxies loaded but only %d session(s) — solving %d of them; "+
			"raise -s to spread the run across more exits\n", len(proxies), o.sessions, n)
	}

	// Worst case, not an estimate: every exit taking the full budget, in
	// -solve-parallel-sized rounds. Worth printing because it is the number that
	// surprises people — a 20-proxy list two at a time is ten rounds deep.
	rounds := (n + o.solveParallel - 1) / o.solveParallel
	fmt.Fprintf(os.Stderr, "solving %s through %d exit(s), %d at a time (up to %s)\n",
		target, n, o.solveParallel, round(time.Duration(rounds)*o.solveTimeout))

	seeds, errs := solveFleet(ctx, o, target, proxies[:n])
	// A Ctrl-C during the solve is not a partial success to carry into a run.
	if err := ctx.Err(); err != nil {
		return err
	}

	kept := make([]string, 0, n)
	keptSeeds := make([]solveSeed, 0, n)
	failed := 0
	for i, seed := range seeds {
		if seed == nil {
			failed++
			logSolve(proxies[i], "solve failed, dropping this exit: %v", errs[i])
			continue
		}
		kept = append(kept, proxies[i])
		keptSeeds = append(keptSeeds, *seed)
	}
	if len(kept) == 0 {
		return fmt.Errorf("none of the %d exit(s) solved, so every session would replay "+
			"nothing: %w", n, errs[0])
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "%d of %d exits solved — the run uses those, and %d session(s) "+
			"share them\n", len(kept), n, o.sessions)
	}

	// Every exit drives the same local Chromium, so the identity it reports is
	// the same for all of them. Checked once, off the first seed, for the same
	// reason it is checked at all: a cookie replayed by a browser it was not
	// issued to is a silent 403.
	reportSolveDrift(&keptSeeds[0])
	warnOnMixedUA(keptSeeds)

	// The list the session pool builds its rotator from is now the solved one,
	// so a dropped exit cannot come back through the file and be dialled by a
	// session whose cookie was issued somewhere else.
	o.proxyList = kept
	o.solveSeeds = keptSeeds
	return nil
}

// solveFleet runs the solves, at most -solve-parallel at a time, and returns
// them positionally: seeds[i] or errs[i] belongs to proxies[i].
//
// Each browser is a real Chromium under Xvfb — several hundred MB and a couple
// of cores while it runs — so the whole list at once would thrash a small box
// into timing every attempt out. Which is a slow failure that reads as "the
// proxies are bad".
func solveFleet(ctx context.Context, o *options, target string, proxies []string) ([]*solveSeed, []error) {
	seeds := make([]*solveSeed, len(proxies))
	errs := make([]error, len(proxies))

	slots := make(chan struct{}, o.solveParallel)
	var wg sync.WaitGroup
	for i, proxy := range proxies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				errs[i] = ctx.Err()
				return
			}
			// Checked after taking the slot too: an interrupt during the first
			// round should not start the second one's browsers.
			if err := ctx.Err(); err != nil {
				errs[i] = err
				return
			}
			seeds[i], errs[i] = solveOne(ctx, o, target, proxy)
		}()
	}
	wg.Wait()
	return seeds, errs
}

// warnOnMixedUA reports exits whose solve came back with a different UA from the
// first one's.
//
// It should never fire: one box, one Chromium, one pinned UA. If it does, the
// cookies are still each valid for the session replaying them — the seed carries
// its own UA — but it means the solver is not returning what this client thinks
// it pinned, which is worth knowing before the fingerprint drifts somewhere less
// visible.
func warnOnMixedUA(seeds []solveSeed) {
	for _, s := range seeds[1:] {
		if s.userAgent != seeds[0].userAgent {
			fmt.Fprintf(os.Stderr, "warning: the exits did not agree on a User-Agent —\n"+
				"  %s\n  %s\n"+
				"  each session replays the UA its own cookie was issued to, but one solver "+
				"should not produce two identities\n", seeds[0].userAgent, s.userAgent)
			return
		}
	}
}
