package solver

import (
	"context"
	"math/rand"
	"strconv"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/cdp"
)

// The few seconds after a clearance is issued, which are not idle time.
//
// Cloudflare samples mouse, scroll and dwell events for the first few seconds
// after issuance and scores the cookie on them. A cookie captured cold dies
// under load within seconds; one captured after 3-5s of believable activity
// holds up. So this runs before the jar is read, not after.
//
// Every step is best-effort. A page that navigated out from under a mouse move
// is the challenge clearing, which is the outcome being waited for — failing the
// solve over it would discard the cookie the behaviour was meant to strengthen.
func simulateHumanBehavior(ctx context.Context, tab *cdp.Tab) {
	// Initial settle pause: RUM beacons fire here.
	if !nap(ctx, 900, 1600) {
		return
	}

	_ = tab.MouseMove(ctx, randRange(220, 1100), randRange(180, 600), 12)
	if !nap(ctx, 280, 600) {
		return
	}

	// Smooth rather than instant: a scroll that jumps produces one event where a
	// wheel produces a series.
	_ = tab.Evaluate(ctx, scrollBy(randRange(280, 600)), nil)
	if !nap(ctx, 800, 1300) {
		return
	}

	_ = tab.MouseMove(ctx, randRange(400, 1500), randRange(300, 800), 10)
	_ = tab.Evaluate(ctx, scrollBy(randRange(150, 380)), nil)
	if !nap(ctx, 700, 1100) {
		return
	}

	// A focus event and a click, the way a tab switched back to behaves.
	_ = tab.Evaluate(ctx, `(() => {
		window.dispatchEvent(new Event("focus"));
		if (document.body) document.body.click();
	})()`, nil)
	if !nap(ctx, 500, 900) {
		return
	}

	// Final dwell: lets __cf_bm settle and any post-load JS finish.
	nap(ctx, 600, 1100)
}

func scrollBy(y float64) string {
	return `window.scrollBy({top: ` + strconv.Itoa(int(y)) + `, behavior: "smooth"})`
}

// nap sleeps for a jittered interval, reporting false if the context ended
// first — the caller's budget outranks the choreography.
func nap(ctx context.Context, minMS, maxMS int) bool {
	d := time.Duration(minMS+rand.Intn(maxMS-minMS+1)) * time.Millisecond
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func randRange(lo, hi float64) float64 {
	return lo + rand.Float64()*(hi-lo)
}
