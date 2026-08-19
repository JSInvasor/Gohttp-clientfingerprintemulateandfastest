package solver

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Where a solve's time actually goes.
//
// A solve is two costs and only one of them is ours. Cloudflare's challenge
// takes what it takes — its JavaScript runs, the widget verifies, the edge
// decides — and nothing here can shorten it. Everything around it is this
// package's: bringing a browser up, opening a context, pinning the identity, and
// the behavioural dwell before the cookie is read.
//
// That second number is worth knowing exactly, because it is the budget floor.
// A -solve-timeout below it cannot succeed no matter how fast the zone is, and
// it is the part that a change here can make worse without anyone noticing.
//
// Run with -v to read the breakdown.
func TestSolvePhaseTimings(t *testing.T) {
	requireBrowser(t)
	headful := true
	if _, err := exec.LookPath("Xvfb"); err != nil || os.Getenv("DISPLAY") != "" {
		// Report the headless numbers rather than skipping: the shape is the
		// same and the launch is the only phase that differs much.
		headful = false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	p := DefaultProfile()
	l := Launcher{Profile: p, Headless: !headful}

	launchStart := time.Now()
	b, err := l.launch(ctx, nil)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer b.Close()
	launchMS := time.Since(launchStart).Milliseconds()

	// A context and a tab, which is what every exit past the first costs in a
	// batch — the launch is paid once.
	ctxStart := time.Now()
	bctx, err := b.NewContext(ctx, "")
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	defer bctx.Close(ctx)
	tab, err := bctx.NewTab(ctx)
	if err != nil {
		t.Fatalf("tab: %v", err)
	}
	defer tab.Close(ctx)
	contextMS := time.Since(ctxStart).Milliseconds()

	prepStart := time.Now()
	if err := l.prepare(ctx, tab, b.Version.Product); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	prepMS := time.Since(prepStart).Milliseconds()

	// The behavioural dwell, which runs after the challenge clears and before
	// the cookie is read. Cloudflare scores the cookie on the first few seconds
	// after issuance, so this is deliberate rather than incidental — a cookie
	// captured cold dies under load.
	site := newFakeEdge(t, 500*time.Millisecond, "Just a moment...")
	if err := tab.Navigate(ctx, site.server.URL+"/"); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	behaviourStart := time.Now()
	simulateHumanBehavior(ctx, tab)
	behaviourMS := time.Since(behaviourStart).Milliseconds()

	harvestStart := time.Now()
	_ = l.harvest(ctx, &session{tab: tab, context: bctx, version: b.Version.Product}, site.server.URL+"/")
	harvestMS := time.Since(harvestStart).Milliseconds()

	mode := "headful under Xvfb"
	if !headful {
		mode = "headless"
	}
	fixed := launchMS + contextMS + prepMS + behaviourMS + harvestMS
	t.Logf("solve phases on this box (%s, %s):", mode, b.Version.Product)
	t.Logf("  browser launch      %5d ms   (once per browser; a batch pays it once)", launchMS)
	t.Logf("  context + tab       %5d ms   (per exit in a batch)", contextMS)
	t.Logf("  identity pin        %5d ms", prepMS)
	t.Logf("  behavioural dwell   %5d ms   (deliberate: the cookie is scored on it)", behaviourMS)
	t.Logf("  harvest             %5d ms", harvestMS)
	t.Logf("  ------------------------------")
	t.Logf("  fixed overhead      %5d ms   + whatever Cloudflare's challenge takes", fixed)

	// The dwell is the one phase with a designed duration, so it is the one
	// worth pinning: shortening it silently would produce cookies captured cold,
	// which is a failure that only shows up under load.
	if behaviourMS < 3500 {
		t.Errorf("behavioural dwell was %dms — too short to score on; "+
			"CF samples the first few seconds after issuance", behaviourMS)
	}
	if behaviourMS > 9000 {
		t.Errorf("behavioural dwell was %dms — that is budget spent on choreography", behaviourMS)
	}

	// The floor a -solve-timeout has to clear before the challenge is even
	// reached. minSolveTimeout in cmd/send is 10s, which this has to fit under
	// on a machine of this class or that minimum is a lie.
	if fixed > 30_000 {
		t.Errorf("fixed overhead is %dms, which leaves a 150s budget little room", fixed)
	}
}
