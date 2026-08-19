package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// chromeProbe builds the probe result runChromiumProbe would hand back, around
// the committed Chrome device capture.
//
// Building the value rather than driving a browser is deliberate: what these
// tests exercise is checkChromiumProbe, the comparison that decides whether the
// browser earning cf_clearance is the browser this client emulates. That is pure
// logic over a capture, and it needs no Chromium, no display and no network.
// Whether the browser launches at all is what the command reports at runtime,
// and internal/cdp covers it against a real one.
//
// It used to be a stub fingerprint.js the probe was pointed at, back when the
// probe was a Node process. The parsing that scaffolding tested — a preamble
// from some dependency, a status field, a stray JSON line — went away with the
// pipe it was parsing.
func chromeProbe(t *testing.T, version string, major int, solverUA string) *chromiumProbe {
	t.Helper()
	raw, err := os.ReadFile("testdata/chrome151-windows.json")
	if err != nil {
		t.Fatalf("read capture: %v", err)
	}
	probe := &chromiumProbe{
		Status:          "ok",
		Version:         version,
		Major:           major,
		NativeUserAgent: gofire.Chrome151UserAgent,
		SolverUserAgent: solverUA,
	}
	if err := json.Unmarshal(raw, &probe.Capture); err != nil {
		t.Fatalf("decode capture: %v", err)
	}
	return probe
}

func TestChromiumProbeAgreesWithProfile(t *testing.T) {
	probe := chromeProbe(t, "HeadlessChrome/151.0.7204.50", 151, gofire.Chrome151UserAgent)
	if probe.Major != 151 {
		t.Errorf("chromium major = %d, want 151", probe.Major)
	}

	for _, c := range checkChromiumProbe(gofire.ReferenceFor(gofire.Chrome151), probe) {
		if c.skipped {
			t.Logf("SKIP %s: %s", c.name, c.note)
			continue
		}
		if !c.ok() {
			t.Errorf("check %q failed against a matching browser\n want: %s\n got:  %s",
				c.name, c.want, c.got)
		}
	}
}

// TestChromiumProbeCatchesUADrift is the failure this command exists to catch.
//
// The solver pinned Chrome 147 while the Go profile moved to 151 — exactly the
// state this repo was in. cf_clearance is bound to the issuing session's UA, so
// the cookie is earned as one browser and presented as another: it works once,
// then dies under load, and looks like a solver bug rather than a version pin.
func TestChromiumProbeCatchesUADrift(t *testing.T) {
	const staleUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
	probe := chromeProbe(t, "HeadlessChrome/151.0.7204.50", 151, staleUA)

	var found bool
	for _, c := range checkChromiumProbe(gofire.ReferenceFor(gofire.Chrome151), probe) {
		if c.name != "solver.user_agent" {
			continue
		}
		found = true
		if c.ok() {
			t.Error("a solver pinned to Chrome 147 passed against a Chrome 151 profile")
		}
	}
	if !found {
		t.Error("no solver.user_agent check ran")
	}
}

// TestChromiumProbeCatchesJA4Drift covers the harder half: the box has a
// Chromium whose TLS layer differs from the profile's. The cookie is bound to
// the JA4 too, so this kills it just as surely as a UA mismatch — but the fix is
// re-pinning the Go profile, not editing a string.
func TestChromiumProbeCatchesJA4Drift(t *testing.T) {
	probe := chromeProbe(t, "HeadlessChrome/146.0.7000.10", 146, gofire.Chrome151UserAgent)
	// Chrome 146 predates the ML-DSA signature algorithms, which moved JA4_c.
	if probe.Capture.TLS.JA4 == "" {
		t.Fatal("the capture carries no JA4 to move")
	}
	probe.Capture.TLS.JA4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"

	var found bool
	for _, c := range checkChromiumProbe(gofire.ReferenceFor(gofire.Chrome151), probe) {
		if c.name == "chromium.ja4" {
			found = true
			if c.ok() {
				t.Error("a Chromium with a different JA4 passed against the profile")
			}
		}
		// The version difference alone must not fail: Chrome's TLS layer was
		// unchanged across several releases, so the JA4 check is what decides.
		if c.name == "chromium.version" && !c.skipped {
			t.Errorf("chromium.version was compared rather than reported; a version "+
				"difference is only meaningful via the JA4 (got %q)", c.got)
		}
	}
	if !found {
		t.Error("no chromium.ja4 check ran")
	}
}

// The missing-browser path has to name the prerequisite. Without it the failure
// is whatever exec reports about a path that is not there.
func TestChromiumProbeRequiresABrowser(t *testing.T) {
	t.Setenv("SOLVER_CHROME", filepath.Join(t.TempDir(), "no-such-browser"))

	_, err := runChromiumProbe(context.Background(), "", "https://example.com", 30*time.Second)
	if err == nil {
		t.Fatal("expected an error when no browser is installed")
	}
	if !strings.Contains(err.Error(), "needs a browser to drive") {
		t.Errorf("error %q does not name the prerequisite", err)
	}
}

func TestMajorFromUA(t *testing.T) {
	for _, tc := range []struct {
		ua   string
		want int
	}{
		{gofire.Chrome151UserAgent, 151},
		{gofire.SafariIOS18UserAgent, 0}, // no Chrome/N token
		{"Chrome/", 0},
		{"", 0},
	} {
		if got := majorFromUA(tc.ua); got != tc.want {
			t.Errorf("majorFromUA(%.40q) = %d, want %d", tc.ua, got, tc.want)
		}
	}
}

// mustReplace substitutes old for new and fails when nothing matched.
//
// A plain strings.Replace that silently misses turns a regression test into one
// that asserts nothing: the payload stays correct, the check passes, and the
// test reports success for a case it never exercised. That happened here — the
// fixture is pretty-printed but the probe envelope is compacted, so a pattern
// written with a space after the colon matched nothing.
func mustReplace(t *testing.T, s, old, new string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("fixture does not contain %q; the test would assert nothing", old)
	}
	return strings.Replace(s, old, new, 1)
}
