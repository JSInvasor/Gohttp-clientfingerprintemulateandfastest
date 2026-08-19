package solver

import (
	"strings"
	"testing"
)

// Cloudflare localises the interstitial, and a title regex in English alone is
// how a solve concluded it was never challenged and gave up in under a second
// with two minutes of budget left.
func TestIsChallengeTitle(t *testing.T) {
	challenged := []string{
		"Just a moment...",
		"Just a moment…",
		"Attention Required! | Cloudflare",
		"Checking your browser before accessing",
		"Bir dakika...",
		"Un momento…",
		"Einen Moment …",
		"请稍候…",
		"しばらくお待ちください",
	}
	for _, title := range challenged {
		if !IsChallengeTitle(title) {
			t.Errorf("IsChallengeTitle(%q) = false, want true", title)
		}
	}

	cleared := []string{
		"Example Domain",
		"Dashboard",
		"",
		"A moment in history",
	}
	for _, title := range cleared {
		if IsChallengeTitle(title) {
			t.Errorf("IsChallengeTitle(%q) = true, want false", title)
		}
	}
}

// The structural probe is what survives a localised interstitial, and one of its
// selectors is the reason it is written as an exclusion rather than a prefix.
func TestDetectChallengeScriptExcludesTheJSDetectionScript(t *testing.T) {
	// Cloudflare injects /cdn-cgi/challenge-platform/scripts/jsd/main.js into
	// ordinary 200 responses on any zone with bot management on. Matching it
	// makes a cleared page read as challenged until the caller's deadline, so a
	// site that never challenges would burn the whole budget and report
	// no_clearance.
	if !strings.Contains(DetectChallengeScript, `:not([src*="/scripts/jsd/"])`) {
		t.Error("the challenge-platform selector no longer excludes the JS-detection script")
	}
	// The markers have to be structural, not prose, or they move with the
	// page's language.
	for _, marker := range []string{
		"#challenge-form",
		"#challenge-stage",
		"#turnstile-wrapper",
		"challenges.cloudflare.com",
		"_cf_chl_opt",
	} {
		if !strings.Contains(DetectChallengeScript, marker) {
			t.Errorf("the probe lost its %q marker", marker)
		}
	}
}

// Both scripts are evaluated in the page, so they must be self-contained
// expressions: they can close over nothing and reference only what the document
// provides.
func TestPageScriptsAreExpressions(t *testing.T) {
	for name, src := range map[string]string{
		"DetectChallengeScript": DetectChallengeScript,
		"IdentityScript":        IdentityScript,
	} {
		trimmed := strings.TrimSpace(src)
		if !strings.HasPrefix(trimmed, "(") {
			t.Errorf("%s does not start as an expression: %.40q", name, trimmed)
		}
		if strings.Contains(trimmed, "function(") && !strings.Contains(trimmed, "=>") {
			t.Errorf("%s looks like a declaration rather than an expression", name)
		}
	}
}
