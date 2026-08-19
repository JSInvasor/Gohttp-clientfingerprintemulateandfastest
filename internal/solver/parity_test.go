package solver

import (
	"strings"
	"testing"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// The solver and the client have to be the same browser, and until now nothing
// checked that they said so.
//
// Cloudflare binds cf_clearance to the issuing session's (UA, JA3/JA4, IP). The
// solver drives a real Chromium and claims an identity; gofire replays the
// cookie with its own emulated ClientHello and claims one too. Those two claims
// live in different files as separate string literals — internal/solver's
// defaults and headers.go's constants — and nothing made them agree.
//
// That is not a hypothetical. From the README: the solver "ended up pinned to
// Chrome 147 while the Go profile moved to 151", which is a cookie earned as one
// browser and presented as another. It works once, dies under load, and looks
// exactly like a solver bug.
//
// Two other instruments cover neighbouring cases and neither covers this one:
// reportChromiumDrift compares the *installed* Chromium to the client's pin at
// run time, and `fpcheck -via-chromium` compares the installed browser to the
// reference when someone runs it. Both are about the browser on the box. This is
// about the two pins in the tree, and it is the one a version bump gets wrong.
func TestSolverPinMatchesTheClientProfile(t *testing.T) {
	p := DefaultProfile()

	// The solver runs on Linux — it is what the container and the VPS this is
	// tuned for run — so the Linux UA is the one it has to claim. Claiming the
	// Windows one was measurably wrong: the headers said Windows while
	// navigator.platform said Linux x86_64 and the fonts agreed with the latter.
	if p.UserAgent != gofire.Chrome151LinuxUserAgent {
		t.Errorf("the solver pins a UA the client does not replay:\n"+
			"  solver: %s\n  client: %s\n"+
			"Re-pin internal/solver's defaultUA and headers.go together.",
			p.UserAgent, gofire.Chrome151LinuxUserAgent)
	}

	if p.SecChUA != gofire.Chrome151SecChUa {
		t.Errorf("the solver pins Client Hints the client does not send:\n"+
			"  solver: %s\n  client: %s\n"+
			"Re-pin internal/solver's defaultSecChUA and headers.go together.",
			p.SecChUA, gofire.Chrome151SecChUa)
	}

	// The two UAs the client carries are one identity with two OS tokens, so the
	// major has to be the same in both — and in the solver's.
	solverMajor := majorOf(t, p.UserAgent)
	clientMajor := majorOf(t, gofire.Chrome151UserAgent)
	if solverMajor != clientMajor {
		t.Errorf("solver claims Chrome %d, client replays as Chrome %d", solverMajor, clientMajor)
	}

	// The OS token and the platform hint have to name the same system; Metadata
	// refuses to build an inconsistent pair, so this is the same check one step
	// earlier, where the message can say which file to edit.
	if got := PlatformFromUA(p.UserAgent); got != p.Platform {
		t.Errorf("the solver's UA says %s but its platform hint says %s", got, p.Platform)
	}

	// And the hints have to be buildable at all, which is what would fail if the
	// sec-ch-ua brands and the UA's major were bumped apart.
	if _, err := p.Metadata(""); err != nil {
		t.Errorf("the pinned profile does not produce Client Hints: %v", err)
	}
}

// A version bump has to move every brand in sec-ch-ua, not just the UA string.
//
// This is the half that is easy to miss: the UA is one obvious literal and
// sec-ch-ua is three brands inside one, so a bump that edits the first and skips
// the second produces a browser claiming two different versions in two headers
// on the same request.
func TestSecChUABrandsAgreeWithTheUAMajor(t *testing.T) {
	p := DefaultProfile()
	major := strings.SplitN(chromeVersionFromUA(p.UserAgent), ".", 2)[0]

	brands := ParseSecChUA(p.SecChUA)
	if len(brands) == 0 {
		t.Fatal("no brands parsed from the pinned sec-ch-ua")
	}
	var real int
	for _, b := range brands {
		if isGreasedBrand(b.Brand) {
			continue // carries its own unrelated version by design
		}
		real++
		if b.Version != major {
			t.Errorf("sec-ch-ua says %s v%s but the UA says Chrome %s", b.Brand, b.Version, major)
		}
	}
	if real == 0 {
		t.Error("sec-ch-ua carries only greased brands")
	}
	// Chrome puts the greased entry first and the ordering is itself observable,
	// so a bump must not reorder them.
	if !isGreasedBrand(brands[0].Brand) {
		t.Errorf("the first brand is %q, want the greased entry", brands[0].Brand)
	}
}

func majorOf(t *testing.T, ua string) int {
	t.Helper()
	v := chromeVersionFromUA(ua)
	if v == "" {
		t.Fatalf("no Chrome version in %q", ua)
	}
	n := 0
	for _, r := range strings.SplitN(v, ".", 2)[0] {
		n = n*10 + int(r-'0')
	}
	return n
}
