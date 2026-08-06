package gofire

import (
	"os"
	"regexp"
	"testing"
)

// The solver hands back a cf_clearance cookie that this client then replays.
// Cloudflare binds that cookie to the User-Agent that earned it, so the two
// User-Agents are one value stored in two languages: when the Go constant moves
// to a new Chrome major and the JavaScript does not, every replayed request is
// mitigated and nothing in the Go code looks wrong.
func TestSolverUserAgentMatchesChromeProfile(t *testing.T) {
	src, err := os.ReadFile("solver/index.js")
	if err != nil {
		t.Skipf("solver not present: %v", err)
	}

	m := regexp.MustCompile(`SOLVER_UA\s*\|\|\s*"([^"]+)"`).FindSubmatch(src)
	if m == nil {
		t.Fatal("could not find the TARGET_UA default in solver/index.js")
	}

	if got := string(m[1]); got != Chrome150UserAgent {
		t.Errorf("solver User-Agent has drifted from the client's:\n solver: %s\n client: %s", got, Chrome150UserAgent)
	}
}
