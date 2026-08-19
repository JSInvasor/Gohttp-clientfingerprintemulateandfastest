package solver

import (
	"strings"
	"testing"
)

// The verdict is the answer the replay tool exists to produce, and getting it
// backwards would send someone to rewrite a fingerprint that was never the
// problem.
func TestVerdict(t *testing.T) {
	passed := &ReplayAttempt{Challenged: false}
	refused := &ReplayAttempt{Challenged: true}

	cases := []struct {
		name          string
		carried       *ReplayAttempt
		inSession     *InSessionAttempt
		clearanceOnly *ReplayAttempt
		want          string
	}{
		{
			name:    "the carried cookie was accepted",
			carried: passed,
			want:    VerdictTravels,
		},
		{
			// Checked before the in-session attempt: if dropping the bookkeeping
			// fixes it, that is the answer regardless of what the zone does.
			name:          "the bookkeeping beside it was what failed",
			carried:       refused,
			inSession:     &InSessionAttempt{SolvedHere: true, Challenged: true},
			clearanceOnly: passed,
			want:          VerdictChallengeState,
		},
		{
			name:      "a clearance earned here was challenged again",
			carried:   refused,
			inSession: &InSessionAttempt{SolvedHere: true, Challenged: true},
			want:      VerdictZoneChallenges,
		},
		{
			name:      "a clearance earned here worked, the carried one did not",
			carried:   refused,
			inSession: &InSessionAttempt{SolvedHere: true, Challenged: false},
			want:      VerdictDoesNotTravel,
		},
		{
			// The distinction the whole SolvedHere field exists for: a browser
			// that never solved the challenge says nothing about the zone, and
			// reporting it as zone_challenges is how a timeout on a busy box
			// gets written up as a property of Cloudflare.
			name:      "the follow-up never solved anything either",
			carried:   refused,
			inSession: &InSessionAttempt{SolvedHere: false, Challenged: true},
			want:      VerdictInconclusive,
		},
		{
			name:    "no follow-up at all",
			carried: refused,
			want:    VerdictInconclusive,
		},
		{
			name: "nothing was measured",
			want: VerdictInconclusive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Verdict(tc.carried, tc.inSession, tc.clearanceOnly)
			if got != tc.want {
				t.Errorf("Verdict = %q, want %q", got, tc.want)
			}
		})
	}
}

// Every verdict has to have words, or the tool answers with a bare token the
// reader then has to interpret — which is the reading that produces a confident
// wrong answer.
func TestExplainCoversEveryVerdict(t *testing.T) {
	for _, v := range []string{
		VerdictTravels, VerdictZoneChallenges, VerdictDoesNotTravel,
		VerdictChallengeState, VerdictInconclusive,
	} {
		text := Explain(v)
		if len(text) < 40 {
			t.Errorf("Explain(%q) = %q, want an explanation", v, text)
		}
	}
	// The zone_challenges case is the one where the answer is "not this repo",
	// so it has to say what to do instead.
	if !strings.Contains(Explain(VerdictZoneChallenges), "-proxy") {
		t.Error("the zone_challenges explanation does not point at a different exit")
	}
	// And inconclusive must not read as evidence.
	if !strings.Contains(Explain(VerdictInconclusive), "absence of evidence") {
		t.Error("the inconclusive explanation does not say it is not evidence")
	}
}

// cf_clearance is the credential; cf_chl_* is the challenge's working state, and
// handing it back claims to be part-way through a challenge rather than done.
func TestIsChallengeState(t *testing.T) {
	state := []string{"cf_chl_rc_i", "cf_chl_2", "_cf_chl_opt", "_cf_chl_tk"}
	for _, name := range state {
		if !IsChallengeState(name) {
			t.Errorf("IsChallengeState(%q) = false, want true", name)
		}
	}
	credentials := []string{"cf_clearance", "__cf_bm", "__cflb", "session"}
	for _, name := range credentials {
		if IsChallengeState(name) {
			t.Errorf("IsChallengeState(%q) = true — that is the credential, not the bookkeeping", name)
		}
	}
}
