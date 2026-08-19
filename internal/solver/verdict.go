package solver

import "strings"

// Which of four cases a replay describes, and how to say it in words.
//
// This is the answer the replay tool exists to produce, so it is computed once
// and reported rather than left for the reader to assemble from four nested
// objects — which is exactly the kind of reading that produces a confident wrong
// answer. Getting it backwards would send someone to rewrite a fingerprint that
// was never the problem.

// The four cases, and the fifth that is the absence of an answer.
const (
	// VerdictTravels: the carried-in cookie was accepted. -solve works here, and
	// a 403 from the Go client is the Go client's problem.
	VerdictTravels = "travels"
	// VerdictZoneChallenges: a clearance the browser earned itself, in the
	// context it earned it in, was challenged on the next navigation. No client
	// can hold a session on this address — there is nothing for -solve to earn
	// that would ever be reusable, and the answer is a different exit.
	VerdictZoneChallenges = "zone_challenges"
	// VerdictDoesNotTravel: that same in-context clearance worked, but the
	// carried-in one did not. The cookie is bound to the session that earned it.
	// Also not fixable from the client side.
	VerdictDoesNotTravel = "does_not_travel"
	// VerdictChallengeState: the carried cookies failed but the clearance alone
	// passed, so it was the challenge bookkeeping being replayed alongside it.
	// That one *is* fixable here.
	VerdictChallengeState = "challenge_state"
	// VerdictInconclusive: the follow-up could not say why. This is the absence
	// of evidence, not evidence about the address.
	VerdictInconclusive = "inconclusive"
)

// ReplayAttempt is what one navigation with one set of cookies reported.
type ReplayAttempt struct {
	Label     string   `json:"label"`
	Presented []string `json:"presented"`
	// Sent are the cookie names that were actually on the wire, and NotSent what
	// is missing from them. A non-empty NotSent invalidates the attempt rather
	// than answering it; nil Sent means the wire could not be observed, which is
	// not the same as nothing having been on it.
	Sent       []string `json:"sent"`
	NotSent    []string `json:"not_sent"`
	Observed   bool     `json:"observed"`
	HTTPStatus int      `json:"http_status"`
	Challenged bool     `json:"challenged"`
	Title      string   `json:"title"`
	URL        string   `json:"url"`
}

// InSessionAttempt is a challenge solved in a fresh context and continued in it.
type InSessionAttempt struct {
	// SolvedHere says whether that context actually earned a clearance, or
	// whether the wait simply ran out. Without it the two are the same JSON and
	// they mean opposite things: "the browser solved it and was challenged
	// again" says the zone re-challenges everything and no client can help,
	// while "the browser never solved it" says only that the budget was not
	// enough. Reporting the second as the first is how a timeout gets written up
	// as a property of Cloudflare.
	SolvedHere bool   `json:"solved_here"`
	HTTPStatus int    `json:"http_status"`
	Challenged bool   `json:"challenged"`
	Title      string `json:"title"`
}

// Verdict names which of the cases these attempts describe.
func Verdict(carried *ReplayAttempt, inSession *InSessionAttempt, clearanceOnly *ReplayAttempt) string {
	if carried == nil {
		return VerdictInconclusive
	}
	if !carried.Challenged {
		return VerdictTravels
	}
	if clearanceOnly != nil && !clearanceOnly.Challenged {
		return VerdictChallengeState
	}
	if inSession == nil {
		return VerdictInconclusive
	}
	// "the browser solved it and was challenged again" and "the browser never
	// solved it" are the same JSON unless SolvedHere is checked, and only the
	// first is worth calling zone_challenges.
	if !inSession.SolvedHere {
		return VerdictInconclusive
	}
	if inSession.Challenged {
		return VerdictZoneChallenges
	}
	return VerdictDoesNotTravel
}

// Explain is the verdict in words, for the human reading the run.
func Explain(v string) string {
	switch v {
	case VerdictTravels:
		return "the clearance was accepted — a browser presenting it from this address is not\n" +
			"challenged. So -solve has something to offer here, and a 403 from the Go client\n" +
			"is about the client rather than the cookie."

	case VerdictZoneChallenges:
		return "this address is challenged whatever presents it.\n\n" +
			"The measurement that says so: a real Chromium solved the challenge itself, then\n" +
			"navigated again in the very context that had just solved it — and was challenged\n" +
			"again. Not a carried cookie, not this client, not a fingerprint. A browser cannot\n" +
			"hold a session here either.\n\n" +
			"Nothing in this repo changes that outcome, and no amount of emulation would. The\n" +
			"aim is not to replay a clearance, it is to not be challenged, and that is a\n" +
			"question about the address. Try a different exit:\n\n" +
			"  send -solve -proxy http://user:pass@host:port <url>\n" +
			"  send -solve -proxy-file proxies.txt <url>\n\n" +
			"Worth knowing before re-running this: each failed challenge from an address makes\n" +
			"the next one harder, so measuring this repeatedly is not free. If the same target\n" +
			"passed from this address earlier today, that is the likeliest reason it no longer\n" +
			"does — leave it alone for a while rather than solving against it in a loop."

	case VerdictDoesNotTravel:
		return "the clearance works, but only inside the session that earned it.\n\n" +
			"A challenge solved in a fresh context and continued in it was accepted; the same\n" +
			"cookie carried into another context was not. So the cookie is bound to more than\n" +
			"the address, the User-Agent and the TLS fingerprint — and nothing on this side\n" +
			"reproduces whatever the rest of it is. -solve cannot help against this zone."

	case VerdictChallengeState:
		return "the clearance travels; the challenge bookkeeping beside it is what was refused.\n\n" +
			"Presented alone it was accepted, presented with the cf_chl_* cookies it was not.\n" +
			"That is fixable here, and send already withholds those by default — check you are\n" +
			"not running with -solve-all-cookies."

	default:
		return "inconclusive.\n\n" +
			"The carried cookie was challenged, and the follow-up could not say why: the\n" +
			"context that was meant to solve the challenge itself never earned a clearance\n" +
			"either (solved_here: false), so there is no way to tell a zone that re-challenges\n" +
			"everything from a challenge that simply did not finish in the time allowed.\n\n" +
			"Both are worth ruling out before concluding anything:\n\n" +
			"  - re-run when the box is not busy; a solve here takes over a minute\n" +
			"  - check `send -solve` still earns a cf_clearance at all\n\n" +
			"Do not read this as evidence about the address. It is the absence of evidence."
	}
}

// IsChallengeState reports whether a cookie name is the challenge's own
// bookkeeping rather than the credential.
//
// cf_clearance is the credential. cf_chl_* are the challenge's working state —
// rc is a retry counter, and the rest are stage markers — and a browser that has
// finished has no reason to keep presenting them. Handing them back says "I am
// part-way through a challenge", which is a different claim from "I finished
// one", and the edge is entitled to act on it.
func IsChallengeState(name string) bool {
	return strings.HasPrefix(name, "cf_chl_") || strings.HasPrefix(name, "_cf_chl")
}
