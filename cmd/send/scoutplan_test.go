package main

import (
	"strings"
	"testing"
	"time"
)

// baseReport is an ordinary target: answers, sets nothing, holds still.
func baseReport() *scoutReport {
	return &scoutReport{
		target: "https://site.test", finalURL: "https://site.test",
		status: 200, proto: "HTTP/2.0",
		rtt: 50 * time.Millisecond, rttSamples: 4, cold: 60 * time.Millisecond,
	}
}

func flags(p plan) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Fields(p.command) {
		if strings.HasPrefix(part, "-") {
			out[part] = true
		}
	}
	return out
}

func reasonFor(p plan, prefix string) string {
	for _, a := range p.advice {
		if strings.HasPrefix(a.flag, prefix) {
			return a.why
		}
	}
	return ""
}

func warningsJoined(p plan) string { return strings.Join(p.warnings, " | ") }

// -c is arithmetic on a measurement, and the report has to show its working —
// that is the whole reason it is allowed to answer a question about rate
// without ever having pushed the target to find out what it can take.
func TestRecommendConcurrencyIsArithmetic(t *testing.T) {
	r := baseReport()
	r.rtt = 50 * time.Millisecond // a thread carries 20 req/s

	p := recommend(r, &options{})
	if !strings.Contains(p.command, "-c 10") {
		t.Errorf("command %q does not carry -c 10 for 200 req/s at 50ms", p.command)
	}
	why := reasonFor(p, "-c ")
	for _, want := range []string{"20", "50ms", "200 req/s"} {
		if !strings.Contains(why, want) {
			t.Errorf("the -c reason %q does not show %q, so nobody can compute a different rate from it", why, want)
		}
	}
}

// The one thing this must never do is discover a limit by pushing until the
// target pushes back. It is checked here rather than trusted because the only
// evidence is the absence of a probe: -c has to trace to the round trip and a
// rate that was chosen, and there must be no flag that ramps.
func TestRecommendNeverProbesTheRateLimit(t *testing.T) {
	r := baseReport()
	p := recommend(r, &options{})

	if !strings.Contains(reasonFor(p, "-c "), round(r.rtt).String()) {
		t.Error("-c was not derived from the measured round trip")
	}
	// No cap is suggested, because no ceiling was measured. -c is arithmetic on
	// a round trip; -rps would be a number about the target's tolerance, and
	// nothing here has the standing to name one.
	if flags(p)["-rps"] || flags(p)["-rate"] {
		t.Errorf("command %q sets a rate cap, which would be a claim about a limit nobody measured", p.command)
	}

	text := p.command + " " + warningsJoined(p)
	for _, a := range p.advice {
		text += " " + a.flag + " " + a.why
	}
	for _, banned := range []string{"ramp", "until it", "find the limit", "how much it can take"} {
		if strings.Contains(text, banned) {
			t.Errorf("the plan mentions %q — the rate ceiling is not this tool's to discover", banned)
		}
	}
}

// The fast path skips the cookie jar entirely (see Client.FastDo). Suggesting it
// for a target that sets cookies is suggesting a run that silently sends none of
// them back, and the -solve case is worse: the clearance is earned and then
// never presented.
func TestRecommendNeverSuggestsFastWithoutAJar(t *testing.T) {
	t.Run("cookies", func(t *testing.T) {
		r := baseReport()
		r.cookies = []string{"__cf_bm", "session"}
		p := recommend(r, &options{})
		if strings.Contains(p.command, "-mode fast") {
			t.Errorf("command %q takes the jarless path against a target that sets cookies", p.command)
		}
		if !strings.Contains(reasonFor(p, "-mode"), "__cf_bm") {
			t.Error("the reason does not name the cookies that ruled fast mode out")
		}
	})

	t.Run("a clearance to replay", func(t *testing.T) {
		r := baseReport()
		r.challenge, r.challengeWhy = challengeCloudflare, "cf-mitigated: challenge"
		p := recommend(r, &options{})
		if strings.Contains(p.command, "-mode fast") {
			t.Errorf("command %q would earn a cf_clearance and then never send it", p.command)
		}
		if !strings.Contains(p.command, "-solve") {
			t.Errorf("command %q does not solve a Cloudflare challenge", p.command)
		}
	})

	t.Run("nothing to keep", func(t *testing.T) {
		p := recommend(baseReport(), &options{})
		if !strings.Contains(p.command, "-mode fast") {
			t.Errorf("command %q pays for a jar, redirects and retries the target does not need", p.command)
		}
	})
}

// -solve earns a cf_clearance and nothing else. Offering it against someone
// else's interstitial costs two minutes of browser and ends where it started.
func TestRecommendSolvesOnlyCloudflare(t *testing.T) {
	r := baseReport()
	r.challenge = challengeVendor
	r.challengeWhy = `a DataDome interstitial ("captcha-delivery.com" is in the page)`

	p := recommend(r, &options{})
	if strings.Contains(p.command, "-solve") {
		t.Errorf("command %q sends a Cloudflare solver at a DataDome wall", p.command)
	}
	if !strings.Contains(warningsJoined(p), "DataDome") {
		t.Errorf("the notes %q do not say what is actually in the way", warningsJoined(p))
	}
}

// A blocked target is not a solvable one, and saying so is the difference
// between an afternoon on a fingerprint and a minute on the real problem.
func TestRecommendReportsAPlainRefusal(t *testing.T) {
	r := baseReport()
	r.status = 403
	r.challenge, r.challengeWhy = challengeBlocked, "403 with no interstitial in it"

	p := recommend(r, &options{})
	if strings.Contains(p.command, "-solve") {
		t.Errorf("command %q solves a challenge that is not there", p.command)
	}
	// The note's job is not to repeat the refusal — the report has already said
	// it — but to say that the plan under it was measured against one.
	if !strings.Contains(warningsJoined(p), "refusal") {
		t.Errorf("the notes %q let the suggestion stand as though the target had answered",
			warningsJoined(p))
	}

	// And the report itself has to say so where the numbers are.
	var sb strings.Builder
	renderScout(&sb, r, p)
	if !strings.Contains(sb.String(), "of the refusal, not the page") {
		t.Error("the page size and assets are presented as the site's rather than the refusal's")
	}
}

// A target that redirects costs a round trip per request for a destination the
// scout already knows.
func TestRecommendPointsAtTheDestination(t *testing.T) {
	r := baseReport()
	r.finalURL = "https://site.test/en/"
	r.redirects = []string{"301 → https://site.test/en/"}

	p := recommend(r, &options{})
	if !strings.Contains(p.command, "https://site.test/en/") {
		t.Errorf("command %q still points at the hop rather than the page", p.command)
	}
	if strings.Contains(reasonFor(p, "the URL"), "") && reasonFor(p, "the URL") == "" {
		t.Error("the redirect was followed silently, with no reason given")
	}
}

func TestRecommendSessionsFollowTheProxyFile(t *testing.T) {
	t.Run("one session per exit", func(t *testing.T) {
		r := baseReport()
		r.proxyCount = 5
		p := recommend(r, &options{proxyFile: "p.txt"})
		if !strings.Contains(p.command, "-s 5") {
			t.Errorf("command %q does not spread across the 5 exits it has", p.command)
		}
		if !strings.Contains(p.command, "-proxy-file p.txt") {
			t.Errorf("command %q dropped the proxy file it was planned for", p.command)
		}
	})

	t.Run("more exits than workers is said out loud", func(t *testing.T) {
		r := baseReport()
		r.rtt = 10 * time.Millisecond // 100 req/s a thread, so -c 2 for 200
		r.proxyCount = 100
		p := recommend(r, &options{proxyFile: "p.txt"})
		if !strings.Contains(warningsJoined(p), "100 entries") {
			t.Errorf("the notes %q do not warn that most of the list would never be dialled",
				warningsJoined(p))
		}
	})
}

// The handshake is paid once per connection, and a run that pays it after the
// clock starts reports it as latency the target does not have.
func TestRecommendWarmsWhenTheHandshakeShows(t *testing.T) {
	r := baseReport()
	r.rtt, r.cold = 40*time.Millisecond, 400*time.Millisecond

	p := recommend(r, &options{})
	if !strings.Contains(p.command, "-warmup") {
		t.Errorf("command %q pays a 400ms handshake inside the measurement", p.command)
	}

	r.cold = 45 * time.Millisecond // nothing to win
	if p := recommend(r, &options{}); strings.Contains(p.command, "-warmup") {
		t.Errorf("command %q warms up for a handshake that costs nothing", p.command)
	}
}

// Which language is right is a question about where the exits are, so it is
// carried through when it has been answered and raised when it has not.
func TestRecommendLanguage(t *testing.T) {
	r := baseReport()
	r.localeAware, r.langWhy = true, "answers with Content-Language: en"

	if p := recommend(r, &options{}); strings.Contains(p.command, "-lang") {
		t.Errorf("command %q invented a language for a target it only knows varies", p.command)
	} else if !strings.Contains(warningsJoined(p), "Accept-Language") {
		t.Error("a locale-sensitive target was not mentioned at all")
	}

	if p := recommend(r, &options{lang: "tr-TR,tr;q=0.9"}); !strings.Contains(p.command, "-lang tr-TR,tr;q=0.9") {
		t.Errorf("command %q dropped the language the run was already set to", p.command)
	}
}

// -assets is honoured on the single-request path only, so recommending it inside
// a load command would be a flag that quietly does nothing.
func TestRecommendKeepsAssetsOutOfTheLoadCommand(t *testing.T) {
	r := baseReport()
	r.assets, r.assetHosts = 23, 2

	p := recommend(r, &options{})
	if strings.Contains(p.command, "-assets") {
		t.Errorf("command %q carries -assets into a duration run, where it does nothing", p.command)
	}
	if !strings.Contains(warningsJoined(p), "-assets") {
		t.Error("23 subresources went unmentioned")
	}
}

// HTTP/2 puts every request on one connection with a stream id one higher than
// the last, and a sustained run leaves a sequence in the tens of thousands that
// no fingerprint work covers — nothing in the ClientHello or the header order
// says anything about it.
func TestRecommendCyclesConnectionsBeforeTheStreamIDsDo(t *testing.T) {
	r := baseReport()
	r.rtt = 5 * time.Millisecond // 200 threads-worth of rate on very few threads

	p := recommend(r, &options{})
	if !strings.Contains(p.command, "-max-streams") {
		t.Errorf("command %q leaves one connection carrying every stream of the run", p.command)
	}
	// The reason has to show the count, or it is an unexplained magic number.
	why := reasonFor(p, "-max-streams")
	if !strings.Contains(why, "streams on each") {
		t.Errorf("the -max-streams reason %q does not say how many streams it is avoiding", why)
	}

	t.Run("not on HTTP/1.1, which has no stream ids at all", func(t *testing.T) {
		r := baseReport()
		r.rtt, r.proto = 5*time.Millisecond, "HTTP/1.1"
		if p := recommend(r, &options{}); strings.Contains(p.command, "-max-streams") {
			t.Errorf("command %q caps streams on a protocol that has none", p.command)
		}
	})

	// The run's total is rate times duration whatever the round trip is — a
	// slower target just needs more threads to hold the same rate — so what
	// decides this is how many connections the total is spread over. A wide
	// proxy list already spreads it: 40 sessions carry a few hundred streams
	// each, which is a browser's own order of magnitude and needs no cap.
	t.Run("not when the sessions already spread them thin", func(t *testing.T) {
		r := baseReport()
		r.proxyCount = 40
		p := recommend(r, &options{proxyFile: "p.txt"})
		if strings.Contains(p.command, "-max-streams") {
			t.Errorf("command %q caps a stream count that is already browser-shaped: %q",
				p.command, reasonFor(p, "-max-streams"))
		}
	})
}

// A widget on a page that was served is not a wall in front of it — but silence
// about it reads as the scout having missed it, on exactly the sites where
// someone would expect -solve.
func TestRecommendExplainsTurnstileWithoutSolving(t *testing.T) {
	r := baseReport()
	r.turnstile = true

	p := recommend(r, &options{})
	if strings.Contains(p.command, "-solve") {
		t.Errorf("command %q solves for a widget on a page that already arrived", p.command)
	}
	if !strings.Contains(warningsJoined(p), "Turnstile") {
		t.Error("the widget went unmentioned, so the absence of -solve looks like an oversight")
	}
}

// Not every target is a page, and the page-shaped advice does not transfer.
func TestRecommendNoticesANonDocument(t *testing.T) {
	r := baseReport()
	r.contentType = "application/json"

	p := recommend(r, &options{})
	if !strings.Contains(warningsJoined(p), "application/json") {
		t.Errorf("the notes %q treat a JSON endpoint as a page", warningsJoined(p))
	}
}

// The box's own link is a constraint people discover by watching a run fail and
// blaming the target for it.
func TestRecommendWeighsTheIngress(t *testing.T) {
	r := baseReport()
	r.bodySize = 550 << 10 // ~550 KiB at ~200 req/s is over a gigabit

	p := recommend(r, &options{})
	if !strings.Contains(warningsJoined(p), "ingress") {
		t.Errorf("the notes %q say nothing about a rate this link may not carry", warningsJoined(p))
	}

	r.bodySize = 2 << 10 // a small document costs nothing worth mentioning
	if p := recommend(r, &options{}); strings.Contains(warningsJoined(p), "ingress") {
		t.Error("a 2 KiB body raised a bandwidth warning")
	}
}

// Every flag the scout adds has to carry the observation that put it there. A
// flag with no reason is a flag nobody should paste, and the list of them is
// what separates this from a second copy of the help screen.
func TestEveryAddedFlagHasAReason(t *testing.T) {
	// The proxying is carried through from what was already given rather than
	// chosen here, so it is not the scout's to justify.
	carried := map[string]bool{"-proxy-file": true, "-proxy": true}

	for _, tc := range []struct {
		name string
		r    func() *scoutReport
		o    *options
	}{
		{"plain", baseReport, &options{}},
		{"challenged", func() *scoutReport {
			r := baseReport()
			r.challenge, r.challengeWhy = challengeCloudflare, "cf-mitigated: challenge"
			return r
		}, &options{}},
		{"through a list", func() *scoutReport {
			r := baseReport()
			r.proxyCount, r.cold = 8, time.Second
			r.localeAware, r.langWhy = true, "answers with Content-Language: en"
			return r
		}, &options{proxyFile: "p.txt", lang: "en-GB"}},
		{"unmeasurable", func() *scoutReport {
			r := baseReport()
			r.rtt, r.rttSamples, r.cold = 0, 0, 0
			return r
		}, &options{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := recommend(tc.r(), tc.o)
			for _, part := range strings.Fields(p.command) {
				if !strings.HasPrefix(part, "-") || carried[part] {
					continue
				}
				if reasonFor(p, part) == "" {
					t.Errorf("command %q carries %s with nothing beside it saying why", p.command, part)
				}
			}
			for _, a := range p.advice {
				if a.why == "" {
					t.Errorf("advice for %q has an empty reason", a.flag)
				}
			}
		})
	}
}

// The command is the deliverable, so it has to be one send would actually
// accept: the dials in the advertised order, and nothing left where a
// positional would be misread.
func TestSuggestedCommandParses(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    func() *scoutReport
		o    *options
	}{
		{"plain", baseReport, &options{}},
		{"challenged through a list", func() *scoutReport {
			r := baseReport()
			r.challenge, r.challengeWhy = challengeCloudflare, "cf-mitigated: challenge"
			r.proxyCount, r.cold = 6, time.Second
			return r
		}, &options{proxyFile: "p.txt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := recommend(tc.r(), tc.o)
			args := strings.Fields(p.command)
			if args[0] != "send" {
				t.Fatalf("command %q does not start with send", p.command)
			}
			o, target, err := parseFlags(args[1:])
			if err != nil {
				t.Fatalf("send cannot parse its own suggestion %q: %v", p.command, err)
			}
			if target == "" {
				t.Errorf("the suggestion %q carries no URL", p.command)
			}
			if o.duration <= 0 {
				t.Errorf("the suggestion %q lost its duration", p.command)
			}
			if o.sessions > o.concurrency {
				t.Errorf("the suggestion %q asks for %d sessions across %d workers, which send rejects",
					p.command, o.sessions, o.concurrency)
			}
		})
	}
}

// The report is colour on a terminal and plain everywhere else, the same rule
// the help screen follows and for the same reason: this one is far more likely
// to be piped somewhere.
func TestScoutReportIsPlainWhenNotATerminal(t *testing.T) {
	var sb strings.Builder
	r := baseReport()
	r.edge, r.edgeWhy = "Cloudflare", "cf-ray"
	renderScout(&sb, r, recommend(r, &options{}))

	if strings.ContainsRune(sb.String(), 0x1b) {
		t.Error("the report carried ANSI escape codes into a non-terminal writer")
	}
	for _, want := range []string{"scouting", "suggested", "send -mode fast"} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("the report does not contain %q:\n%s", want, sb.String())
		}
	}
}

// Long reasons wrap into their own column. Running back to the margin turns the
// page into prose and loses which flag a line belongs to.
func TestReportStaysInsideItsColumns(t *testing.T) {
	var sb strings.Builder
	r := baseReport()
	r.challenge, r.challengeWhy = challengeCloudflare, "cf-mitigated: challenge"
	r.proxyCount, r.cold = 40, time.Second
	r.edge, r.edgeWhy = "Cloudflare", "cf-ray, cf-cache-status, server: cloudflare"
	renderScout(&sb, r, recommend(r, &options{proxyFile: "proxies.txt"}))

	for _, line := range strings.Split(sb.String(), "\n") {
		// The command is the one line that must not wrap: broken in two it no
		// longer pastes, which is the only thing it is for.
		if line == "" || strings.Contains(line, "> send ") {
			continue
		}
		if n := len([]rune(line)); n > pageWidth+len(indent)*2 {
			t.Errorf("line runs to %d columns:\n%s", n, line)
		}
		// Headings and the rule sit at one indent, everything else at two. A
		// wrapped line that lost its hanging indent lands at zero, which is
		// what this catches.
		if !strings.HasPrefix(line, indent) {
			t.Errorf("a line starts outside the page margin: %q", line)
		}
	}
}
