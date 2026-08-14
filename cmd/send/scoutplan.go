package main

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// From a report to a command line.
//
// This half is pure: it takes what the probes found and the flags already given,
// and returns the command and the reason for every flag in it. No network, so it
// is testable against a made-up report, and — more to the point — every claim it
// makes is traceable to a measurement rather than to a default someone picked
// once and nobody revisited.
//
// A flag with no reason beside it does not go in. That rule is doing real work:
// it is what keeps the suggestion from becoming a list of everything the tool
// can do, which is what the help screen is for.

// scoutDuration is how long the suggested run is written for. The clock is the
// one dial scouting cannot measure — it is a question about what you want, not
// about the target — so it is a round number, and the report says so.
const scoutDuration = "30s"

// advice is one flag in the suggestion and the observation that put it there.
type advice struct {
	flag string
	why  string
}

// plan is the command a report leads to.
type plan struct {
	command  string
	advice   []advice
	warnings []string
}

// recommend turns a report into the command to run against it.
func recommend(r *scoutReport, o *options) plan {
	var (
		p    plan
		pre  []string // flags before the URL: the ones that shape the run
		post []string // flags after the dials, where the usage text puts them
	)
	add := func(flag, why string) { p.advice = append(p.advice, advice{flag: flag, why: why}) }
	warn := func(format string, args ...any) {
		p.warnings = append(p.warnings, fmt.Sprintf(format, args...))
	}

	// Where to point. A target that redirects costs a round trip per request for
	// a destination that is already known by the time this prints.
	target := r.target
	if r.finalURL != "" && r.finalURL != r.target {
		target = r.finalURL
		add("the URL", fmt.Sprintf("%s redirects here; pointing straight at it saves a round trip on every request",
			r.target))
	}

	// What is in the way, and whether this tool has an answer for it.
	switch r.challenge {
	case challengeCloudflare:
		pre = append(pre, "-solve")
		add("-solve", r.challengeWhy+" — earn a cf_clearance in a real browser and replay it. Implies -p chrome")
		if o.proxy == "" && o.proxyFile == "" {
			warn("the clearance is bound to the address that earns it, so one solved here works only from here; -proxy-file solves once per exit instead")
		}
	case challengeVendor:
		warn("%s. -solve earns a cf_clearance and nothing else, so it has no answer for this one", r.challengeWhy)
	case challengeBlocked:
		// The field above already says what happened; repeating it here would
		// spend a note on something the reader has just read. What is worth
		// adding is that everything under "suggested" was planned against a
		// page that refused, and is a shape rather than a way in.
		warn("everything below is measured against that refusal, so it describes the shape of a run rather than a way past one — a wall with no puzzle in it is usually the URL, the method or a credential rather than the fingerprint")
	}

	// Mode. The fast path has no cookie jar at all, and that is invisible until
	// a target that needs one silently gets none.
	switch {
	case r.challenge == challengeCloudflare:
		add("-mode client", "the default, and required here: -mode fast has no cookie jar, so the clearance -solve earns would never be sent")
	case len(r.cookies) > 0:
		add("-mode client", fmt.Sprintf("the default: the target sets %s, and -mode fast has no jar to keep it in",
			strings.Join(r.cookies, ", ")))
	default:
		pre = append(pre, "-mode fast")
		add("-mode fast", "the target sets no cookies and the URL above needs no redirect — nothing the jar, the redirect chain or the retry loop is for")
	}

	// -c, from the round trip rather than from a probe.
	//
	// A thread holds one request open for as long as the round trip takes, so it
	// carries 1/rtt requests a second and no more. Concurrency is therefore the
	// rate dial, and the arithmetic is printed rather than the conclusion so any
	// other rate can be read straight off it.
	concurrency := scoutFallbackConcurrency
	if r.rtt > 0 {
		perThread := float64(time.Second) / float64(r.rtt)
		concurrency = max(int(math.Ceil(float64(scoutRate)/perThread)), 1)
		add(fmt.Sprintf("-c %d", concurrency), fmt.Sprintf(
			"a thread carries ~%s req/s at %s, so %d of them is about %d req/s — and -c is the rate dial here, not -rps. Want %d? -c %d",
			trimFloat(perThread), round(r.rtt), concurrency, scoutRate,
			10*scoutRate, max(int(math.Ceil(float64(10*scoutRate)/perThread)), 1)))
	} else {
		add(fmt.Sprintf("-c %d", concurrency), "send's own default for a timed run — the round trip never came back, so this one number is a default rather than arithmetic")
		warn("nothing could be timed, so -c is the only line below that is not a measurement")
	}

	// -s, which is how many identities the threads spread across.
	sessions := 1
	switch {
	case r.proxyCount > 1:
		sessions = min(r.proxyCount, concurrency)
		add(fmt.Sprintf("-s %d", sessions), fmt.Sprintf(
			"one session per entry in %s — each with its own cookie jar, connection pool and pinned exit",
			o.proxyFile))
		if r.proxyCount > concurrency {
			warn("%s has %d entries but -c is %d, and a session needs a worker — only %d of them would ever be dialled. Raise -c (the rate rises with it) or trim the list",
				o.proxyFile, r.proxyCount, concurrency, concurrency)
		}
	case concurrency >= 2:
		sessions = 2
		add("-s 2", "one session is one HTTP/2 connection behind one write lock, and a second measured ~28% over the first")
	}

	// -warmup, when the handshake is worth paying before the clock starts.
	if r.cold > 0 && r.rtt > 0 && r.cold > 2*r.rtt {
		n := 1
		if strings.HasPrefix(r.proto, "HTTP/1") {
			// HTTP/1.1 has no multiplexing, so a session needs a connection per
			// worker rather than the one h2 shares.
			n = max(concurrency/max(sessions, 1), 1)
		}
		post = append(post, "-warmup", strconv.Itoa(n))
		add(fmt.Sprintf("-warmup %d", n), fmt.Sprintf(
			"the first request cost %s against %s warm; the difference is DNS and the handshake, and this pays it before the clock starts",
			round(r.cold), round(r.rtt)))
	}

	// -lang, when the target's answer depends on it. Which value is right is a
	// question about where the exits are, so it is only carried through when it
	// has already been answered.
	if r.localeAware {
		if o.lang != "" {
			post = append(post, "-lang", o.lang)
			add("-lang "+o.lang, r.langWhy+", and this is the one you asked for")
		} else {
			warn("this target varies by Accept-Language (%s), so -lang is a content decision here and not only a fingerprint one — the default is en-US", r.langWhy)
		}
	}

	// The proxying already chosen, carried into the command so it can be pasted
	// rather than edited.
	switch {
	case o.proxyFile != "":
		post = append(post, "-proxy-file", o.proxyFile)
	case o.proxy != "":
		post = append(post, "-proxy", o.proxy)
	}

	if strings.HasPrefix(r.proto, "HTTP/1") {
		warn("the target negotiated %s rather than h2, so the HTTP/2 fingerprint is not in play and every request in flight needs its own connection", r.proto)
	}
	// The assets belong to whatever came back, and what came back was a wall.
	if r.assets > 0 && r.challenge == challengeNone {
		warn("the page pulls in %d subresources across %d host(s), and a document with nothing following it is not what a page load looks like — -assets fetches them, on the single-request form (drop the duration)",
			r.assets, r.assetHosts)
	}
	for _, note := range r.notes {
		warn("%s", note)
	}

	// The dials go in as flags rather than in their positional form, even though
	// the positional form is shorter and is what the help screen shows. This
	// command is printed above a list that explains it one flag at a time, and
	// `30s 10 2` cannot be matched to `-c 10` by anyone who does not already
	// know the order — which is the audience.
	add("-t "+scoutDuration, "a round number: how long to run is a question about what you want, and the only dial here that is not a measurement")

	parts := append([]string{"send"}, pre...)
	parts = append(parts, target, "-t", scoutDuration, "-c", strconv.Itoa(concurrency))
	if sessions > 1 {
		parts = append(parts, "-s", strconv.Itoa(sessions))
	}
	p.command = strings.Join(append(parts, post...), " ")
	return p
}

// scoutFallbackConcurrency is what -c falls back to when the round trip could
// not be measured. It is the same default the tool already uses for a duration
// run, so an unmeasurable target lands on the documented behaviour rather than
// on a number invented here.
const scoutFallbackConcurrency = 50

// trimFloat prints a rate without a decimal point it has no precision for.
func trimFloat(v float64) string {
	if v >= 10 {
		return strconv.Itoa(int(math.Round(v)))
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// renderScout writes the report and the plan.
//
// Same two tones as the help screen and the same width, because they are read
// in the same terminal minutes apart: red for what the eye should land on, grey
// for everything supporting it, and nothing at all when the writer is not a
// terminal.
func renderScout(w io.Writer, r *scoutReport, p plan) {
	pal := paletteFor(w)

	fmt.Fprintf(w, "\n%s%ssend%s %sscouting%s %s%s%s\n",
		indent, pal.name, pal.reset, pal.dim, pal.reset, pal.cmd, r.target, pal.reset)
	fmt.Fprintf(w, "%s%s%s%s\n\n", indent, pal.rule, strings.Repeat("─", pageWidth), pal.reset)

	for _, f := range scoutFields(r) {
		fmt.Fprint(w, pal.field(f.name, f.value))
	}

	fmt.Fprint(w, pal.heading("suggested"))
	fmt.Fprintf(w, "\n%s%s%s>%s %s%s%s\n\n",
		indent, indent, pal.name, pal.reset, pal.cmd, p.command, pal.reset)
	for _, a := range p.advice {
		fmt.Fprint(w, pal.reason(a.flag, a.why))
	}

	if len(p.warnings) > 0 {
		fmt.Fprint(w, pal.heading("notes"))
		for _, note := range p.warnings {
			fmt.Fprint(w, pal.bullet(note))
		}
	}
	fmt.Fprintln(w)
}

// scoutFields is the report as label-and-value lines, in the order they answer
// the questions someone actually has: where am I looking from, what came back,
// who is in front, did they stop me, and how far away is it.
func scoutFields(r *scoutReport) []struct{ name, value string } {
	out := []struct{ name, value string }{}
	field := func(name, format string, args ...any) {
		out = append(out, struct{ name, value string }{name, fmt.Sprintf(format, args...)})
	}

	if r.via != "" {
		field("seen from", "%s", r.via)
	} else {
		field("seen from", "this machine — no proxy, so this is what your own address sees")
	}
	field("answered", "%d %s over %s", r.status, statusText(r.status), r.proto)

	if r.edge != "" {
		field("edge", "%s — %s", r.edge, r.edgeWhy)
	} else {
		field("edge", "nothing announced itself")
	}

	switch r.challenge {
	case challengeNone:
		field("challenge", "none from this address")
	case challengeCloudflare:
		field("challenge", "Cloudflare — %s", r.challengeWhy)
	case challengeVendor:
		field("challenge", "%s", r.challengeWhy)
	case challengeBlocked:
		field("challenge", "blocked — %s", r.challengeWhy)
	}

	if len(r.redirects) > 0 {
		field("redirects", "%s", strings.Join(r.redirects, "  →  "))
	} else {
		field("redirects", "none")
	}

	if len(r.cookies) > 0 {
		field("cookies", "%s", strings.Join(r.cookies, ", "))
	} else {
		field("cookies", "none set")
	}

	page := humanBytes(int64(r.bodySize))
	if r.encoding != "" {
		page += ", " + r.encoding
	}
	if r.assets > 0 {
		page += fmt.Sprintf(", %d assets across %d host(s)", r.assets, r.assetHosts)
	}
	// Whatever was measured, it was measured on whatever came back — and what
	// came back was not the page. Reporting it as the page's would be a number
	// about the wrong document.
	switch r.challenge {
	case challengeCloudflare, challengeVendor:
		page += " — of the interstitial, not the page"
	case challengeBlocked:
		page += " — of the refusal, not the page"
	}
	field("page", "%s", page)

	if r.localeAware {
		field("language", "%s", r.langWhy)
	} else {
		field("language", "the same answer in ja-JP as in the default")
	}

	switch {
	case r.rtt > 0:
		field("round trip", "%s (median of %d), %s cold with the handshake",
			round(r.rtt), r.rttSamples, round(r.cold))
	case r.cold > 0:
		field("round trip", "%s for the first request; the warm ones never came back", round(r.cold))
	}
	if r.proxyCount > 1 {
		field("proxies", "%d entries in the file", r.proxyCount)
	}
	return out
}

// The three shapes this page needs on top of what the help screen uses. Padding
// is measured on the plain text: the colour codes have no width on screen but do
// have length in the string, so %-14s would count them and pull every value out
// of line.
const (
	scoutFieldWidth  = 14
	scoutReasonWidth = 16
)

// field is one label-and-value line of the report.
func (p palette) field(name, value string) string {
	pad := max(scoutFieldWidth-len([]rune(name)), 1)
	body := indentWrap(value, indent+indent+strings.Repeat(" ", scoutFieldWidth), pageWidth-scoutFieldWidth-4)
	return indent + indent + p.dim + name + p.reset + strings.Repeat(" ", pad) +
		p.cmd + body + p.reset + "\n"
}

// reason is one flag of the suggestion with what put it there.
func (p palette) reason(flag, why string) string {
	pad := max(scoutReasonWidth-len([]rune(flag)), 1)
	body := indentWrap(why, indent+indent+strings.Repeat(" ", scoutReasonWidth), pageWidth-scoutReasonWidth-4)
	return indent + indent + p.cmd + flag + p.reset + strings.Repeat(" ", pad) +
		p.dim + body + p.reset + "\n"
}

// bullet is one line of the notes.
func (p palette) bullet(text string) string {
	body := indentWrap(text, indent+indent+"  ", pageWidth-4)
	return indent + indent + p.rule + "·" + p.reset + " " + p.dim + body + p.reset + "\n"
}

// indentWrap breaks text to width and hangs the continuation lines under a
// prefix, so a wrapped value stays inside its own column instead of running back
// to the margin.
func indentWrap(text, prefix string, width int) string {
	if width < 20 {
		width = 20
	}
	var (
		lines []string
		line  string
	)
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len([]rune(line))+1+len([]rune(word)) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n"+prefix)
}
