package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// -solve earns a cf_clearance with the real browser in solver/ and seeds it
// into every session before the run starts.
//
// The three things Cloudflare binds that cookie to — User-Agent, JA3/JA4, and
// source IP — all have to survive the handover from the browser that earned it
// to the client that replays it:
//
//   - the UA comes back in the solver's output and is pinned onto the run,
//     rather than assumed to match.
//   - the TLS layer is why this only runs against the Chrome profile. The
//     solver drives a real Chromium; replaying its cookie from the Safari
//     profile presents a JA4 the cookie was never issued to.
//   - the IP is why the proxy is handed to the solver. Solving from this box and
//     replaying from an exit node fails exactly like a UA mismatch does, and
//     just as quietly. With -proxy-file that binding is per exit rather than per
//     run, which is what solvefleet.go is about.
//
// A mismatch in any of them does not fail loudly. It produces a cookie that
// works for the first request and dies under load, which is indistinguishable
// from the target simply blocking the client.

// minSolveTimeout is the smallest -solve-timeout worth accepting. Chromium
// under Xvfb takes several seconds to come up before the challenge is even
// requested.
const minSolveTimeout = 10 * time.Second

// defaultSolveTimeout is generous on purpose. Chromium under Xvfb takes ~20s to
// come up and that comes out of every attempt, so the old 75s left a managed
// challenge almost no time to actually solve in. Measured against a live UAM:
// 75s failed with no cookie, 150s+ solved on the first attempt in 71s. It is a
// ceiling, not a wait — a fast box finishes early.
const defaultSolveTimeout = 150 * time.Second

// solveResult is what solver/index.js prints.
type solveResult struct {
	Status    string `json:"status"`
	Error     string `json:"error"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent"`
	// AcceptLanguage is what the browser actually put on the wire, which is not
	// always what it was asked for: Chromium regenerates the header from the
	// first tag of --accept-lang and drops the rest.
	AcceptLanguage string `json:"accept_language"`
	// PageLanguages is navigator.languages as the solved page reported it. It
	// exists to be compared against AcceptLanguage: the header is what the
	// server sees, this is what the challenge's JavaScript sees, and a solve
	// where they disagree is a browser no ordinary Chrome install produces.
	PageLanguages []string `json:"page_languages"`
	// Timezone is Intl's resolved zone as the solved page reported it. Nothing
	// on this side replays it — no JS, no timezone on the wire — but it is read
	// back so the run can say when the solve ran in a zone no browser reports.
	Timezone      string         `json:"timezone"`
	Cookies       string         `json:"cookies"`
	CookieList    []solvedCookie `json:"cookie_list"`
	DurationMS    int64          `json:"duration_ms"`
	Attempts      int            `json:"attempts"`
	Exit          string         `json:"exit"` // batch only: the id this line answers for
	Chromium      string         `json:"chromium_version"`
	ChromiumMajor int            `json:"chromium_major"`
	Proxy         string         `json:"proxy"`
	LaunchMS      int64          `json:"launch_ms"`
}

type solvedCookie struct {
	Name    string  `json:"name"`
	Value   string  `json:"value"`
	Domain  string  `json:"domain"`
	Expires float64 `json:"expires"`
}

// solveSeed is one solved identity: the cookies one exit earned, the UA they
// were issued to, and the proxy that has to replay them.
//
// A run with a single exit has one of these and it covers every session. A run
// with -proxy-file has one per exit, and a session may only ever use its own —
// the source IP is part of what the cookie is bound to, so the pairing has to
// hold all the way into the session pool.
type solveSeed struct {
	proxy     string
	userAgent string
	// acceptLanguage is the header the solve actually sent, which is not always
	// the one it was asked for — Chromium regenerates it from the first tag and
	// drops the rest, so -lang "tr-TR,tr;q=0.9,en;q=0.8" solves under
	// "tr-TR,tr;q=0.9". Replaying the asked-for value would advertise a language
	// the session that earned the cookie never did.
	acceptLanguage string
	// pageLanguages is navigator.languages as the solved page reported it, kept
	// beside the header so reportLanguageSplit can compare the two. Not replayed
	// — nothing on this side can set a page object — but a disagreement is worth
	// naming, since it is the shape of two separate bugs this repo has shipped.
	pageLanguages []string
	// timezone is Intl's resolved zone in the solved page. Not replayed either —
	// there is no timezone on the wire — but a solve that ran in a zone no
	// browser reports is worth saying out loud rather than leaving in the JSON.
	timezone      string
	cookies       []string
	chromiumMajor int
	// expiresAt is when the cf_clearance stops being worth anything, zero when
	// the solve produced none. A fleet solve can outlast it — see
	// warnOnExpiredSeeds.
	expiresAt time.Time
}

// solveLog serialises the progress lines. Exits solve in parallel, and a
// message assembled from several writes would interleave with another exit's.
var solveLog sync.Mutex

// logSolve prints a message tagged with the exit it came from. Credentials are
// stripped: a proxy list is usually user:pass@host, and a run's stderr ends up
// in terminals, log files and pasted issue reports.
//
// Every line gets the tag, not just the first. A warning under a bare margin
// belongs to whichever exit the reader last saw a tag for, which during a
// parallel solve is not the one that raised it.
func logSolve(proxy, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if proxy != "" {
		tag := redactProxy(proxy) + ": "
		msg = tag + strings.ReplaceAll(msg, "\n", "\n"+tag)
	}
	solveLog.Lock()
	defer solveLog.Unlock()
	fmt.Fprintln(os.Stderr, msg)
}

// acceptLanguage is the Accept-Language this run will replay with, which is
// what the solve has to advertise too.
//
// Cloudflare does not bind cf_clearance to the language, but the challenge is
// served in it and the score is computed from the whole request: a solve that
// asked for de-DE and a replay that asks for en-US are not the same client, and
// the difference costs nothing to remove. The library's default is read rather
// than repeated so the two cannot drift apart.
func acceptLanguage(o *options) string {
	if o.lang != "" {
		return o.lang
	}
	return gofire.DefaultAcceptLanguage
}

// redactProxy renders a proxy URL without its password.
func redactProxy(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Redacted()
	}
	// The host:port:user:pass shorthand is not a URL, so url.Parse leaves it
	// alone rather than redacting it. Cut it by shape instead of printing the
	// credentials.
	if parts := strings.SplitN(raw, ":", 4); len(parts) == 4 {
		return parts[0] + ":" + parts[1]
	}
	return raw
}

// splitSolvedCookies divides what the solve captured into the cookies worth
// replaying and the ones that belong to the browser session that earned them.
//
// Not everything in the jar is a credential this client can carry. Three kinds
// come back from a solve and only two of them travel:
//
//   - cf_clearance is the point of the exercise. It is bound to the address, the
//     User-Agent and the TLS fingerprint, all three of which -solve exists to
//     reproduce, and it is meant to be presented on later requests.
//   - the target's own cookies — a session, a consent flag — are the site's, and
//     dropping them would break whatever the run is actually doing.
//   - Cloudflare's session bookkeeping is neither. __cf_bm is minted for one
//     browser session and read back by the edge on the next request; cf_chl_*
//     and __cf_chl_* track a challenge that is in progress. Replaying those from
//     a different client does not carry anything forward — it presents the edge
//     with a token whose contents describe a session this connection is not, and
//     invites exactly the interstitial the clearance was earned to avoid.
//
// This is reasoning about what the cookies are for, and not a measurement — a
// distinction worth stating here because it was briefly claimed as one. Two runs
// against a live zone differed in both their cookie set and their outcome: one
// cookie and a 200, two cookies and a challenge. That looked like evidence.
// replay.js then asked the question directly and answered no: on that address,
// at that hour, cf_clearance presented *alone* from a real Chromium was
// challenged too — as was a clearance the same browser had just earned, in the
// very context it earned it in. The address had changed state between the two
// runs, so the cookie set was never the variable. See Known gaps.
//
// The filtering stands on its own terms — a token minted for another session is
// not a credential, and withholding one costs nothing — but it should not be
// expected to rescue a run. -solve-all-cookies flips it back, and the held-back
// names are printed rather than dropped in silence.
//
// A browser that is *not* handed a __cf_bm simply gets a fresh one on its first
// response, which is what any newly-opened browser does. There is nothing to
// lose by withholding it — as long as there is a clearance to withhold it in
// favour of. Which is the one case this must not apply to: a zone running Bot
// Fight Mode alone never issues cf_clearance, and there __cf_bm is not
// bookkeeping beside the credential, it is the only thing the solve earned.
// Holding it back would leave the run with an empty jar and no way to tell.
func splitSolvedCookies(cookies []solvedCookie, keepAll bool) (kept, dropped []solvedCookie) {
	if !keepAll && !hasClearance(cookies) {
		keepAll = true
	}
	for _, c := range cookies {
		switch {
		case keepAll, !sessionBoundCookie(c.Name):
			kept = append(kept, c)
		default:
			dropped = append(dropped, c)
		}
	}
	return kept, dropped
}

// hasClearance reports whether this jar carries the cookie the rest of the
// filtering is in service of.
func hasClearance(cookies []solvedCookie) bool {
	return slices.ContainsFunc(cookies, func(c solvedCookie) bool {
		return c.Name == "cf_clearance"
	})
}

// sessionBoundCookie reports whether a name is one of Cloudflare's per-session
// tokens, as opposed to cf_clearance or a cookie belonging to the site.
//
// Matched by prefix because the challenge cookies carry a ray id or a variant
// suffix — cf_chl_rc_m, __cf_chl_tk — and an exact list would go stale the next
// time Cloudflare adds one. cf_clearance is checked first: it shares the "cf_"
// start with the very cookies being excluded, so name order here is load
// bearing.
func sessionBoundCookie(name string) bool {
	if name == "cf_clearance" {
		return false
	}
	for _, prefix := range []string{"__cf_bm", "cf_chl_", "__cf_chl_", "cf_chl", "__cflb"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// cookieNames renders a cookie list for the report — names only. The values are
// credentials and this goes to stderr, which ends up in logs and pasted issues.
func cookieNames(cookies []solvedCookie) string {
	if len(cookies) == 0 {
		return "no cookies"
	}
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, c.Name)
	}
	return strings.Join(names, ", ")
}

// clearance returns the cf_clearance cookie, if the solve produced one.
func (r *solveResult) clearance() (solvedCookie, bool) {
	for _, c := range r.CookieList {
		if c.Name == "cf_clearance" {
			return c, true
		}
	}
	return solvedCookie{}, false
}

// runSolver shells out to solver/index.js and returns what it solved.
//
// It is a separate process rather than a library call because the solve needs a
// real browser: the whole point is that a genuine Chromium TLS handshake and JS
// runtime answer the challenge, which is precisely what this client cannot do.
//
// The exit is a parameter rather than a field of o because a -proxy-file run
// calls this once per proxy, concurrently. One process solves through one exit;
// the browser has a single --proxy-server and there is nothing to rotate inside
// it.
func runSolver(ctx context.Context, o *options, target, proxy string) (*solveResult, error) {
	script := filepath.Join(o.solverDir, "index.js")
	if err := checkSolverDir(o); err != nil {
		return nil, err
	}

	// The solver gets its own budget plus a margin: it has its own watchdog at
	// timeout+30s, and killing it from here first would leave the Chromium tree
	// to its exit handlers rather than letting it report what it found.
	solveCtx, cancel := context.WithTimeout(ctx, o.solveTimeout+45*time.Second)
	defer cancel()

	seconds := int(o.solveTimeout.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	cmd := exec.CommandContext(solveCtx, "node", script, target, strconv.Itoa(seconds))
	cmd.Stderr = os.Stderr // puppeteer's launch diagnostics are worth seeing

	// The solver's identity is set rather than inherited — see solverEnv.
	cmd.Env = solverEnv(proxy, acceptLanguage(o))

	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("node not found in PATH; -solve needs Node.js")
		}
		return nil, fmt.Errorf("run %s: %w", script, err)
	}

	res, perr := parseSolveOutput(out)
	if perr != nil {
		return nil, fmt.Errorf("parse %s output: %w", script, perr)
	}
	if res.Status == "error" {
		msg := res.Error
		if msg == "" {
			msg = "solve failed"
		}
		return nil, fmt.Errorf("solver: %s", msg)
	}
	return res, nil
}

// parseSolveOutput extracts the result object from the script's stdout.
//
// index.js prints one JSON object and nothing else, so the whole output
// normally parses directly. The line fallback exists because a dependency deep
// in puppeteer's tree can print a banner first, and a solve that worked should
// not be thrown away over a warning. Scanning backwards means the result —
// always last — wins over any preamble.
func parseSolveOutput(out []byte) (*solveResult, error) {
	if res, err := decodeSolve(out); err == nil {
		return res, nil
	}
	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if res, err := decodeSolve([]byte(line)); err == nil {
			return res, nil
		}
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, errors.New("the solver produced no output")
	}
	return nil, fmt.Errorf("no JSON object in %q", truncate(strings.TrimSpace(string(out)), 200))
}

// decodeSolve unmarshals one result object, rejecting anything without a status
// so a stray JSON line from a dependency is not mistaken for the result.
func decodeSolve(b []byte) (*solveResult, error) {
	var res solveResult
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	if res.Status == "" {
		return nil, errors.New("JSON object has no status field")
	}
	return &res, nil
}

// solveAndSeed earns one identity for the whole run and folds it into the
// options the session pool is about to be built from, so the solved cookies and
// UA arrive through the same paths -cookie and -ua already use.
//
// This is the single-exit path: no proxy at all, or one -proxy every session
// shares. A -proxy-file run goes through solveAcrossProxies instead, because
// there the identity is per session rather than per run.
func solveAndSeed(ctx context.Context, o *options, profile gofire.BrowserProfile, target string) error {
	// Even one proxy is worth measuring: a rotating gateway cannot hold a
	// cf_clearance, and finding that out here costs a second rather than a
	// solve followed by a run that 403s from its first request.
	only := exit{proxy: o.proxy}
	if o.proxy != "" {
		exits, err := resolveExits(ctx, o, profile, []string{o.proxy})
		if err != nil {
			return err
		}
		only = exits[0]
	}

	seed, err := solveOne(ctx, o, target, only)
	if err != nil {
		return err
	}
	reportSolveDrift(seed, o)

	// The UA the cookie was issued to wins over the profile's default, but not
	// over an explicit -ua: an override the user typed is a deliberate choice,
	// and silently replacing it would hide the mismatch rather than surface it.
	switch {
	case o.userAgent == "":
		o.userAgent = seed.userAgent
	case seed.userAgent != "" && o.userAgent != seed.userAgent:
		fmt.Fprintf(os.Stderr, "warning: -ua differs from the UA the cookie was issued to.\n"+
			"  issued to %s\n  replaying %s\n", seed.userAgent, o.userAgent)
	}

	o.cookies = append(o.cookies, seed.cookies...)
	return nil
}

// solveOne earns the identity for one exit — or reuses a cached one — and
// returns it without touching the run's options.
//
// It is the unit both paths are built from, so a single-exit run and one exit of
// a fleet cost, cache and report the same thing. It holds no shared state:
// solveAcrossProxies calls it from several goroutines at once.
func solveOne(ctx context.Context, o *options, target string, e exit) (*solveSeed, error) {
	proxy := e.proxy

	// A cookie that is still valid is worth more than a fresh one: it costs
	// nothing and it is the same cookie. Most of a solve is the edge's own
	// challenge, so this is the only real answer to "the solve takes too long".
	//
	// The key is the exit's identity rather than the proxy string, so two
	// entries that leave from one address share the entry — which is the same
	// reason they share a solve.
	if !o.solveRefresh {
		if hit := loadSolveCache(o.solveCache, target, e.identity(), o.solveMaxAge); hit != nil {
			return seedFromCache(proxy, hit, o.solveAllCookies), nil
		}
	}

	where := "direct"
	if proxy != "" {
		where = "via " + e.label()
	}
	logSolve(proxy, "solving %s with the browser in %s/ (%s, up to %s)",
		target, o.solverDir, where, o.solveTimeout)

	res, err := runSolver(ctx, o, target, proxy)
	if err != nil {
		return nil, err
	}

	return seedFromResult(o, target, e, res), nil
}

// seedFromResult turns one solver result into the seed a session replays, and
// reports what it cost.
//
// Shared by the one-browser-per-exit path and the batch, so an exit is reported
// and cached the same way whichever produced it — the batch would otherwise be
// a second place for the cache write to be forgotten.
func seedFromResult(o *options, target string, e exit, res *solveResult) *solveSeed {
	proxy := e.proxy
	cf, gotClearance := res.clearance()

	// Assembled and printed as one write. The exits of a -proxy-file run solve
	// in parallel, and a report built from four Fprintf calls arrives
	// interleaved with three other exits' — which is how a warning ends up
	// under the wrong proxy.
	// Named rather than counted. "2 cookie(s)" and "1 cookie(s)" was the entire
	// visible difference between a solve that replayed as 200 and one that
	// replayed as 403, and neither line said which cookies — so the one thing
	// worth knowing was the one thing not printed.
	kept, dropped := splitSolvedCookies(res.CookieList, o.solveAllCookies)
	report := fmt.Sprintf("solved in %s, %d attempt(s), chromium %s\nseeding %s",
		round(time.Duration(res.DurationMS)*time.Millisecond), res.Attempts,
		res.Chromium, cookieNames(kept))
	if len(dropped) > 0 {
		report += fmt.Sprintf("\nheld back %s — bound to the browser session that earned them, "+
			"not to the client replaying it (-solve-all-cookies to send them anyway)",
			cookieNames(dropped))
	}

	// The budget is what the browser startup does not eat. A challenge with a
	// Turnstile widget needs 15-30s of it, and a launch on a small VPS takes
	// 20s of every attempt — which is how a run fails with no cookie at all
	// while looking like the target simply refused. A batch pays that launch
	// once for the whole list, so this only fires on the path that pays it per
	// exit.
	if launch := time.Duration(res.LaunchMS) * time.Millisecond; launch > 0 {
		if solving := o.solveTimeout - launch*time.Duration(max(res.Attempts, 1)); solving < 20*time.Second {
			report += fmt.Sprintf("\nnote: browser startup took %s of the %s budget — "+
				"raise -solve-timeout if the challenge does not clear", round(launch), o.solveTimeout)
		}
	}

	switch {
	case gotClearance:
		report += fmt.Sprintf("\ncf_clearance issued for %s", cf.Domain)
	default:
		// Worth continuing: a site behind Bot Fight Mode alone never issues a
		// clearance cookie, and the __cf_bm the solve did earn is still the
		// thing that carries the session.
		report += "\nwarning: no cf_clearance — the target may not use UAM, " +
			"or the challenge was not solved. Seeding what was captured anyway."
	}
	logSolve(proxy, "%s", report)

	seed := &solveSeed{
		proxy:          proxy,
		userAgent:      res.UserAgent,
		acceptLanguage: res.AcceptLanguage,
		pageLanguages:  res.PageLanguages,
		timezone:       res.Timezone,
		chromiumMajor:  res.ChromiumMajor,
	}
	if gotClearance && cf.Expires > 0 {
		seed.expiresAt = time.Unix(int64(cf.Expires), 0)
	}
	for _, c := range kept {
		seed.cookies = append(seed.cookies, c.Name+"="+c.Value)
	}
	if gotClearance {
		storeSolveCache(o.solveCache, target, e.identity(), res)
	}
	return seed
}

// reportSolveDrift checks the solved identity against the one this client will
// replay it with, and says so rather than silently living with a difference.
//
// A fleet solve calls this once rather than once per exit. Every exit drives the
// same local Chromium, so drift is a property of this box, and repeating it per
// proxy would bury the per-exit results under copies of one warning.
func reportSolveDrift(seed *solveSeed, o *options) {
	reportUADrift(seed.userAgent)
	reportChromiumDrift(seed.chromiumMajor)
	reportLanguageDrift(seed.acceptLanguage, acceptLanguage(o))
	reportLanguageSplit(seed.acceptLanguage, seed.pageLanguages)
	reportTimezone(seed.timezone)
}

// reportTimezone says so when the solve ran in something that is not a timezone.
//
// Intl answers from ICU, and ICU answers from TZ. On a container with no
// /etc/localtime and no TZ — every minimal Docker image and most small VPS
// builds — it resolves to "Etc/Unknown", which is not a zone any installed
// browser reports. A challenge reads that property, and it read it on the
// request that earned the cookie.
//
// solver/profile.js pins TZ for exactly this reason, so reaching here means the
// pin was turned off or did not apply. A note rather than an error: the solve
// may well have worked, and refusing to continue over it would be worse than
// saying what was noticed.
func reportTimezone(tz string) {
	if tz == "" || (tz != "Etc/Unknown" && tz != "UTC") {
		return
	}
	detail := "no timezone at all"
	if tz == "UTC" {
		detail = "UTC, which a server has and a desktop browser rarely does"
	}
	fmt.Fprintf(os.Stderr, "note: the solve reported Intl timezone %q — %s.\n"+
		"  solver/profile.js pins TZ from the language for this reason, so either\n"+
		"  SOLVER_PIN_LOCALE=0 is set or SOLVER_TZ named a zone ICU does not know.\n"+
		"  Set SOLVER_TZ to where your exit actually is.\n", tz, detail)
}

// reportLanguageSplit says so when the browser's Accept-Language header and its
// own navigator.languages name different languages.
//
// This has been wrong in this repo twice, in both directions, and neither time
// did anything notice — which is the whole reason it is checked here rather than
// reasoned about. A page-level shim once asserted ["en-US","en"] on a box whose
// browser was asking for something else; removing the shim then left the browser
// reporting ["en-US"] while its header advertised en-US,en;q=0.9. Both are a
// client that says one thing to the server and another to the script the server
// sent, on the request that earns cf_clearance.
//
// Compared as tag sets in order, quality values dropped, because that is the
// only part the two forms share: "en-US,en;q=0.9" and ["en-US","en"] agree.
//
// A note rather than an error. The solve may well still have worked, and a run
// that refuses to continue over a fingerprint nuance is worse than one that says
// what it noticed.
func reportLanguageSplit(header string, pageLanguages []string) {
	if header == "" || len(pageLanguages) == 0 {
		return
	}
	sent := languageTags(header)
	if slices.Equal(sent, pageLanguages) {
		return
	}
	fmt.Fprintf(os.Stderr, "note: the solve's Accept-Language and navigator.languages disagree —\n"+
		"  header %q -> %v\n  navigator.languages %v\n"+
		"  A real Chrome reports the same list in both. Both halves come from one value in\n"+
		"  solver/profile.js (expectedAcceptLanguage): --accept-lang puts it on the wire and\n"+
		"  preparePage's shim puts it on the page. A disagreement means one of the two did not\n"+
		"  apply — most likely the shim, since evaluateOnNewDocument fails silently.\n",
		header, sent, pageLanguages)
}

// languageTags reduces an Accept-Language header to its tags, in order, with
// quality values dropped — the form navigator.languages reports.
func languageTags(header string) []string {
	var out []string
	for _, part := range strings.Split(header, ",") {
		tag := strings.TrimSpace(strings.Split(part, ";")[0])
		if tag != "" {
			out = append(out, tag)
		}
	}
	return out
}

// reportLanguageDrift says so when the browser did not send the language it was
// asked for.
//
// Drift alone is not an error and nothing is broken by it — the sessions replay
// what was actually sent, so the two halves of the handover match either way. It
// is worth a line because the run is then advertising something other than what
// -lang says, and a flag that silently means something else is worse than one
// that does not work.
//
// A malformed header is a different matter, and is checked first. Chrome 151
// answered --accept-lang=en-US,en;q=0.9 with
//
//	en-US,en;q=0.9,en;q=0.9;q=0.8
//
// on the request that earns cf_clearance, because the flag takes a preference
// list and was being handed a finished header. Chromium 141 collapsed the same
// input cleanly, which is exactly why it needs checking rather than reasoning
// about: the transform belongs to the build, and the next one is free to change
// it again.
func reportLanguageDrift(sent, asked string) {
	if sent == "" {
		return
	}
	if bad := malformedLanguage(sent); bad != "" {
		fmt.Fprintf(os.Stderr, "warning: the solve advertised Accept-Language %q, which is malformed "+
			"(%s). No browser emits that, and it was on the request that earned the cookie. "+
			"Please report the Chromium version — solver/profile.js builds this flag from a "+
			"measurement that this build evidently does not share.\n", sent, bad)
		return
	}
	if asked == "" || sent == asked {
		return
	}
	fmt.Fprintf(os.Stderr, "note: -lang asked for %q but the browser sent %q — Chromium builds the "+
		"header from its own preference list. The run replays what was sent, so the cookie still "+
		"matches; pass that form to -lang if you want the flag to read true.\n", asked, sent)
}

// malformedLanguage names what is wrong with an Accept-Language header, or
// returns "" when it is well formed.
//
// Only the two shapes a mis-built --accept-lang produces are looked for, rather
// than a full RFC 9110 §12.5.4 parse: a tag repeated, and a tag carrying more
// than one quality parameter. Both are things a server can trivially notice and
// no browser ever sends.
func malformedLanguage(header string) string {
	seen := map[string]bool{}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Split(part, ";")
		tag := strings.TrimSpace(fields[0])
		if qs := len(fields) - 1; qs > 1 {
			return fmt.Sprintf("%q carries %d quality parameters", part, qs)
		}
		if seen[tag] {
			return fmt.Sprintf("the tag %q appears more than once", tag)
		}
		seen[tag] = true
	}
	return ""
}

// reportChromiumDrift warns when the browser that earned the cookie is not the
// browser version this client claims to be.
//
// The solver has always measured this and printed it as chromium_major, and
// nothing read it. It is the third binding — JA3/JA4 — arriving in the one form
// that can be checked without a capture: Chrome's ClientHello changes between
// majors, so a cookie earned by Chromium 141 and replayed as Chrome 151 is
// presented with a fingerprint it was never issued to. That is the failure the
// README describes as "works once, dies under load", and it was diagnosable only
// by running fpcheck separately and knowing to.
//
// A warning rather than an error: the run may still be worth having (Bot Fight
// Mode alone does not check this hard), and the fix — a Chromium upgrade or a
// re-pin — is not something to discover mid-run.
func reportChromiumDrift(major int) {
	// 0 is "not reported": an older solver, or a cache entry written before this
	// was recorded. Absence of a measurement is not evidence of a match, but it
	// is not evidence of drift either.
	if major == 0 {
		return
	}
	want := chromeMajorFromUA(gofire.Chrome151UserAgent)
	if want == 0 || want == major {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: the solver's Chromium is %d but this client replays as Chrome %d —\n"+
		"  the cookie is bound to the TLS fingerprint that earned it, and the ClientHello moves\n"+
		"  between majors, so it will work once and then stop under load.\n"+
		"  Upgrade the browser in solver/, or run `go run ./cmd/fpcheck -via-chromium -profile chrome`\n"+
		"  to see how far apart they actually are\n", major, want)
}

// chromeMajorFromUA pulls the major out of a Chrome/N.N.N.N token, or 0.
func chromeMajorFromUA(ua string) int {
	_, rest, ok := strings.Cut(ua, "Chrome/")
	if !ok {
		return 0
	}
	major, _, _ := strings.Cut(rest, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0
	}
	return n
}

// reportUADrift compares the UA a solve came back with against the one this
// client pins for the platform the solver runs on, and says so rather than
// silently living with the difference.
//
// The comparison is against the pinned UA for that platform, not the profile's
// default: the solver claims the OS it actually has — a Linux VPS stays Linux —
// and Sec-Ch-Ua-Platform follows the UA, so that difference is expected and
// already handled. A difference in the browser identity is not.
func reportUADrift(ua string) {
	if ua == "" {
		return
	}
	platform := gofire.PlatformFromUserAgent(ua)
	switch want, ok := gofire.ChromeUserAgentFor(platform); {
	case !ok:
		fmt.Fprintf(os.Stderr, "warning: the solver runs on %q, which this client has no "+
			"pinned Chrome UA for — replaying its UA verbatim\n", platform)
	case want != ua:
		fmt.Fprintf(os.Stderr, "warning: solver UA and the pinned Chrome UA for %s differ —\n"+
			"  solver %s\n  pinned %s\n"+
			"  run `go run ./cmd/fpcheck -via-chromium -profile chrome` to see what else drifted\n",
			platform, ua, want)
	}
}

// truncate shortens s for an error message.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// reportRejectedClearance says so when a solved cookie was handed back a fresh
// challenge on its first use.
//
// Without this the run prints "403 Forbidden" and five kilobytes of
// interstitial, which reads as the solve having failed — it did not, the
// clearance was earned and then refused. Those are different problems and only
// one of them is this tool's.
//
// The message deliberately does not guess which. Measured on a live zone: a
// clearance that the *browser that earned it* could not reuse from a fresh
// context on the same address, same UA, same TLS. No fingerprint work in this
// client would have changed that, and someone staring at a 403 has no way to
// know it. solver/replay.js is the one-command answer, so it is named here
// rather than described.
func reportRejectedClearance(o *options, target string, status int, header http.Header, body []byte) {
	kind, why := identifyChallenge(status, header, body)
	if kind != challengeCloudflare {
		return
	}
	fmt.Fprintf(os.Stderr, `
the solve earned a cf_clearance and the target challenged it anyway (%s).

That is not a failed solve, and it is usually not a fingerprint problem — a
clearance is refused for reasons one response cannot distinguish:

  - the zone re-scores every request, so no clearance is ever reusable
  - the address is on a range the edge scores badly whatever it presents
  - the clearance is bound to the session that earned it and does not travel

To find out which, ask the browser that earned it:

  node %s %s

That replays the same cookie in a fresh context of the same browser, from this
same address. If it is challenged too, nothing on this side would have helped
and the answer is a different exit — try -proxy or -proxy-file.
`, why, filepath.Join(o.solverDir, "replay.js"), target)
}
