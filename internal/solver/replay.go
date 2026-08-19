package solver

import (
	"context"
	"net/url"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/cdp"
)

// Does the cookie work in the browser that earned it?
//
// This exists to answer one question, and it is the question that decides where
// to look when a solve succeeds and the run that follows it gets 403.
//
// Two very different things produce that symptom:
//
//  1. the client replaying the cookie does not look enough like the browser that
//     earned it, so the edge rejects a cookie that is otherwise fine; or
//  2. the clearance is not replayable at all — the zone re-scores every request,
//     the address is on a datacenter range, or the challenge bound the cookie to
//     the session that solved it.
//
// From outside they are identical: a fresh interstitial either way. And they have
// opposite answers — the first is fingerprint work in this repo, the second is
// not work at all, it is a proxy.
//
// So: take the cookies a solve already earned, put them in a *fresh* context, and
// navigate. Same browser, same address, same everything the solve had — except
// that the challenge is not being solved again, only its cookie presented. If
// that comes back uncontested, the cookie is replayable and the gap is in
// whatever else is replaying it. If it is challenged, no amount of fingerprint
// work in the Go client would have helped, because the browser itself could not
// do it.

// ReplayReport is the whole measurement.
type ReplayReport struct {
	Carried *ReplayAttempt `json:"carried"`
	// SameSessionAfterSolving is nil when the carried cookie already passed, so
	// there was nothing to distinguish.
	SameSessionAfterSolving *InSessionAttempt `json:"same_session_after_solving"`
	// WithoutChallengeState is nil when nothing was dropped, or when the carried
	// attempt passed.
	WithoutChallengeState *ReplayAttempt `json:"without_challenge_state"`
	ChromiumVersion       string         `json:"chromium_version"`
	Verdict               string         `json:"verdict"`
}

// challengedInPage is the narrowest probe there is: the object the challenge
// bootstrap defines before it builds anything. A replay only needs to know
// whether it landed on a challenge, not which kind.
const challengedInPage = `(typeof window._cf_chl_opt === "object" && window._cf_chl_opt !== null)`

// Replay measures whether cookies earned earlier still work.
func Replay(ctx context.Context, o Options, proxy string, cookies []Cookie) (*ReplayReport, error) {
	parsed, err := ParseProxy(proxy)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(o.Target)
	if err != nil {
		return nil, err
	}
	l := o.launcher()

	b, err := l.launch(ctx, parsed)
	if err != nil {
		return nil, err
	}
	defer b.Close()

	report := &ReplayReport{ChromiumVersion: b.Version.Product}

	// The carried-in cookie, in a context of its own.
	report.Carried, err = replayAttempt(ctx, l, b, parsed, o.Target, target.Hostname(), cookies, "carried in")
	if err != nil {
		return nil, err
	}

	if report.Carried.Challenged {
		// Only worth asking once that has answered no: is the clearance
		// unusable, or is the zone challenging everything?
		report.SameSessionAfterSolving, err = solveThenContinue(ctx, l, b, parsed, o.Target)
		if err != nil {
			return nil, err
		}

		// The solver captures every cookie the origin set, challenge bookkeeping
		// included. If presenting that bookkeeping is what breaks the replay,
		// the same cookies without it will pass — and the fix is in this repo.
		kept := make([]Cookie, 0, len(cookies))
		for _, c := range cookies {
			if !IsChallengeState(c.Name) {
				kept = append(kept, c)
			}
		}
		if len(kept) != len(cookies) {
			report.WithoutChallengeState, err = replayAttempt(
				ctx, l, b, parsed, o.Target, target.Hostname(), kept, "clearance only")
			if err != nil {
				return nil, err
			}
		}
	}

	report.Verdict = Verdict(report.Carried, report.SameSessionAfterSolving, report.WithoutChallengeState)
	return report, nil
}

// replayAttempt presents one set of cookies in a fresh context and reports both
// what went out and what came back.
func replayAttempt(ctx context.Context, l Launcher, b *cdp.Browser, proxy *Proxy,
	target, host string, cookies []Cookie, label string) (*ReplayAttempt, error) {

	// A context of its own, so the only thing this session has is the cookies
	// being tested. Reusing one would carry whatever the last attempt left.
	server := ""
	if proxy != nil {
		server = proxy.Server
	}
	bctx, err := b.NewContext(ctx, server)
	if err != nil {
		return nil, err
	}
	// The tab is closed before the context for the reason session.go documents:
	// disposing the context ends the page in the browser but leaves this side's
	// pump goroutine parked forever. Declared ahead of the defer so one teardown
	// covers both, whichever way this function leaves.
	var tab *cdp.Tab
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if tab != nil {
			_ = tab.Close(cctx)
		}
		_ = bctx.Close(cctx)
	}()

	tab, err = bctx.NewTab(ctx)
	if err != nil {
		return nil, err
	}
	if proxy != nil && (proxy.Username != "" || proxy.Password != "") {
		if err := tab.AuthenticateProxy(ctx, proxy.Username, proxy.Password); err != nil {
			return nil, err
		}
	}
	// The identity the cookie was issued to, before anything navigates.
	//
	// Without this the whole measurement is worthless. cf_clearance is bound to
	// the User-Agent, the solve pins Chrome's frozen build — "Chrome/151.0.0.0"
	// — and an unpinned page reports the browser's real one,
	// "Chrome/151.0.7922.108". Same browser, different string, and the edge
	// refuses the cookie on that alone. Every "the clearance was challenged" the
	// Node version of this tool ever printed was guaranteed by its own method
	// rather than measured.
	if err := l.prepare(ctx, tab, b.Version.Product); err != nil {
		return nil, err
	}

	sent, err := tab.WatchSentCookies(ctx)
	if err != nil {
		return nil, err
	}

	presented := make([]string, 0, len(cookies))
	jar := make([]cdp.Cookie, 0, len(cookies))
	for _, c := range cookies {
		presented = append(presented, c.Name)
		domain := c.Domain
		if domain == "" {
			domain = host
		}
		jar = append(jar, cdp.Cookie{
			Name: c.Name, Value: c.Value, Domain: domain, Path: "/", Secure: true,
		})
	}
	if err := bctx.SetCookies(ctx, jar); err != nil {
		return nil, err
	}

	navCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	resp, navErr := tab.NavigateCapturing(navCtx, target)
	cancel()

	// A few seconds for the interstitial to declare itself: a challenge that is
	// going to appear does so after the document is ready, not with it.
	nap(ctx, 3000, 3000)

	attempt := &ReplayAttempt{Label: label, Presented: presented, Challenged: true}
	if resp != nil {
		attempt.HTTPStatus = resp.Status
	} else if navErr != nil {
		attempt.HTTPStatus = 0
	}
	// A probe that cannot run leaves this challenged, which is the conservative
	// answer: an unreadable page is not evidence the cookie was accepted.
	_ = tab.Evaluate(ctx, challengedInPage, &attempt.Challenged)
	attempt.Title, _ = tab.Title(ctx)
	attempt.URL, _ = tab.URL(ctx)

	if names, observed := sent.Names(); observed {
		attempt.Observed = true
		attempt.Sent = names
		inWire := make(map[string]bool, len(names))
		for _, n := range names {
			inWire[n] = true
		}
		for _, n := range presented {
			if !inWire[n] {
				attempt.NotSent = append(attempt.NotSent, n)
			}
		}
	}
	return attempt, nil
}

// solveThenContinue lets a challenge run to completion in a context of its own —
// a browser solves it and proceeds, which is the whole difference between it and
// a client — then navigates again with whatever that left behind.
//
// If the second navigation passes, a clearance does work here and simply does not
// travel. If it is challenged too, the zone re-challenges every request and there
// is nothing for -solve to earn that would ever be reusable.
func solveThenContinue(ctx context.Context, l Launcher, b *cdp.Browser, proxy *Proxy,
	target string) (*InSessionAttempt, error) {

	server := ""
	if proxy != nil {
		server = proxy.Server
	}
	bctx, err := b.NewContext(ctx, server)
	if err != nil {
		return nil, err
	}
	// The tab is closed before the context for the reason session.go documents:
	// disposing the context ends the page in the browser but leaves this side's
	// pump goroutine parked forever. Declared ahead of the defer so one teardown
	// covers both, whichever way this function leaves.
	var tab *cdp.Tab
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if tab != nil {
			_ = tab.Close(cctx)
		}
		_ = bctx.Close(cctx)
	}()

	tab, err = bctx.NewTab(ctx)
	if err != nil {
		return nil, err
	}
	if proxy != nil && (proxy.Username != "" || proxy.Password != "") {
		if err := tab.AuthenticateProxy(ctx, proxy.Username, proxy.Password); err != nil {
			return nil, err
		}
	}
	if err := l.prepare(ctx, tab, b.Version.Product); err != nil {
		return nil, err
	}

	navCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	_ = tab.Navigate(navCtx, target)
	cancel()

	// Wait the challenge out, then click a widget if one is sitting there.
	waitCtx, waitCancel := context.WithTimeout(ctx, 180*time.Second)
	for waitCtx.Err() == nil {
		nap(waitCtx, 2000, 2000)
		stillOn := true
		_ = tab.Evaluate(waitCtx, challengedInPage, &stillOn)
		if !stillOn {
			break
		}
		solveTurnstile(waitCtx, tab)
	}
	waitCancel()

	// Did this context actually earn a clearance, or did the wait simply run
	// out? See InSessionAttempt.SolvedHere for why the two must not be reported
	// as the same thing.
	jar, _ := bctx.Cookies(ctx)
	solvedHere := HasClearance(CookiesForURL(jar, target))

	// The same few seconds the solver spends before it reads a cookie, for the
	// same reason — see behavior.go. Re-navigating the instant the interstitial
	// clears tests a clearance captured cold, which is the one that "dies under
	// load". A zone_challenges verdict taken that way would be measuring this
	// file's impatience.
	if solvedHere {
		simulateHumanBehavior(ctx, tab)
	}

	secondCtx, secondCancel := context.WithTimeout(ctx, 45*time.Second)
	resp, _ := tab.NavigateCapturing(secondCtx, target)
	secondCancel()
	nap(ctx, 2000, 2000)

	out := &InSessionAttempt{SolvedHere: solvedHere, Challenged: true}
	if resp != nil {
		out.HTTPStatus = resp.Status
	}
	_ = tab.Evaluate(ctx, challengedInPage, &out.Challenged)
	out.Title, _ = tab.Title(ctx)
	return out, nil
}
