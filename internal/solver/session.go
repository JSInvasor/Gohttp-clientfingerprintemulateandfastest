package solver

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/cdp"
)

// A session is one isolated place to solve in: a tab to drive, the context its
// cookies come from, and the teardown that ends it.
//
// There are two ways to get one, and the difference between them is the whole
// point of batch mode:
//
//	newBrowserSession   a fresh Chromium per attempt. On a small VPS that is
//	                    ~20s of every attempt — the honest price of a clean
//	                    profile when there is one exit, and half an hour of pure
//	                    startup when there are a hundred.
//	newContextSession   a fresh context in a browser that is already up. Own
//	                    cookie jar, own storage, and its own proxy: Chrome takes
//	                    one per context, not only on the command line. It costs
//	                    milliseconds.
//
// Both produce the same shape and everything below is written against it, so the
// solving logic cannot drift between the one-exit path and the list.
type session struct {
	tab      *cdp.Tab
	context  *cdp.Context
	version  string
	major    int
	launchMS int64
	close    func()
}

// newSession opens a place to solve, by the deadline it is given.
type newSession func(ctx context.Context) (*session, error)

// Launcher opens browsers. It exists so the batch path can hold one open across
// every exit while the single path opens one per attempt, without either of them
// knowing which it is.
type Launcher struct {
	Profile Profile
	// Headless runs without a display. The default is headful under Xvfb, which
	// is what puppeteer-real-browser did and what this solver was measured
	// passing a live Under Attack zone with.
	Headless bool
	// ExecPath overrides browser discovery.
	ExecPath string
	// Stderr receives the browser's own diagnostics, which are worth seeing when
	// a launch fails. nil discards them.
	Stderr *os.File
}

// launch brings up a browser configured to this profile.
func (l Launcher) launch(ctx context.Context, proxy *Proxy) (*cdp.Browser, error) {
	args := l.Profile.LaunchArgs()
	if proxy != nil {
		// The browser-level proxy, for the single-exit path. A batch gives each
		// context its own instead and leaves this unset.
		args = append(args, "--proxy-server="+proxy.Server)
	}
	return cdp.Launch(ctx, cdp.LaunchConfig{
		ExecPath: l.ExecPath,
		Args:     args,
		Headless: l.Headless,
		Env:      l.Profile.Env(),
		Stderr:   l.Stderr,
	})
}

// prepare puts the gofire-matching identity on a tab before it navigates.
//
// Every tab a solve drives goes through this. One that missed it would carry the
// browser's own identity into the request that earns the cookie, which is the
// mismatch this package exists to prevent — and in batch mode there are as many
// tabs as there are exits.
//
// The metadata is rebuilt here rather than reused from startup so the
// high-entropy hints can carry this browser's real build. Building it once up
// front is still worth it: it fails on a bad pin before a browser is launched,
// which is the expensive way to find out.
func (l Launcher) prepare(ctx context.Context, tab *cdp.Tab, browserVersion string) error {
	meta, err := l.Profile.Metadata(browserVersion)
	if err != nil {
		return err
	}
	// The preference list, never the header: the browser reads a header's
	// q-values as part of the language codes. This one call sets the header the
	// edge reads and the navigator.languages the challenge's own JavaScript
	// reads, so the two agree with nothing shimmed on navigator to detect.
	err = tab.SetUserAgent(ctx,
		l.Profile.UserAgent,
		LanguagePreference(ExpectedAcceptLanguage(l.Profile.Language)),
		l.Profile.Platform,
		meta)
	if err != nil {
		return err
	}
	// The environment pins Intl for the browser; this pins it for the tab, which
	// is what a batch needs since it cannot relaunch to change a zone.
	return tab.SetTimezone(ctx, l.Profile.Timezone)
}

// newBrowserSession is a fresh Chromium per attempt: the single-exit path.
func (l Launcher) newBrowserSession(proxy *Proxy) newSession {
	return func(ctx context.Context) (*session, error) {
		start := time.Now()
		// The launch is charged against the attempt's own deadline. It used to
		// be unbounded, and on a slow box it is the longest step there is: a
		// 90-second budget produced a 111-second run because two launches
		// happened outside it.
		b, err := l.launch(ctx, proxy)
		if err != nil {
			return nil, err
		}

		bctx := b.DefaultContext()
		tab, err := bctx.NewTab(ctx)
		if err != nil {
			b.Close()
			return nil, err
		}
		if proxy != nil && (proxy.Username != "" || proxy.Password != "") {
			if err := tab.AuthenticateProxy(ctx, proxy.Username, proxy.Password); err != nil {
				b.Close()
				return nil, err
			}
		}
		if err := l.prepare(ctx, tab, b.Version.Product); err != nil {
			b.Close()
			return nil, err
		}

		return &session{
			tab:      tab,
			context:  bctx,
			version:  b.Version.Product,
			major:    ChromiumMajor(b.Version.Product),
			launchMS: time.Since(start).Milliseconds(),
			close:    func() { b.Close() },
		}, nil
	}
}

// newContextSession is a fresh context in a browser already up: the batch path.
//
// The context carries the proxy, which is what lets one browser serve a list of
// exits. Credentials are applied per tab rather than at the browser, because in
// a batch each exit brings its own and a browser-level answer would be the wrong
// one for every exit but the first.
func (l Launcher) newContextSession(b *cdp.Browser, proxy *Proxy) newSession {
	return func(ctx context.Context) (*session, error) {
		start := time.Now()
		server := ""
		if proxy != nil {
			server = proxy.Server
		}
		bctx, err := b.NewContext(ctx, server)
		if err != nil {
			return nil, err
		}
		closeContext := func() {
			// Teardown gets its own context: the attempt's is usually already
			// expired by the time this runs, and a dispose that inherits an
			// expired deadline never reaches the browser.
			cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = bctx.Close(cctx)
		}

		tab, err := bctx.NewTab(ctx)
		if err != nil {
			closeContext()
			return nil, err
		}
		if proxy != nil && (proxy.Username != "" || proxy.Password != "") {
			if err := tab.AuthenticateProxy(ctx, proxy.Username, proxy.Password); err != nil {
				closeContext()
				return nil, err
			}
		}
		if err := l.prepare(ctx, tab, b.Version.Product); err != nil {
			closeContext()
			return nil, err
		}

		return &session{
			tab:      tab,
			context:  bctx,
			version:  b.Version.Product,
			major:    ChromiumMajor(b.Version.Product),
			launchMS: time.Since(start).Milliseconds(),
			close:    closeContext,
		}, nil
	}
}

// harvest reads the session's cookies for the target and shapes what the caller
// reports. Status is decided by the cookie that matters; everything else in the
// jar is context.
func (l Launcher) harvest(ctx context.Context, s *session, target string) *Result {
	// Teardown-safe: harvest runs on the unhappy path too, where the attempt's
	// context has usually expired, and a read that inherits it would return
	// nothing precisely when the salvage matters most.
	rctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	all, err := s.context.Cookies(rctx)
	if err != nil {
		all = nil
	}
	scoped := CookiesForURL(all, target)

	res := &Result{
		Status:         StatusNoClearance,
		URL:            target,
		UserAgent:      l.Profile.UserAgent,
		AcceptLanguage: ExpectedAcceptLanguage(l.Profile.Language),
		PageLanguages:  []string{},
		Cookies:        CookieHeader(scoped),
		CookieList:     make([]Cookie, 0, len(scoped)),
		ChromiumVer:    s.version,
		ChromiumMajor:  s.major,
		LaunchMS:       s.launchMS,
	}
	if HasClearance(scoped) {
		res.Status = StatusOK
	}
	for _, c := range scoped {
		res.CookieList = append(res.CookieList, Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Expires: c.Expires,
		})
	}

	// The identity is read back from the page rather than assumed from what was
	// pinned. navigator.languages is the half of the language the wire cannot
	// show, and the timezone is the half no header carries — a run where either
	// contradicts the header is the bug this read exists to make visible.
	var identity struct {
		UserAgent string   `json:"userAgent"`
		Languages []string `json:"languages"`
		Timezone  string   `json:"timezone"`
	}
	if err := s.tab.Evaluate(rctx, IdentityScript, &identity); err == nil {
		if identity.UserAgent != "" {
			res.UserAgent = identity.UserAgent
		}
		if identity.Languages != nil {
			res.PageLanguages = identity.Languages
		}
		res.Timezone = identity.Timezone
	}
	if final, err := s.tab.URL(rctx); err == nil && final != "" {
		res.URL = final
	}
	return res
}

// clearanceOutcome is what waitForClearance concluded.
type clearanceOutcome struct {
	cleared bool
	// challenged says whether a retry has anything to retry. A site with no
	// challenge at all has already given us everything it is going to, and
	// relaunching the browser for it only costs another cold start.
	challenged bool
}

// waitForClearance polls until cf_clearance appears for the target origin, or
// until the page leaves the challenge state, or until the deadline.
func waitForClearance(ctx context.Context, s *session, target string) clearanceOutcome {
	for {
		select {
		case <-ctx.Done():
			return clearanceOutcome{cleared: false, challenged: true}
		default:
		}

		if all, err := s.context.Cookies(ctx); err == nil {
			if HasClearance(CookiesForURL(all, target)) {
				return clearanceOutcome{cleared: true}
			}
		}

		// Wording first, structure only as the tie-breaker — and the order is
		// the point.
		//
		// The structural probe exists because Cloudflare localises the
		// interstitial: a solve routed through a non-English exit sees "Bir
		// dakika…", the title check misses, and the solver concludes it was
		// never challenged and gives up in under a second with two minutes of
		// budget left.
		//
		// What was wrong in the version this replaces was running that probe on
		// every pass — an evaluate into the document, twice a second, for the
		// whole time the challenge is running, where the version that passes a
		// live zone does one title read per pass and nothing else. So the common
		// case here is one title read, and the probe is reached only when the
		// title says the challenge is over: the one moment its answer changes
		// anything, and a moment that happens at most once per attempt.
		title, err := s.tab.Title(ctx)
		if err == nil && title != "" && !IsChallengeTitle(title) {
			var challenged bool
			// A probe that cannot run — an execution context torn down
			// mid-navigation — leaves the decision to the title, exactly as
			// before.
			if err := s.tab.Evaluate(ctx, DetectChallengeScript, &challenged); err != nil || !challenged {
				return clearanceOutcome{cleared: false, challenged: false}
			}
		}

		select {
		case <-ctx.Done():
			return clearanceOutcome{cleared: false, challenged: true}
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// solveTurnstile clicks the Turnstile checkbox if one is on the page.
//
// This is puppeteer-real-browser's `turnstile: true`, which is the one capability
// that library provided that a plain CDP driver does not get for free. A managed
// challenge presents a checkbox inside a cross-origin iframe nested in a closed
// shadow root, and it will sit there until something clicks it.
//
// Every failure here is soft. Most pages have no widget at all — an interstitial
// that solves itself is the common case — so "no checkbox found" is the expected
// answer and not a reason to end an attempt that is otherwise going fine.
func solveTurnstile(ctx context.Context, tab *cdp.Tab) {
	box, ok := findTurnstileBox(ctx, tab)
	if !ok {
		return
	}
	// 15% in from the left edge and centred vertically is where the checkbox
	// sits inside the widget; the rest of the box is its label.
	_ = tab.MouseClick(ctx, box.x+box.width*0.15, box.y+box.height/2)
}

type widgetBox struct {
	x, y, width, height float64
}

// findTurnstileBox locates the challenge widget in page coordinates.
//
// It is read from the page rather than walked over the DOM domain because the
// widget lives behind a closed shadow root, where DOM.getBoxModel cannot reach
// without first resolving nodes the page can be made to notice. The element that
// hosts it is visible to an ordinary querySelector, and its rectangle is what a
// click needs.
func findTurnstileBox(ctx context.Context, tab *cdp.Tab) (widgetBox, bool) {
	var box struct {
		Found  bool    `json:"found"`
		X      float64 `json:"x"`
		Y      float64 `json:"y"`
		Width  float64 `json:"width"`
		Height float64 `json:"height"`
	}
	err := tab.Evaluate(ctx, `(() => {
		const hosts = [
			"#turnstile-wrapper",
			"#challenge-stage",
			'div[id^="cf-chl-widget"]',
			'iframe[src*="challenges.cloudflare.com"]',
		];
		for (const selector of hosts) {
			const el = document.querySelector(selector);
			if (!el) continue;
			const r = el.getBoundingClientRect();
			if (r.width < 20 || r.height < 20) continue;
			return {found: true, x: r.x, y: r.y, width: r.width, height: r.height};
		}
		return {found: false, x: 0, y: 0, width: 0, height: 0};
	})()`, &box)
	if err != nil || !box.Found {
		return widgetBox{}, false
	}
	return widgetBox{x: box.X, y: box.Y, width: box.Width, height: box.Height}, true
}

func describeErr(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprint(err)
}
