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
	tab     *cdp.Tab
	context *cdp.Context
	// docs is what the edge answered this session's main frame with, which is
	// how waitForPassage recognises a challenge that carries none of
	// Cloudflare's markers. nil when the watcher could not be started, and
	// waitForPassage falls back to the markup alone rather than to nothing.
	docs     *cdp.DocumentStatus
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

// watchDocuments starts the main-frame status watcher for a session, before
// anything navigates.
//
// A failure here is a degradation rather than an error: without it the solve
// still recognises a Cloudflare challenge by its markup, which is every
// challenge the previous version could recognise at all. What it loses is the
// vendor-neutral half — so it is said out loud rather than swallowed, because
// the symptom otherwise is a non-Cloudflare challenge reported as a site that
// never challenged, which is indistinguishable from the bug this replaced.
func (l Launcher) watchDocuments(ctx context.Context, tab *cdp.Tab) *cdp.DocumentStatus {
	docs, err := tab.WatchDocuments(ctx)
	if err != nil {
		if l.Stderr != nil {
			fmt.Fprintf(l.Stderr, "solver: document status unavailable (%v); "+
				"challenge detection falls back to page markup\n", err)
		}
		return nil
	}
	return docs
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

		// Same teardown contract as newContextSession: killing the browser ends
		// the page but leaves this side's pump goroutine parked on its
		// condition forever, so the tab is closed first. One browser per
		// attempt means one leak per attempt, which a retrying solve across a
		// proxy list turns into one per exit.
		var tab *cdp.Tab
		closeSession := func() {
			if tab != nil {
				cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_ = tab.Close(cctx)
				cancel()
			}
			b.Close()
		}

		tab, err = bctx.NewTab(ctx)
		if err != nil {
			closeSession()
			return nil, err
		}
		if proxy != nil && (proxy.Username != "" || proxy.Password != "") {
			if err := tab.AuthenticateProxy(ctx, proxy.Username, proxy.Password); err != nil {
				closeSession()
				return nil, err
			}
		}
		if err := l.prepare(ctx, tab, b.Version.Product); err != nil {
			closeSession()
			return nil, err
		}

		return &session{
			tab:      tab,
			context:  bctx,
			docs:     l.watchDocuments(ctx, tab),
			version:  b.Version.Product,
			major:    ChromiumMajor(b.Version.Product),
			launchMS: time.Since(start).Milliseconds(),
			close:    closeSession,
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
		// Teardown closes the tab before disposing the context, and closing the
		// tab is not redundant. Target.disposeBrowserContext ends the page in
		// the browser, but nothing tells this side: Tab.Close is what stops the
		// tab's pump goroutine and drops its handler from the connection's
		// session map. Without it every solved exit leaked one of each, for the
		// life of the process — and the batch path this function exists for is
		// one browser serving a whole proxy list, so the leak scales with
		// exactly the run it was written for.
		//
		// The tab is captured rather than passed because teardown has to be
		// callable from the failure paths below, which is before there is a tab
		// to pass.
		var tab *cdp.Tab
		closeSession := func() {
			// Teardown gets its own context: the attempt's is usually already
			// expired by the time this runs, and a dispose that inherits an
			// expired deadline never reaches the browser.
			cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if tab != nil {
				_ = tab.Close(cctx)
			}
			_ = bctx.Close(cctx)
		}

		tab, err = bctx.NewTab(ctx)
		if err != nil {
			closeSession()
			return nil, err
		}
		if proxy != nil && (proxy.Username != "" || proxy.Password != "") {
			if err := tab.AuthenticateProxy(ctx, proxy.Username, proxy.Password); err != nil {
				closeSession()
				return nil, err
			}
		}
		if err := l.prepare(ctx, tab, b.Version.Product); err != nil {
			closeSession()
			return nil, err
		}

		return &session{
			tab:      tab,
			context:  bctx,
			docs:     l.watchDocuments(ctx, tab),
			version:  b.Version.Product,
			major:    ChromiumMajor(b.Version.Product),
			launchMS: time.Since(start).Milliseconds(),
			close:    closeSession,
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

// passageOutcome is what waitForPassage concluded.
type passageOutcome struct {
	// cleared says the target is serving us rather than refusing us. It is not
	// "a cf_clearance was issued": that is one way to get here and the only one
	// the previous version could see, which is why every non-Cloudflare edge
	// read as a site that never challenged.
	cleared bool
	// challenged says whether a retry has anything to retry. A site with no
	// challenge at all has already given us everything it is going to, and
	// relaunching the browser for it only costs another cold start.
	challenged bool
}

// waitForPassage polls until the target is serving content, until it is clear
// nothing is in the way, or until the deadline.
//
// Three signals, in the order their answers can be trusted:
//
//  1. The clearance cookie. Definitive where it applies and cheaper than
//     anything else, so it stays the fast path — but only Cloudflare issues one,
//     and treating its absence as "not challenged" is the bug this replaces.
//  2. The status the edge answered the main frame with. This is the vendor-
//     neutral one: an interstitial is a refusal and content is a 200, whoever is
//     serving it, in whatever language, under whatever markup. A challenge that
//     passes replaces its own page, so the passage arrives as a second
//     main-frame response carrying a different status.
//  3. The page's own markup. Cloudflare's markers and wording, unchanged. It is
//     last because it is the one that only recognises one vendor.
//
// The combination matters more than any of them. Status alone is not enough —
// some managed challenges are served with a 200 — and markup alone is what was
// there before. So a refusal keeps the wait alive whatever the markup says, and
// only a served status with nothing interstitial about the page ends it.
func waitForPassage(ctx context.Context, s *session, target string) passageOutcome {
	// Whether anything was ever in the way. It is the difference between "we got
	// through a challenge" and "there was never a challenge", and collapsing the
	// two is not cosmetic: `send` keys on it, and a solve that reports success
	// with an empty jar seeds a run with no cookies that then replays as though
	// it had solved something. A site that simply serves its content has given
	// us nothing to carry, and says so.
	sawChallenge := false

	// A control that is waiting to be pressed waits forever, so the press has to
	// happen inside this loop. It used to live at the call site, guarded by
	// `ctx.Err() == nil` and reached only when the wait returned challenged —
	// and the wait returns challenged only when the context is done, so the
	// guard was false every time it was evaluated. Turnstile checkboxes were
	// never clicked once, by anything, on any run.
	//
	// The first pass is too early: an interstitial fetches its own bootstrap
	// before it builds the control, so there is nothing to find yet. After that
	// it is retried a few times rather than once, because a page that rejects an
	// answer rebuilds its controls and the click has to survive that.
	const (
		firstClickPass = 2
		clickEveryPass = 12
		maxClicks      = 3
	)
	pass, clicks := 0, 0

	for {
		select {
		case <-ctx.Done():
			return passageOutcome{cleared: false, challenged: true}
		default:
		}
		pass++

		if all, err := s.context.Cookies(ctx); err == nil {
			if HasClearance(CookiesForURL(all, target)) {
				// A clearance is only ever issued by something that challenged,
				// so this is passage whether or not a refusal was observed on
				// the way — the first navigation can be answered with the
				// interstitial and the cookie in one round trip.
				return passageOutcome{cleared: true, challenged: true}
			}
		}

		status, _, seen := 0, "", 0
		if s.docs != nil {
			status, _, seen = s.docs.Latest()
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
		interstitial := true
		title, err := s.tab.Title(ctx)
		if err == nil && title != "" && !IsChallengeTitle(title) {
			var marked bool
			// A probe that cannot run — an execution context torn down
			// mid-navigation — leaves the decision to the title, exactly as
			// before.
			if err := s.tab.Evaluate(ctx, DetectChallengeScript, &marked); err != nil || !marked {
				interstitial = false
			}
		}

		refusing := seen > 0 && IsChallengeStatus(status)
		if refusing || interstitial {
			sawChallenge = true

			// Still in the way, so look for something to press. Soft on every
			// failure: most interstitials solve themselves and have no control
			// at all, which is the expected answer rather than a problem.
			due := pass == firstClickPass || (pass > firstClickPass && pass%clickEveryPass == 0)
			if due && clicks < maxClicks {
				clicks++
				clickVerification(ctx, s.tab)
			}
		}

		switch {
		case refusing:
			// The edge is still refusing, so keep waiting whatever the markup
			// says. This is the whole of the generalisation: a challenge with no
			// Cloudflare markers and a title in nobody's regex used to fall
			// straight through the check below and be reported as a site that
			// never challenged.

		case interstitial:
			// The markup still says challenge even though the status does not.
			// Some managed challenges are served with a 200.

		case sawChallenge:
			// Something was in the way and no longer is: the edge is serving and
			// the page is not an interstitial. That is passage, whether or not a
			// cookie named cf_clearance was ever involved.
			return passageOutcome{cleared: true, challenged: true}

		default:
			// Nothing was ever in the way. There is no clearance to earn here
			// and nothing for a retry to retry — this is the answer the site
			// gives, not a failure to get one.
			return passageOutcome{cleared: false, challenged: false}
		}

		select {
		case <-ctx.Done():
			return passageOutcome{cleared: false, challenged: true}
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
func solveTurnstile(ctx context.Context, tab *cdp.Tab) bool {
	box, ok := findTurnstileBox(ctx, tab)
	if !ok {
		return false
	}
	// 15% in from the left edge and centred vertically is where the checkbox
	// sits inside the widget; the rest of the box is its label.
	return tab.MouseClick(ctx, box.x+box.width*0.15, box.y+box.height/2) == nil
}

// clickVerification presses whatever the page is waiting to be pressed.
//
// Turnstile first, because it is precise and because its checkbox carries no
// text for the generic probe to recognise. Then the generic one, for the
// interstitials that gate on an ordinary button — "I am human", "doğrula",
// "continue" — which is a shape Cloudflare does not have a monopoly on and
// which nothing here could press before.
func clickVerification(ctx context.Context, tab *cdp.Tab) bool {
	if solveTurnstile(ctx, tab) {
		return true
	}
	var box *struct {
		X float64 `json:"x"`
		Y float64 `json:"y"`
		W float64 `json:"w"`
		H float64 `json:"h"`
	}
	if err := tab.Evaluate(ctx, findVerifyControlScript, &box); err != nil || box == nil {
		return false
	}
	return tab.MouseClick(ctx, box.X+box.W/2, box.Y+box.H/2) == nil
}

// findVerifyControlScript returns the box of the one control on this page that
// is asking to be clicked, or null.
//
// It is deliberately unwilling. A challenge page is single-purpose, so clicking
// the wrong thing on one is cheap — but this runs on whatever the target served,
// and "press the only button" would eventually press something that submits an
// order. So a candidate has to be a real control, has to be visible, and has to
// say what it is: the text, the aria-label, the id or the class has to read like
// a verification. Anything that only looks like a button is left alone, and a
// widget with no text at all is Turnstile's business rather than this one's.
//
// Open shadow roots are walked because a control inside a web component is still
// an ordinary control. Closed ones are not reachable from here at all, which is
// what findTurnstileBox exists for.
const findVerifyControlScript = `(() => {
  // Both cases spelled out for Turkish: the i/İ pair does not fold under the
  // JS "i" flag, so /insan/i does not match "İnsan".
  const VERIFY = new RegExp(
    "verify|verification|human|not a robot|i'?m not human|continue|proceed|" +
    "doğrula|dogrula|İnsan|insan|robot değilim|devam et|" +
    "ich bin kein roboter|bestätigen|je ne suis pas un robot|vérifier|" +
    "no soy un robot|verificar|sou humano|" +
    "не робот|подтверди|" +
    "我不是机器人|私は人間",
    "i");

  const nodes = [];
  const walk = (root, depth) => {
    if (depth > 4 || nodes.length > 2000) return;
    let found;
    try { found = root.querySelectorAll("*"); } catch { return; }
    for (const el of found) {
      if (nodes.length > 2000) return;
      nodes.push(el);
      if (el.shadowRoot) walk(el.shadowRoot, depth + 1);
    }
  };
  walk(document, 0);

  let best = null;
  for (const el of nodes) {
    const tag = (el.tagName || "").toLowerCase();
    const role = (el.getAttribute("role") || "").toLowerCase();
    const type = (el.getAttribute("type") || "").toLowerCase();

    const isControl = tag === "button"
      || (tag === "input" && (type === "checkbox" || type === "submit" || type === "button"))
      || role === "button" || role === "checkbox";
    if (!isControl || el.disabled) continue;

    let style;
    try { style = getComputedStyle(el); } catch { continue; }
    if (!style || style.visibility === "hidden" || style.display === "none") continue;
    if (Number(style.opacity) < 0.1) continue;

    const r = el.getBoundingClientRect();
    // On screen, and big enough to be a target rather than a tracking pixel.
    if (r.width < 16 || r.height < 16 || r.width > 1600 || r.height > 600) continue;
    if (r.x < 0 || r.y < 0) continue;

    const cls = typeof el.className === "string" ? el.className : "";
    const text = [
      el.innerText || "",
      el.getAttribute("aria-label") || "",
      el.getAttribute("value") || "",
      el.getAttribute("title") || "",
      el.id || "",
      cls,
    ].join(" ").slice(0, 400);
    if (!VERIFY.test(text)) continue;

    // A checkbox that says it is a verification is the strongest shape there
    // is; a button that says so is next.
    const score = (type === "checkbox" || role === "checkbox") ? 2 : 1;
    if (!best || score > best.score) {
      best = {score: score, x: r.x, y: r.y, w: r.width, h: r.height};
    }
  }
  return best ? {x: best.x, y: best.y, w: best.w, h: best.h} : null;
})()`

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
