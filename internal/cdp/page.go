package cdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"
)

// Navigate loads url and waits for the document to be ready.
//
// The wait is DOMContentLoaded rather than load: a challenge page never fires
// load — it is a page whose whole purpose is to replace itself — and waiting for
// one is how a solve spends its entire budget on a navigation that already
// finished.
//
// A navigation that is superseded is not an error here. Page.navigate answers
// with an errorText of net::ERR_ABORTED when the frame is navigated out from
// under it, which is exactly what a challenge does when it clears — after the
// cookie has been set. Reporting that as a failure is how a successful solve was
// turned into an aborted run.
func (t *Tab) Navigate(ctx context.Context, url string) error {
	loaded := make(chan struct{}, 1)
	t.on("Page.domContentEventFired", func(json.RawMessage) {
		select {
		case loaded <- struct{}{}:
		default:
		}
	})

	var out struct {
		FrameID   string `json:"frameId"`
		ErrorText string `json:"errorText"`
	}
	if err := t.call(ctx, "Page.navigate", map[string]any{"url": url}, &out); err != nil {
		return err
	}
	if out.ErrorText != "" && out.ErrorText != "net::ERR_ABORTED" {
		return fmt.Errorf("navigate %s: %s", url, out.ErrorText)
	}

	select {
	case <-loaded:
		return nil
	case <-ctx.Done():
		// The document not being ready is not the same as the navigation having
		// failed, and the caller has a jar to read either way: a challenge page
		// sets __cf_bm before it ever finishes rendering. So this reports what
		// happened rather than discarding the session.
		return fmt.Errorf("navigate %s: %w", url, ctx.Err())
	}
}

// URL is where the tab currently is.
func (t *Tab) URL(ctx context.Context) (string, error) {
	var out struct {
		TargetInfo struct {
			URL string `json:"url"`
		} `json:"targetInfo"`
	}
	err := t.b.conn.call(ctx, "", "Target.getTargetInfo",
		map[string]any{"targetId": t.targetID}, &out)
	if err != nil {
		return "", err
	}
	return out.TargetInfo.URL, nil
}

// Title is the document title.
//
// It is one Runtime.evaluate rather than a DOM traversal because the challenge
// poll runs it twice a second for the length of an attempt, and the version of
// this solver that passes a live zone does exactly one title read per pass and
// nothing else.
func (t *Tab) Title(ctx context.Context) (string, error) {
	var title string
	if err := t.Evaluate(ctx, "document.title", &title); err != nil {
		return "", err
	}
	return title, nil
}

// Evaluate runs expr in the page and decodes the result into out.
//
// Runtime.enable is never called, and that is the point of this package. The
// domain works without it — enable exists to deliver executionContextCreated
// events, which nothing here needs — and enabling it is the loudest thing an
// automation can do over CDP: it makes the page observable to itself and opens
// the isolated-world console leak that both rebrowser-patches and nodriver were
// written to close. A solver that pins a UA to look like Chrome and then
// announces itself this way has pinned the wrong thing.
//
// out may be nil for an expression evaluated for its effect.
func (t *Tab) Evaluate(ctx context.Context, expr string, out any) error {
	params := map[string]any{
		"expression":    expr,
		"returnByValue": true,
		"awaitPromise":  true,
		// The page's own world, not an isolated one. An isolated world cannot
		// see the document's globals — _cf_chl_opt is defined by the challenge
		// bootstrap and is one of the markers the probe reads — and creating one
		// is itself a CDP call the page can be made to notice.
		"userGesture": false,
	}
	var res struct {
		Result struct {
			Type  string          `json:"type"`
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception *struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if err := t.call(ctx, "Runtime.evaluate", params, &res); err != nil {
		return err
	}
	if res.ExceptionDetails != nil {
		msg := res.ExceptionDetails.Text
		if res.ExceptionDetails.Exception != nil && res.ExceptionDetails.Exception.Description != "" {
			msg = res.ExceptionDetails.Exception.Description
		}
		return fmt.Errorf("evaluate: %s", msg)
	}
	if out == nil {
		return nil
	}
	if len(res.Result.Value) == 0 {
		return errors.New("evaluate: expression produced no value")
	}
	return json.Unmarshal(res.Result.Value, out)
}

// AddInitScript registers source to run before anything else on every document
// this tab loads, including ones it navigates to later.
//
// "Before anything else" is the whole requirement: a shim applied after the
// document has scripts running is a shim the page has already seen the absence
// of.
func (t *Tab) AddInitScript(ctx context.Context, source string) error {
	return t.call(ctx, "Page.addScriptToEvaluateOnNewDocument",
		map[string]any{"source": source}, nil)
}

// UserAgentMetadata is the Client Hint half of a UA override
// (Emulation.UserAgentMetadata).
//
// It is not optional in practice. Overriding the UA string alone does not leave
// Chromium's native hints in place, it clears them — so the session ends up
// claiming Chrome 151 in User-Agent while sending no sec-ch-ua at all, which is
// a combination no real Chrome emits, on the one request that earns
// cf_clearance.
type UserAgentMetadata struct {
	Brands          []Brand `json:"brands"`
	FullVersionList []Brand `json:"fullVersionList"`
	FullVersion     string  `json:"fullVersion,omitempty"`
	Platform        string  `json:"platform"`
	PlatformVersion string  `json:"platformVersion"`
	Architecture    string  `json:"architecture"`
	Model           string  `json:"model"`
	Mobile          bool    `json:"mobile"`
	Bitness         string  `json:"bitness,omitempty"`
	Wow64           bool    `json:"wow64,omitempty"`
}

// Brand is one entry of sec-ch-ua. Order is preserved everywhere it is built:
// Chrome puts its greased entry first and the ordering is itself observable.
type Brand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

// SetUserAgent pins the identity this tab presents, before it navigates.
//
// acceptLanguage is a language *preference list* — "en-US,en", "tr-TR,tr" — and
// never a finished Accept-Language header. This is the one parameter here that
// is easy to get wrong and silent when you do: the browser derives the header
// from the codes it is given, so a header handed to it has its q-values read as
// part of the codes. Measured against Chromium 141 through this exact call:
//
//	passed "en-US,en"        ->  accept-language: en-US,en;q=0.9        (right)
//	passed "en-US,en;q=0.9"  ->  accept-language: en-US,en;q=0.9;q=0.9  (wrong)
//
// TestAcceptLanguageDerivation carries the full table, including how this
// differs from the --accept-lang command-line flag: the flag collapses to the
// first tag and derives the base language itself, this keeps the whole list.
//
// The list also becomes navigator.languages, which is the reason to prefer this
// over the flag. The header the edge reads and the list the challenge's own
// JavaScript reads are then set together by the browser, so they agree by
// construction and there is no shim on navigator to detect.
func (t *Tab) SetUserAgent(ctx context.Context, ua, acceptLanguage, platform string, meta *UserAgentMetadata) error {
	params := map[string]any{"userAgent": ua}
	if acceptLanguage != "" {
		params["acceptLanguage"] = acceptLanguage
	}
	if platform != "" {
		params["platform"] = platform
	}
	if meta != nil {
		params["userAgentMetadata"] = meta
	}
	return t.call(ctx, "Network.setUserAgentOverride", params, nil)
}

// SetTimezone pins the zone Intl answers from, for this tab.
//
// The process environment reaches ICU for the browser as a whole, which is what
// pins the timezone at launch. This is the per-tab belt to that braces: a batch
// solving a hundred exits through one browser cannot re-launch to change a zone,
// and a container with neither reports "Etc/Unknown" — a value no installed
// browser produces, on a property a managed challenge reads.
func (t *Tab) SetTimezone(ctx context.Context, tz string) error {
	if tz == "" {
		return nil
	}
	return t.call(ctx, "Emulation.setTimezoneOverride",
		map[string]any{"timezoneId": tz}, nil)
}

// AuthenticateProxy answers the proxy's 407 with these credentials.
//
// Chrome has nowhere to put credentials on --proxy-server, so an authenticated
// exit has to be answered through the Fetch domain: enable it with
// handleAuthRequests, and every request that draws a challenge gets these back.
// Nothing else is intercepted — Fetch.requestPaused is continued untouched — so
// the request that earns the cookie is the browser's own bytes.
func (t *Tab) AuthenticateProxy(ctx context.Context, username, password string) error {
	t.on("Fetch.authRequired", func(raw json.RawMessage) {
		var ev struct {
			RequestID     string `json:"requestId"`
			AuthChallenge struct {
				Source string `json:"source"`
			} `json:"authChallenge"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			return
		}
		resp := map[string]any{"response": "ProvideCredentials", "username": username, "password": password}
		if ev.AuthChallenge.Source != "Proxy" {
			// A site's own 401 is not ours to answer, and answering it would
			// hand the proxy's credentials to the target.
			resp = map[string]any{"response": "CancelAuth"}
		}
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = t.call(cctx, "Fetch.continueWithAuth",
			map[string]any{"requestId": ev.RequestID, "authChallengeResponse": resp}, nil)
	})

	t.on("Fetch.requestPaused", func(raw json.RawMessage) {
		var ev struct {
			RequestID string `json:"requestId"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			return
		}
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = t.call(cctx, "Fetch.continueRequest", map[string]any{"requestId": ev.RequestID}, nil)
	})

	// Enabled last: the handlers have to be registered before the first
	// authRequired can arrive, and enabling the domain is what starts them
	// arriving.
	return t.call(ctx, "Fetch.enable", map[string]any{"handleAuthRequests": true}, nil)
}

// MouseMove moves the pointer to (x, y) in steps, the way a hand does.
//
// steps matters: a pointer that teleports produces one mousemove where a real
// one produces a trail, and the trail is what the challenge's behavioural
// scoring samples.
func (t *Tab) MouseMove(ctx context.Context, x, y float64, steps int) error {
	if steps < 1 {
		steps = 1
	}
	fromX, fromY := t.pointer()
	for i := 1; i <= steps; i++ {
		f := float64(i) / float64(steps)
		px := fromX + (x-fromX)*f
		py := fromY + (y-fromY)*f
		err := t.call(ctx, "Input.dispatchMouseEvent", map[string]any{
			"type": "mouseMoved", "x": px, "y": py, "button": "none", "buttons": 0,
		}, nil)
		if err != nil {
			return err
		}
		// Between 8 and 20ms: a move dispatched as fast as the pipe allows
		// arrives as a burst with no timing signature at all.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(8+rand.Intn(12)) * time.Millisecond):
		}
	}
	t.setPointer(x, y)
	return nil
}

// MouseClick presses and releases at (x, y).
func (t *Tab) MouseClick(ctx context.Context, x, y float64) error {
	if err := t.MouseMove(ctx, x, y, 6); err != nil {
		return err
	}
	for _, kind := range []string{"mousePressed", "mouseReleased"} {
		err := t.call(ctx, "Input.dispatchMouseEvent", map[string]any{
			"type": kind, "x": x, "y": y, "button": "left", "buttons": 1, "clickCount": 1,
		}, nil)
		if err != nil {
			return err
		}
		if kind == "mousePressed" {
			// A press and release in the same millisecond is not a click any
			// hand produces.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(40+rand.Intn(80)) * time.Millisecond):
			}
		}
	}
	return nil
}

func (t *Tab) pointer() (float64, float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.mouseX, t.mouseY
}

func (t *Tab) setPointer(x, y float64) {
	t.mu.Lock()
	t.mouseX, t.mouseY = x, y
	t.mu.Unlock()
}
