package cdp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
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
	// Registered before the navigate so the event cannot be missed, and dropped
	// on the way out so the next navigation on this tab does not find this one
	// still listening.
	remove := t.on("Page.domContentEventFired", func(json.RawMessage) {
		select {
		case loaded <- struct{}{}:
		default:
		}
	})
	defer remove()

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

// SentCookies records the Cookie header the browser actually put on the wire.
//
// This exists because "the cookie was presented and refused" and "the cookie was
// never sent" look identical from the response, and a cookie that fails to be
// stored quietly produces the second while reading as the first. Any tool that
// concludes something about a clearance from a challenged response is asserting
// the cookie went out, and until this is observed that assertion is unfounded.
//
// It has to come from Network.requestWillBeSentExtraInfo rather than from the
// request event. Chrome's network stack adds Cookie after the interception
// point, so the plain request headers report no Cookie on a request that carries
// one — a false "never sent" on every attempt. Measured against a local server
// that recorded what it received:
//
//	server actually received   "cf_clearance=abc123"
//	requestWillBeSent headers  (absent)
//	extraInfo headers.Cookie   "cf_clearance=abc123"
type SentCookies struct {
	mu       sync.Mutex
	observed bool
	header   string
}

// Header returns the Cookie header that went out and whether the wire could be
// observed at all. Not observed is not the same as nothing having been sent, and
// reporting an empty string for both would turn one into the other.
func (s *SentCookies) Header() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.header, s.observed
}

// Names are the cookie names that went out, in wire order.
func (s *SentCookies) Names() ([]string, bool) {
	header, ok := s.Header()
	if !ok {
		return nil, false
	}
	var names []string
	for _, part := range strings.Split(header, ";") {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if name != "" {
			names = append(names, name)
		}
	}
	return names, true
}

// WatchSentCookies starts recording what the next request carries.
//
// Only the first request is kept: a challenge redirects, and the redirects carry
// whatever the interstitial set rather than what was presented to it.
func (t *Tab) WatchSentCookies(ctx context.Context) (*SentCookies, error) {
	s := &SentCookies{}
	// Deliberately not removed: the caller reads what this records after the
	// navigation it is watching, so the registration has to outlive this call.
	// It is one per tab and it goes when the tab does.
	_ = t.on("Network.requestWillBeSentExtraInfo", func(raw json.RawMessage) {
		var ev struct {
			Headers map[string]string `json:"headers"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.observed {
			return
		}
		s.observed = true
		for name, value := range ev.Headers {
			if strings.EqualFold(name, "cookie") {
				s.header = value
				return
			}
		}
	})
	if err := t.call(ctx, "Network.enable", nil, nil); err != nil {
		return nil, err
	}
	return s, nil
}

// Response is what a captured navigation returned.
type Response struct {
	Status  int
	Body    string
	Headers map[string]string
}

// NavigateCapturing loads url and hands back the raw response body.
//
// The body is read from the network rather than from the rendered document, and
// that is the whole reason this exists: Chrome's JSON viewer wraps a JSON
// response in markup and truncates the visible text on a large one, so scraping
// the DOM measures the viewer instead of the response. A fingerprint endpoint's
// answer has to arrive byte for byte.
//
// It is also a real navigation rather than a fetch(): the header order and the
// Sec-Fetch-* values being measured are the ones a document load produces, which
// is what the Go client's default profile emits.
//
// This enables the Network domain, which the solve path deliberately does not.
// Network.enable is not observable from the page the way Runtime.enable is — it
// delivers events to us and changes nothing the document can read — but it is
// still one more domain than a solve needs, so it lives on this call rather than
// on Tab.
func (t *Tab) NavigateCapturing(ctx context.Context, url string) (*Response, error) {
	if err := t.call(ctx, "Network.enable", nil, nil); err != nil {
		return nil, err
	}
	defer func() {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = t.call(dctx, "Network.disable", nil, nil)
	}()

	type captured struct {
		requestID string
		status    int
		headers   map[string]string
	}
	var (
		mu   sync.Mutex
		doc  *captured
		done = make(chan struct{})
		once sync.Once
	)

	removeResponse := t.on("Network.responseReceived", func(raw json.RawMessage) {
		var ev struct {
			RequestID string `json:"requestId"`
			Type      string `json:"type"`
			Response  struct {
				Status  int               `json:"status"`
				Headers map[string]string `json:"headers"`
			} `json:"response"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			return
		}
		// The document, not its subresources: a page pulls scripts and images
		// and any of them would otherwise be captured as the answer.
		if ev.Type != "Document" {
			return
		}
		mu.Lock()
		doc = &captured{requestID: ev.RequestID, status: ev.Response.Status, headers: ev.Response.Headers}
		mu.Unlock()
	})

	finished := func(raw json.RawMessage) {
		var ev struct {
			RequestID string `json:"requestId"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			return
		}
		mu.Lock()
		match := doc != nil && doc.requestID == ev.RequestID
		mu.Unlock()
		if match {
			once.Do(func() { close(done) })
		}
	}
	removeFinished := t.on("Network.loadingFinished", finished)
	// A failed load still ends the wait; the status captured above is what says
	// what happened, and hanging until the deadline would say nothing at all.
	removeFailed := t.on("Network.loadingFailed", finished)

	// All three go when this call does. A second capture on the same tab —
	// which replay.go makes — would otherwise run this one's handlers alongside
	// its own, writing into a `doc` nobody reads and closing a `done` nobody
	// waits on.
	defer func() {
		removeResponse()
		removeFinished()
		removeFailed()
	}()

	if err := t.Navigate(ctx, url); err != nil {
		return nil, err
	}

	select {
	case <-done:
	case <-ctx.Done():
		return nil, fmt.Errorf("capture %s: %w", url, ctx.Err())
	}

	mu.Lock()
	got := doc
	mu.Unlock()
	if got == nil {
		return nil, fmt.Errorf("no document response from %s", url)
	}

	var body struct {
		Body          string `json:"body"`
		Base64Encoded bool   `json:"base64Encoded"`
	}
	err := t.call(ctx, "Network.getResponseBody",
		map[string]any{"requestId": got.requestID}, &body)
	if err != nil {
		return nil, err
	}
	text := body.Body
	if body.Base64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil, fmt.Errorf("decode %s body: %w", url, err)
		}
		text = string(decoded)
	}
	return &Response{Status: got.status, Body: text, Headers: got.headers}, nil
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
// Both handlers below are deliberately permanent: they answer every request the
// tab makes for as long as it exists, so there is no point at which removing
// them would be right. They go when the tab does.
func (t *Tab) AuthenticateProxy(ctx context.Context, username, password string) error {
	_ = t.on("Fetch.authRequired", func(raw json.RawMessage) {
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

	_ = t.on("Fetch.requestPaused", func(raw json.RawMessage) {
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
