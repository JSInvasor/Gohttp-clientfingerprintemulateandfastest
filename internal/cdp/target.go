package cdp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Context is one isolated browsing context: its own cookie jar, its own storage,
// and — the part batch mode is built on — its own egress.
//
// Chrome takes a proxy per context through Target.createBrowserContext, not only
// on the command line. That is what lets one browser serve a list of exits: a
// launch costs ~20s on a small VPS and a context costs milliseconds, so a
// hundred exits is one startup instead of half an hour of them.
//
// What a context is not is a new profile. It is Chrome's incognito primitive:
// same process, same BoringSSL, so the JA3/JA4 the cookie is bound to is
// identical to the browser's — which is the property that matters here, since a
// cf_clearance earned in a context is replayed by a client emulating that same
// ClientHello.
type Context struct {
	b  *Browser
	id string // empty means the browser's default context
}

// DefaultContext is the browser's own context, for a solve that does not need
// isolation — one exit, one browser, nothing to keep apart.
func (b *Browser) DefaultContext() *Context {
	return &Context{b: b}
}

// NewContext opens an isolated context, optionally with its own proxy.
//
// proxyServer is Chrome's --proxy-server value, so it carries a scheme for
// anything that is not a plain HTTP proxy: "host:port" is dialled as HTTP, and
// a SOCKS exit given that way is silently dialled as the wrong protocol.
// Credentials do not belong here — Chrome has nowhere to put them — and are
// answered by Tab.AuthenticateProxy instead.
func (b *Browser) NewContext(ctx context.Context, proxyServer string) (*Context, error) {
	params := map[string]any{
		// The context dies with the connection that made it, so a solver that
		// is killed does not leave the browser holding contexts nobody owns.
		"disposeOnDetach": true,
	}
	if proxyServer != "" {
		params["proxyServer"] = proxyServer
	}
	var out struct {
		BrowserContextID string `json:"browserContextId"`
	}
	if err := b.conn.call(ctx, "", "Target.createBrowserContext", params, &out); err != nil {
		return nil, err
	}
	return &Context{b: b, id: out.BrowserContextID}, nil
}

// Close disposes the context and every tab in it. The default context has
// nothing to dispose and closing it is a no-op rather than an error, so callers
// can tear down uniformly.
func (c *Context) Close(ctx context.Context) error {
	if c == nil || c.id == "" {
		return nil
	}
	return c.b.conn.call(ctx, "", "Target.disposeBrowserContext",
		map[string]any{"browserContextId": c.id}, nil)
}

// Cookies returns every cookie this context holds.
//
// Storage.getCookies scoped to the context is the read, not Network.getCookies
// on a tab. In a batch the browser's jar holds every exit's cookies at once, so
// reading at browser scope would hand one exit the cf_clearance another one
// earned — the exact mispairing the Go side spends its effort preventing. It is
// also the read that does not depend on which tab handle happens to be live,
// which is how the previous solver reported an empty cookie list for a session
// that had just been issued a clearance.
func (c *Context) Cookies(ctx context.Context) ([]Cookie, error) {
	params := map[string]any{}
	if c.id != "" {
		params["browserContextId"] = c.id
	}
	var out struct {
		Cookies []Cookie `json:"cookies"`
	}
	if err := c.b.conn.call(ctx, "", "Storage.getCookies", params, &out); err != nil {
		return nil, err
	}
	return out.Cookies, nil
}

// SetCookies puts cookies into this context's jar, for a session that is meant
// to present a credential it did not earn.
//
// Storage.setCookies scoped to the context, for the same reason the read is: in
// a browser serving several contexts, writing at browser scope would put one
// exit's credential where another exit can present it.
func (c *Context) SetCookies(ctx context.Context, cookies []Cookie) error {
	if len(cookies) == 0 {
		return nil
	}
	params := map[string]any{"cookies": cookies}
	if c.id != "" {
		params["browserContextId"] = c.id
	}
	return c.b.conn.call(ctx, "", "Storage.setCookies", params, nil)
}

// Cookie is CDP's Network.Cookie, trimmed to the fields a solve reports.
type Cookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	SameSite string  `json:"sameSite,omitempty"`
}

// NewTab opens a page in this context and attaches to it.
//
// The tab starts at about:blank rather than at the target, because everything
// that pins the identity — the UA override, the Client Hints, the language shim
// — has to be in place before the request that earns the cookie is sent. A tab
// created straight at the target has already made that request.
func (c *Context) NewTab(ctx context.Context) (*Tab, error) {
	params := map[string]any{"url": "about:blank"}
	if c.id != "" {
		params["browserContextId"] = c.id
	}
	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := c.b.conn.call(ctx, "", "Target.createTarget", params, &created); err != nil {
		return nil, err
	}

	// flatten:true is what makes one pipe serve every target: responses and
	// events come back tagged with a sessionId instead of wrapped in
	// Target.receivedMessageFromTarget envelopes that would have to be unpacked
	// by hand.
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	err := c.b.conn.call(ctx, "", "Target.attachToTarget",
		map[string]any{"targetId": created.TargetID, "flatten": true}, &attached)
	if err != nil {
		_ = c.b.conn.call(ctx, "", "Target.closeTarget",
			map[string]any{"targetId": created.TargetID}, nil)
		return nil, err
	}

	t := &Tab{
		b:         c.b,
		ctxID:     c.id,
		targetID:  created.TargetID,
		sessionID: attached.SessionID,
		events:    make(map[string][]tabHandler),
	}
	t.wake = sync.NewCond(&t.mu)
	go t.pump()
	c.b.conn.onEvent(attached.SessionID, t.handleEvent)

	// Page has to be enabled for lifecycle events; that is a domain the page
	// cannot observe, unlike Runtime.enable. See the package comment.
	if err := t.call(ctx, "Page.enable", nil, nil); err != nil {
		_ = t.Close(ctx)
		return nil, err
	}
	return t, nil
}

// Tab is one page, addressed by its CDP session.
type Tab struct {
	b         *Browser
	ctxID     string
	targetID  string
	sessionID string

	mu   sync.Mutex
	wake *sync.Cond
	// events are the per-method handlers, each carrying the id its remover
	// closes over. A slice rather than a map because order of registration is
	// the order they run in, and an id rather than a function pointer because
	// two registrations of the same function are two handlers.
	events      map[string][]tabHandler
	nextHandler int
	// queue holds events the read loop handed over but the pump has not run yet.
	// See handleEvent for why they cannot be run where they arrive.
	queue  []*message
	closed bool
	// Where the pointer was left. Input.dispatchMouseEvent carries an absolute
	// position and no state, so the browser has no notion of "the cursor" —
	// tracking it here is what makes a move a path from somewhere rather than a
	// teleport from the origin every time.
	mouseX, mouseY float64
}

func (t *Tab) call(ctx context.Context, method string, params any, out any) error {
	return t.b.conn.call(ctx, t.sessionID, method, params, out)
}

// handleEvent is called by the connection's read loop. It only queues.
//
// Running handlers here would be a deadlock, not a slow path. A handler that
// issues a CDP command — Fetch.continueWithAuth answering a proxy's 407 is the
// one this driver needs — blocks waiting for a response that only the read loop
// can deliver, and the read loop is the goroutine it is blocking. Every
// authenticated proxy request would stall until its context expired and then
// fail to authenticate.
//
// The queue is a slice rather than a buffered channel because a full channel
// puts the block back where it was. Ordering is kept: one pump per tab, events
// in arrival order, which is what Network.responseReceived-then-loadingFinished
// depends on.
func (t *Tab) handleEvent(msg *message) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.queue = append(t.queue, msg)
	t.mu.Unlock()
	t.wake.Signal()
}

// pump runs this tab's handlers, one event at a time, off the read loop.
func (t *Tab) pump() {
	for {
		t.mu.Lock()
		for len(t.queue) == 0 && !t.closed {
			t.wake.Wait()
		}
		if t.closed && len(t.queue) == 0 {
			t.mu.Unlock()
			return
		}
		msg := t.queue[0]
		t.queue = t.queue[1:]
		hs := append([]tabHandler{}, t.events[msg.Method]...)
		t.mu.Unlock()

		for _, h := range hs {
			h.fn(msg.Params)
		}
	}
}

// tabHandler is one registration: the callback and the id that removes it.
type tabHandler struct {
	id int
	fn func(json.RawMessage)
}

// on registers a handler for one CDP event on this tab and returns the function
// that removes it again.
//
// Handlers run on the tab's pump, so they may issue CDP commands — but they run
// one at a time, so a slow handler delays this tab's later events. Nothing here
// needs one that is slow.
//
// Removal is not decoration. Navigate, NavigateCapturing and WatchSentCookies
// all register per call, and a tab is navigated more than once — replay.go does
// it twice on the same tab. Without a remover those registrations only ever
// accumulate, and the stale ones keep running: an old Navigate's handler is
// still listening for the DOMContentLoaded the next one is waiting on, holding
// its dead channel and closure alive for the life of the tab.
func (t *Tab) on(method string, h func(json.RawMessage)) (remove func()) {
	t.mu.Lock()
	id := t.nextHandler
	t.nextHandler++
	t.events[method] = append(t.events[method], tabHandler{id: id, fn: h})
	t.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			hs := t.events[method]
			for i, e := range hs {
				if e.id != id {
					continue
				}
				// Full slice expression: the copy the pump is holding shares
				// nothing with this one, so a removal cannot rewrite handlers
				// out from under an event that is mid-dispatch.
				t.events[method] = append(hs[:i:i], hs[i+1:]...)
				return
			}
		})
	}
}

// Close detaches from the tab and closes it.
func (t *Tab) Close(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	// Wake the pump so it can see the close and return rather than sitting on
	// the condition for the life of the process.
	t.wake.Broadcast()

	t.b.conn.onEvent(t.sessionID, nil)
	return t.b.conn.call(ctx, "", "Target.closeTarget",
		map[string]any{"targetId": t.targetID}, nil)
}

// Cookies returns the cookies of the context this tab belongs to. It is the
// context read rather than the tab's, for the reason Context.Cookies documents.
func (t *Tab) Cookies(ctx context.Context) ([]Cookie, error) {
	return (&Context{b: t.b, id: t.ctxID}).Cookies(ctx)
}

func (t *Tab) String() string { return fmt.Sprintf("tab(%s)", t.targetID) }
