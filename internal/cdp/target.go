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
		events:    make(map[string][]func(json.RawMessage)),
	}
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

	mu     sync.Mutex
	events map[string][]func(json.RawMessage)
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

func (t *Tab) handleEvent(msg *message) {
	t.mu.Lock()
	hs := append([]func(json.RawMessage){}, t.events[msg.Method]...)
	t.mu.Unlock()
	for _, h := range hs {
		h(msg.Params)
	}
}

// on registers a handler for one CDP event on this tab.
func (t *Tab) on(method string, h func(json.RawMessage)) {
	t.mu.Lock()
	t.events[method] = append(t.events[method], h)
	t.mu.Unlock()
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
