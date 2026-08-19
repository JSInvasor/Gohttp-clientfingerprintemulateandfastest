// Package cdp drives a real Chromium over the Chrome DevTools Protocol.
//
// It exists because the solve needs a browser and this repo needs it in Go. The
// solver used to be a Node process built on puppeteer-real-browser, which meant
// `send` — a static Go binary — could not solve anything without a Node install,
// an npm tree and a Chromium that the two agreed about. Everything here replaces
// that with the ~20 CDP methods a challenge solve actually uses.
//
// The design follows zendriver/nodriver rather than puppeteer, on the one point
// where they differ and it matters:
//
//   - No Runtime.enable, ever. Runtime.evaluate works on an attached session
//     without it — enable only exists to receive executionContextCreated events.
//     Enabling it is the single loudest CDP tell there is: it makes the page
//     observable to itself, and the isolated-world console leak it opens is what
//     rebrowser-patches and nodriver were both written to close. We never need
//     the events, so we never take the cost.
//   - No injected stealth JS beyond the one shim identity.go documents. Every
//     Object.defineProperty on a native object leaves an own property and a
//     non-native toString where none belongs.
//
// The transport is a pipe rather than a WebSocket, which is the other deliberate
// difference from both. --remote-debugging-port opens a listener on localhost
// for the life of the browser: anything else on the box can drive the session
// that is earning a cf_clearance, and the port is discovered by parsing it out
// of stderr. --remote-debugging-pipe hands the same protocol over inherited file
// descriptors 3 and 4 — nothing to bind, nothing to discover, nothing else can
// reach it, and no WebSocket implementation to carry.
package cdp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// message is one CDP frame in either direction. Commands carry id+method,
// responses carry id+result or id+error, and events carry method+params with no
// id. SessionID is what makes one pipe serve every target: a command addressed
// to a session is routed to that target, and an event arrives tagged with the
// session it came from.
type message struct {
	ID        int             `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *protocolError  `json:"error,omitempty"`
}

// protocolError is CDP's own error shape. It is kept whole rather than
// flattened to a string because the code distinguishes the cases that are
// ordinary from the ones that are not — see IsDetached.
type protocolError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func (e *protocolError) Error() string {
	if e.Data != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Data)
	}
	return e.Message
}

// IsDetached reports whether err is the protocol saying the target this command
// was addressed to is gone.
//
// This is not an exceptional condition and treating it as one was a bug in the
// version this replaces: a challenge that clears navigates the frame out from
// under whatever was reading it, so the read that raced the navigation fails
// with a detached context *after* the cookie was set. Callers that are polling
// use this to keep waiting instead of reporting a failed solve.
func IsDetached(err error) bool {
	var pe *protocolError
	if !errors.As(err, &pe) {
		return false
	}
	switch pe.Message {
	case "Session with given id not found.",
		"Target closed.",
		"Inspected target navigated or closed",
		"Execution context was destroyed.",
		"Cannot find context with specified id":
		return true
	}
	return false
}

// conn is the multiplexed CDP connection: one pipe pair, every target on it.
//
// Commands are matched to responses by id through pending; events are handed to
// whichever session registered for them. Both maps are behind one mutex because
// the reader goroutine and every caller touch them, and the critical sections
// are a map lookup each.
type conn struct {
	w   io.WriteCloser
	r   io.ReadCloser
	buf *bufio.Reader

	mu       sync.Mutex
	nextID   int
	pending  map[int]chan *message
	handlers map[string]func(*message) // by session id; "" is the browser session
	closed   bool
	closeErr error

	writeMu sync.Mutex
}

func newConn(w io.WriteCloser, r io.ReadCloser) *conn {
	c := &conn{
		w:        w,
		r:        r,
		buf:      bufio.NewReaderSize(r, 64*1024),
		pending:  make(map[int]chan *message),
		handlers: make(map[string]func(*message)),
	}
	go c.read()
	return c
}

// read pumps the pipe until it closes, which is how the browser going away is
// noticed. Every pending caller is failed with the same error rather than left
// blocked — a solve that outlived its browser has to report that, not hang until
// the run's deadline.
func (c *conn) read() {
	for {
		// CDP over a pipe is NUL-delimited JSON, not newline-delimited: a
		// message may legitimately contain a newline inside a string, and
		// scanning lines would split it. NUL cannot appear in JSON at all.
		frame, err := c.buf.ReadBytes(0)
		if len(frame) > 0 {
			if frame[len(frame)-1] == 0 {
				frame = frame[:len(frame)-1]
			}
			if len(frame) > 0 {
				c.dispatch(frame)
			}
		}
		if err != nil {
			c.fail(fmt.Errorf("devtools pipe closed: %w", err))
			return
		}
	}
}

func (c *conn) dispatch(frame []byte) {
	var msg message
	if err := json.Unmarshal(frame, &msg); err != nil {
		return // a frame we cannot parse is not a frame anyone is waiting on
	}

	if msg.ID != 0 {
		c.mu.Lock()
		ch := c.pending[msg.ID]
		delete(c.pending, msg.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- &msg
		}
		return
	}

	c.mu.Lock()
	h := c.handlers[msg.SessionID]
	c.mu.Unlock()
	if h != nil {
		h(&msg)
	}
}

func (c *conn) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.closeErr = err
	pending := c.pending
	c.pending = make(map[int]chan *message)
	c.mu.Unlock()

	for id, ch := range pending {
		ch <- &message{ID: id, Error: &protocolError{Message: err.Error()}}
	}
}

// onEvent registers the handler for one session's events. Passing nil removes
// it, which callers do on teardown so a late event cannot reach a closed tab.
func (c *conn) onEvent(sessionID string, h func(*message)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h == nil {
		delete(c.handlers, sessionID)
		return
	}
	c.handlers[sessionID] = h
}
