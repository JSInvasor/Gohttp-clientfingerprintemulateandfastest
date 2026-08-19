package cdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// call sends one command and waits for its response.
//
// ctx is honoured for the wait, not for the command: CDP has no cancellation,
// so a call whose context expires leaves the browser doing the work. What the
// context buys is that the caller stops waiting — and the pending entry is
// dropped so the eventual response is discarded rather than delivered to
// whoever next takes that id.
func (c *conn) call(ctx context.Context, sessionID, method string, params any, out any) error {
	c.mu.Lock()
	if c.closed {
		err := c.closeErr
		c.mu.Unlock()
		if err == nil {
			err = errors.New("devtools connection closed")
		}
		return err
	}
	c.nextID++
	id := c.nextID
	ch := make(chan *message, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	frame := struct {
		ID        int    `json:"id"`
		Method    string `json:"method"`
		Params    any    `json:"params,omitempty"`
		SessionID string `json:"sessionId,omitempty"`
	}{ID: id, Method: method, Params: params, SessionID: sessionID}

	payload, err := json.Marshal(frame)
	if err != nil {
		c.drop(id)
		return fmt.Errorf("encode %s: %w", method, err)
	}

	// One write per frame, serialised: two goroutines interleaving their bytes
	// on the pipe would produce two unparseable frames rather than two frames.
	c.writeMu.Lock()
	_, err = c.w.Write(append(payload, 0))
	c.writeMu.Unlock()
	if err != nil {
		c.drop(id)
		return fmt.Errorf("write %s: %w", method, err)
	}

	select {
	case <-ctx.Done():
		c.drop(id)
		return fmt.Errorf("%s: %w", method, ctx.Err())
	case msg := <-ch:
		if msg.Error != nil {
			return fmt.Errorf("%s: %w", method, msg.Error)
		}
		if out == nil || len(msg.Result) == 0 {
			return nil
		}
		if err := json.Unmarshal(msg.Result, out); err != nil {
			return fmt.Errorf("decode %s result: %w", method, err)
		}
		return nil
	}
}

func (c *conn) drop(id int) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// close tears the pipe down. It does not fail the pending callers itself:
// closing the read side is what the reader goroutine observes, and fail() there
// is the single place that answers everyone still waiting. Doing it here as well
// would mark the connection closed first, and fail() would then find nothing to
// answer — which is how a teardown mid-solve left its callers blocked until
// their own deadlines.
func (c *conn) close() {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}
	c.w.Close()
	c.r.Close()
}
