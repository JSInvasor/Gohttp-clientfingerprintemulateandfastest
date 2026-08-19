package solver

import (
	"errors"
	"fmt"
)

// The exits a batch solve works through.
//
// In the Node solver this arrived as JSON on stdin, and stdin rather than argv
// or the environment because these carry proxy credentials: /proc/<pid>/cmdline
// is world-readable, so a proxy password in argv is visible to every user on the
// box for as long as the solve runs — and a solve runs for minutes.
//
// In-process there is no second process to hand them to, so the credentials
// never leave this address space at all. That is the one security property this
// port gains for free, and it is why the pipe format is gone rather than ported.

// Exit is one address to solve through.
type Exit struct {
	// ID is what the caller calls this exit. It is echoed back on the result and
	// never used for anything else, so it can be an address, a label or a number.
	ID string
	// Proxy is what the browser dials, and may be empty for a direct solve.
	Proxy string
}

// Batch is a list of exits and how many to work at once.
type Batch struct {
	Exits    []Exit
	Parallel int
}

// NewBatch validates a list of exits, rejecting anything it cannot run rather
// than silently solving a subset.
func NewBatch(exits []Exit, parallel int) (*Batch, error) {
	if len(exits) == 0 {
		return nil, errors.New("batch has no exits")
	}
	out := make([]Exit, 0, len(exits))
	seen := make(map[string]bool, len(exits))
	for i, e := range exits {
		id := e.ID
		if id == "" {
			id = fmt.Sprint(i)
		}
		if seen[id] {
			// The caller keys results by id. Two exits sharing one would make a
			// result ambiguous, and the ambiguity would land on a cookie.
			return nil, fmt.Errorf("duplicate exit id %q", id)
		}
		seen[id] = true

		// Every proxy is parsed before the browser starts, for the same reason
		// the Client Hints are built up front: finding out about a malformed one
		// after a launch is an expensive way to learn it, and in a batch it
		// would strand the exits behind it too.
		if _, err := ParseProxy(e.Proxy); err != nil {
			return nil, fmt.Errorf("exit %s: %w", id, err)
		}
		out = append(out, Exit{ID: id, Proxy: e.Proxy})
	}
	return &Batch{Exits: out, Parallel: clampParallel(parallel, len(out))}, nil
}

// clampParallel bounds the requested concurrency to something runnable.
//
// A batch shares one browser, so this is how many tabs are challenged at once
// rather than how many browsers are up — much cheaper, but not free: each one is
// a live page running Cloudflare's JavaScript.
func clampParallel(requested, exits int) int {
	if requested < 1 {
		return 1
	}
	if requested > exits {
		return exits
	}
	return requested
}
