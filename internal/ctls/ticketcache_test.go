package ctls

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func deadTicket(received time.Time) *sessionTicket {
	return &sessionTicket{
		psk: make([]byte, 32), suite: 0x1301, received: received,
		lifetime: time.Minute, identity: make([]byte, 512),
	}
}

func liveTicket(received time.Time) *sessionTicket {
	t := deadTicket(received)
	t.lifetime = time.Hour
	return t
}

// The per-key limit bounded the tickets under one host; nothing bounded the
// hosts. An entry was only ever reclaimed by a take() on that exact key, so a
// client that visits a host once and never returns left its tickets behind for
// the life of the process — and Len(), which counts live tickets only, reported
// them as gone. That is what made it invisible: a thousand dead hosts measured
// Len() == 0 against a map still holding a thousand entries.
func TestSessionCacheBoundsDeadEntries(t *testing.T) {
	c := NewSessionCache(0)
	past := time.Now().Add(-time.Hour)
	for i := 0; i < 4*maxCachedKeys; i++ {
		c.put(fmt.Sprintf("host%d.example", i), deadTicket(past))
	}

	if c.Len() != 0 {
		t.Errorf("Len() = %d, want 0 — every ticket here is expired", c.Len())
	}
	if n := c.keyCount(); n > maxCachedKeys {
		t.Errorf("%d entries held for 0 live tickets, want at most %d", n, maxCachedKeys)
	}
}

// Live entries are bounded too, or a long-running crawler grows without limit
// whatever the tickets' state.
func TestSessionCacheBoundsLiveEntries(t *testing.T) {
	c := NewSessionCache(0)
	now := time.Now()
	for i := 0; i < 4*maxCachedKeys; i++ {
		c.put(fmt.Sprintf("host%d.example", i), liveTicket(now))
	}
	if n := c.keyCount(); n > maxCachedKeys {
		t.Errorf("%d entries, want at most %d", n, maxCachedKeys)
	}
}

// Eviction takes the dead before the living: a full cache of live tickets that
// then goes quiet must not lose a usable one while dead ones sit beside it.
func TestSessionCacheEvictsDeadBeforeLive(t *testing.T) {
	c := NewSessionCache(0)
	now := time.Now()
	past := now.Add(-time.Hour)

	// Fill to the brim with dead entries, then one live one.
	for i := 0; i < maxCachedKeys-1; i++ {
		c.put(fmt.Sprintf("dead%d.example", i), deadTicket(past))
	}
	c.put("keeper.example", liveTicket(now))

	// One more key forces a reclaim.
	c.put("newcomer.example", liveTicket(now))

	if got := c.take("keeper.example", 0x1301, now); got == nil {
		t.Error("the live ticket was evicted while dead entries were available")
	}
}

// A ticket is single-use, and the expired ones ahead of it in the list go with
// it rather than being walked again on every take.
func TestSessionCacheTakeIsSingleUseAndSelfCleaning(t *testing.T) {
	c := NewSessionCache(0)
	now := time.Now()

	// put prepends, so this leaves the live one behind two expired ones.
	c.put("site.example", liveTicket(now))
	c.put("site.example", deadTicket(now.Add(-time.Hour)))
	c.put("site.example", deadTicket(now.Add(-time.Hour)))

	if got := c.take("site.example", 0x1301, now); got == nil {
		t.Fatal("the live ticket was not returned")
	}
	if got := c.take("site.example", 0x1301, now); got != nil {
		t.Error("the same ticket came back twice — a resumption ticket is single-use")
	}
	if n := c.keyCount(); n != 0 {
		t.Errorf("%d entries left behind after the list was emptied", n)
	}
}

// The cache is reached from every dial on a Client, so it is shared across
// goroutines by construction.
func TestSessionCacheConcurrent(t *testing.T) {
	c := NewSessionCache(0)
	now := time.Now()

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				host := fmt.Sprintf("host%d.example", (w*500+i)%64)
				c.put(host, liveTicket(now))
				c.take(host, 0x1301, now)
				c.Len()
			}
		}(w)
	}
	wg.Wait()
}

// keyCount reports how many entries the map holds, live or not — which is the
// number Len() cannot see and the one that was growing.
func (c *SessionCache) keyCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
