package ctls

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Session tickets, the half of TLS 1.3 resumption that arrives rather than the
// half that is offered.
//
// A server that supports resumption sends one or more NewSessionTicket messages
// after its Finished. This package used to drop them on the floor, which had a
// cost beyond the missing feature: a client that opens hundreds of connections
// and resumes none of them is a client whose behaviour no browser reproduces.
// Chrome caches tickets and its second connection to a host carries a
// pre_shared_key — measured against a real TLS 1.3 server, its resumed
// ClientHello has one extension more than its first, and that extension is
// always last.
//
// This file receives, derives and stores. Offering the PSK is the other half:
// it changes the ClientHello, so it is pinned against that measurement rather
// than written from the RFC alone.

// maxTicketsPerSession bounds what one connection may deposit. Servers commonly
// send two; a peer that sends thousands would otherwise be handed unbounded
// memory on the client's side of the connection.
const maxTicketsPerSession = 8

// ticketLifetimeCap is the ceiling RFC 8446 §4.6.1 puts on ticket_lifetime, and
// therefore on how long one may be believed. A server claiming longer is
// claiming something the protocol does not allow.
const ticketLifetimeCap = 7 * 24 * time.Hour

// sessionTicket is one usable resumption credential.
type sessionTicket struct {
	// psk is already derived from the ticket nonce, so the resumption master
	// secret does not have to outlive the connection that produced it.
	psk        []byte
	identity   []byte // the opaque ticket, sent back as the PSK identity
	ageAdd     uint32 // added to the real age to obfuscate it on the wire
	received   time.Time
	lifetime   time.Duration
	suite      uint16 // a ticket is only usable with the hash it was derived under
	allowEarly bool   // server advertised early_data; unused until 0-RTT exists
}

// expired reports whether the ticket may still be offered.
func (t *sessionTicket) expired(now time.Time) bool {
	return !now.Before(t.received.Add(t.lifetime))
}

// obfuscatedAge is what goes on the wire beside the identity:
//
//	(milliseconds since receipt + ticket_age_add) mod 2^32
//
// RFC 8446 §4.2.11.1. The server compares it against its own record to reject
// replays, so an age computed from the wrong clock is a ticket that is silently
// refused rather than one that errors.
func (t *sessionTicket) obfuscatedAge(now time.Time) uint32 {
	ms := now.Sub(t.received).Milliseconds()
	if ms < 0 {
		ms = 0
	}
	return uint32(ms) + t.ageAdd
}

// parseNewSessionTicket reads the body of a NewSessionTicket handshake message.
//
//	struct {
//	    uint32 ticket_lifetime;
//	    uint32 ticket_age_add;
//	    opaque ticket_nonce<0..255>;
//	    opaque ticket<1..2^16-1>;
//	    Extension extensions<0..2^16-2>;
//	} NewSessionTicket;
func parseNewSessionTicket(body []byte) (lifetime time.Duration, ageAdd uint32, nonce, ticket []byte, allowEarly bool, err error) {
	fail := func(what string) (time.Duration, uint32, []byte, []byte, bool, error) {
		return 0, 0, nil, nil, false, fmt.Errorf("malformed new_session_ticket: %s", what)
	}
	if len(body) < 8 {
		return fail("truncated header")
	}
	seconds := binary.BigEndian.Uint32(body[0:4])
	ageAdd = binary.BigEndian.Uint32(body[4:8])
	p := body[8:]

	if len(p) < 1 {
		return fail("truncated nonce length")
	}
	nl := int(p[0])
	p = p[1:]
	if len(p) < nl {
		return fail("truncated nonce")
	}
	nonce = append([]byte(nil), p[:nl]...)
	p = p[nl:]

	if len(p) < 2 {
		return fail("truncated ticket length")
	}
	tl := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if tl == 0 {
		return fail("empty ticket")
	}
	if len(p) < tl {
		return fail("truncated ticket")
	}
	ticket = append([]byte(nil), p[:tl]...)
	p = p[tl:]

	if len(p) < 2 {
		return fail("truncated extensions length")
	}
	el := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < el {
		return fail("truncated extensions")
	}
	for ext := p[:el]; len(ext) >= 4; {
		typ := binary.BigEndian.Uint16(ext)
		l := int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+l {
			return fail("truncated extension body")
		}
		if typ == extEarlyData {
			allowEarly = true
		}
		ext = ext[4+l:]
	}

	// §4.6.1: a lifetime over a week is invalid. Capping rather than rejecting
	// keeps a server's over-long ticket usable for as long as it is allowed to
	// be, which is what a browser does with one.
	lifetime = time.Duration(seconds) * time.Second
	if lifetime > ticketLifetimeCap {
		lifetime = ticketLifetimeCap
	}
	return lifetime, ageAdd, nonce, ticket, allowEarly, nil
}

// SessionCache holds tickets between connections. The zero value is not usable;
// call NewSessionCache.
//
// Keying is by server name and cipher suite together: a ticket carries a PSK
// derived under one hash, and offering it to a handshake that negotiates the
// other produces a binder the server cannot verify.
type SessionCache struct {
	mu      sync.Mutex
	entries map[string][]*sessionTicket
	max     int
}

// NewSessionCache returns a cache holding at most maxPerHost tickets per
// (host, suite).
func NewSessionCache(maxPerHost int) *SessionCache {
	if maxPerHost < 1 {
		maxPerHost = maxTicketsPerSession
	}
	return &SessionCache{entries: make(map[string][]*sessionTicket), max: maxPerHost}
}

func cacheKey(serverName string, suite uint16) string {
	return fmt.Sprintf("%s|%04x", serverName, suite)
}

// put stores a ticket, newest first, dropping the oldest past the limit.
func (c *SessionCache) put(serverName string, t *sessionTicket) {
	if c == nil || t == nil || len(t.psk) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	k := cacheKey(serverName, t.suite)
	list := append([]*sessionTicket{t}, c.entries[k]...)
	if len(list) > c.max {
		list = list[:c.max]
	}
	c.entries[k] = list
}

// take returns the newest unexpired ticket and removes it.
//
// Removing is the point: a resumption ticket is single-use. Offering the same
// one twice is a replay, which a server is entitled to refuse — and which looks
// like exactly what it is.
func (c *SessionCache) take(serverName string, suite uint16, now time.Time) *sessionTicket {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	k := cacheKey(serverName, suite)
	list := c.entries[k]
	for i, t := range list {
		if t.expired(now) {
			continue
		}
		c.entries[k] = append(append([]*sessionTicket{}, list[:i]...), list[i+1:]...)
		return t
	}
	// Everything here is expired; drop it rather than walk it again next time.
	delete(c.entries, k)
	return nil
}

// Len reports how many live tickets are held, for tests and diagnostics.
func (c *SessionCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	now := time.Now()
	for _, list := range c.entries {
		for _, t := range list {
			if !t.expired(now) {
				n++
			}
		}
	}
	return n
}
