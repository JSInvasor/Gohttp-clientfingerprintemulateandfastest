package ctls

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Session is a resumable TLS 1.3 session derived from a NewSessionTicket.
//
// Real browsers resume aggressively: a full handshake per connection to a host
// already visited is both slower and a behavioural tell, since no browser
// discards the tickets a server hands it.
type Session struct {
	psk       []byte
	ticket    []byte
	ageAdd    uint32
	lifetime  uint32 // seconds, from the server
	suite     uint16 // the PSK is bound to this suite's hash
	createdAt time.Time
}

// expired reports whether the ticket is past the lifetime the server gave it.
//
// RFC 8446 §4.6.1 caps ticket_lifetime at 7 days and requires clients to stop
// using a ticket after it elapses.
func (s *Session) expired(now time.Time) bool {
	const maxTicketLifetime = 7 * 24 * time.Hour
	life := time.Duration(s.lifetime) * time.Second
	if life <= 0 || life > maxTicketLifetime {
		life = maxTicketLifetime
	}
	return now.Sub(s.createdAt) >= life
}

// obfuscatedAge returns the ticket age the ClientHello advertises: the elapsed
// milliseconds since the ticket was issued, plus the server's random age_add,
// modulo 2^32 (RFC 8446 §4.2.11.1). Servers use it to bound replay windows.
func (s *Session) obfuscatedAge(now time.Time) uint32 {
	ms := now.Sub(s.createdAt).Milliseconds()
	if ms < 0 {
		ms = 0
	}
	return uint32(ms) + s.ageAdd
}

// SessionCache stores resumption tickets, keyed by an opaque scope string.
//
// The scope is the caller's concern, and it matters: presenting the same ticket
// over two different proxies proves to the server that both connections are the
// same client, which defeats the point of rotating them. Transport keys the
// scope by host *and* proxy so tickets never cross that boundary.
//
// A ticket is single-use — RFC 8446 §4.2.11 warns that reusing one across
// connections lets a passive observer correlate them — so Get removes what it
// returns.
type SessionCache struct {
	mu        sync.Mutex
	m         map[string][]*Session
	maxPerKey int
}

// NewSessionCache returns an empty cache holding up to a few tickets per scope,
// matching the handful a server typically issues per connection.
func NewSessionCache() *SessionCache {
	return &SessionCache{m: make(map[string][]*Session), maxPerKey: 4}
}

// Get removes and returns a usable ticket for key, or nil if none is cached.
func (c *SessionCache) Get(key string) *Session {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	sessions := c.m[key]
	for len(sessions) > 0 {
		s := sessions[len(sessions)-1]
		sessions = sessions[:len(sessions)-1]
		if s.expired(now) {
			continue
		}
		if len(sessions) == 0 {
			delete(c.m, key)
		} else {
			c.m[key] = sessions
		}
		return s
	}
	delete(c.m, key)
	return nil
}

// Put stores a ticket for key, dropping the oldest once the per-key cap is hit.
func (c *SessionCache) Put(key string, s *Session) {
	if c == nil || s == nil || len(s.psk) == 0 || len(s.ticket) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.m == nil {
		c.m = make(map[string][]*Session)
	}
	sessions := append(c.m[key], s)
	if len(sessions) > c.maxPerKey {
		sessions = sessions[len(sessions)-c.maxPerKey:]
	}
	c.m[key] = sessions
}

// parseNewSessionTicket decodes a NewSessionTicket body (RFC 8446 §4.6.1):
//
//	uint32 ticket_lifetime, uint32 ticket_age_add,
//	opaque ticket_nonce<0..255>, opaque ticket<1..2^16-1>,
//	Extension extensions<0..2^16-2>
//
// Every length here is server-controlled, so each one is bounds-checked before
// use: this runs on the application-data path of a live connection.
func parseNewSessionTicket(body []byte) (lifetime, ageAdd uint32, nonce, ticket []byte, err error) {
	if len(body) < 9 {
		return 0, 0, nil, nil, fmt.Errorf("new session ticket too short: %d bytes", len(body))
	}
	lifetime = binary.BigEndian.Uint32(body[0:4])
	ageAdd = binary.BigEndian.Uint32(body[4:8])

	p := body[8:]
	nonceLen := int(p[0])
	p = p[1:]
	if nonceLen > len(p) {
		return 0, 0, nil, nil, fmt.Errorf("ticket nonce overruns message")
	}
	nonce = p[:nonceLen]
	p = p[nonceLen:]

	if len(p) < 2 {
		return 0, 0, nil, nil, fmt.Errorf("ticket length field missing")
	}
	ticketLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if ticketLen == 0 || ticketLen > len(p) {
		return 0, 0, nil, nil, fmt.Errorf("ticket overruns message: %d > %d", ticketLen, len(p))
	}
	ticket = p[:ticketLen]

	return lifetime, ageAdd, nonce, ticket, nil
}

// buildPSKExtension builds the pre_shared_key extension body for a single
// offered identity, leaving the binder zeroed for finalizePSKBinder to fill in.
//
// The binder cannot be computed here: it is an HMAC over the ClientHello up to
// the binder itself, so the message has to be fully assembled first.
func buildPSKExtension(sess *Session, now time.Time) []byte {
	hl := hashLen(sess.suite)
	age := sess.obfuscatedAge(now)

	identitiesLen := 2 + len(sess.ticket) + 4
	bindersLen := 1 + hl

	data := make([]byte, 0, 2+identitiesLen+2+bindersLen)
	data = appendUint16(data, uint16(identitiesLen))
	data = appendUint16(data, uint16(len(sess.ticket)))
	data = append(data, sess.ticket...)
	data = append(data, byte(age>>24), byte(age>>16), byte(age>>8), byte(age))
	data = appendUint16(data, uint16(bindersLen))
	data = append(data, byte(hl))
	data = append(data, make([]byte, hl)...) // binder placeholder
	return data
}

// pskBinderTailLen is the number of trailing ClientHello bytes the binder
// covers but is not itself part of the transcript: binders_length(2) +
// binder_length(1) + the binder.
func pskBinderTailLen(suite uint16) int {
	return 3 + hashLen(suite)
}

// finalizePSKBinder computes the PSK binder over the truncated ClientHello and
// writes it into the placeholder buildPSKExtension left at the end of msg.
//
// RFC 8446 §4.2.11.2: the binder is a Finished-style MAC, keyed from the PSK's
// binder_key, over Transcript-Hash(ClientHello without the binders list). A
// wrong value is not a soft failure — the server aborts with decrypt_error.
func finalizePSKBinder(msg []byte, sess *Session) error {
	h := hashForCipher(sess.suite)
	hl := h().Size()
	tail := pskBinderTailLen(sess.suite)
	if len(msg) < tail {
		return fmt.Errorf("client hello too short to carry a psk binder")
	}

	ks := newKeyScheduleWithPSK(sess.suite, sess.psk)
	finishedKey := hkdfExpandLabel(h, ks.binderKey(), "finished", nil, hl)

	th := h()
	th.Write(msg[:len(msg)-tail])
	binder := computeFinishedMAC(h, finishedKey, th.Sum(nil))

	copy(msg[len(msg)-hl:], binder)
	return nil
}
