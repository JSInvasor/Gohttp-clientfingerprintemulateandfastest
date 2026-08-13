package ctls

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"time"
)

// The offering half of TLS 1.3 resumption.
//
// ticket.go keeps what the server hands out; this puts it back on the wire. The
// shape is pinned to testdata/resumed-clienthello.txt, captured from Chrome
// against a ticket-issuing server: the resumed ClientHello carries exactly one
// extension more than the fresh one, and pre_shared_key is last — after even
// the trailing GREASE, which is otherwise always final.
//
// The binder is the part with no margin. It is an HMAC over the ClientHello
// truncated immediately before the binders themselves, so the message has to be
// built once with the right-sized placeholder, hashed, and then patched. One
// byte off and the server rejects the handshake outright rather than falling
// back, which is why this is written against the capture and the RFC together
// rather than either alone.

// pskExtensionLen is the byte count pre_shared_key adds to a ClientHello for a
// single identity: identities length (2) + identity length (2) + the ticket +
// obfuscated age (4) + binders length (2) + binder length (1) + the binder.
func pskExtensionLen(identityLen, hashLen int) int {
	return 2 + 2 + identityLen + 4 + 2 + 1 + hashLen
}

// buildPSKExtension renders pre_shared_key with a zero-filled binder.
//
//	struct {
//	    PskIdentity identities<7..2^16-1>;
//	    PskBinderEntry binders<33..2^16-1>;
//	} OfferedPsks;
//
// The binder is left as zeros because it cannot be computed yet: it covers the
// ClientHello this extension is part of. finishBinder fills it in once the
// message exists.
func buildPSKExtension(identity []byte, obfuscatedAge uint32, hashLen int) []byte {
	out := make([]byte, 0, pskExtensionLen(len(identity), hashLen))

	// identities<7..2^16-1>: one PskIdentity.
	identitiesLen := 2 + len(identity) + 4
	out = binary.BigEndian.AppendUint16(out, uint16(identitiesLen))
	out = binary.BigEndian.AppendUint16(out, uint16(len(identity)))
	out = append(out, identity...)
	out = binary.BigEndian.AppendUint32(out, obfuscatedAge)

	// binders<33..2^16-1>: one entry, length-prefixed by a single byte.
	out = binary.BigEndian.AppendUint16(out, uint16(1+hashLen))
	out = append(out, byte(hashLen))
	out = append(out, make([]byte, hashLen)...)

	return out
}

// binderKey derives the key the PskBinderEntry is HMAC'd with.
//
//	early_secret = HKDF-Extract(0, PSK)
//	binder_key   = Derive-Secret(early_secret, "res binder", "")
//	finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
//
// RFC 8446 §4.2.11.2 and §7.1. The context for "res binder" is the hash of the
// empty string, not of the transcript — the transcript only enters through the
// message the HMAC covers.
func binderFinishedKey(h func() hash.Hash, psk []byte) []byte {
	hl := h().Size()
	earlySecret := hkdfExtract(h, make([]byte, hl), psk)
	emptyHash := h().Sum(nil)
	bk := deriveSecret(h, earlySecret, "res binder", emptyHash)
	return hkdfExpandLabel(h, bk, "finished", nil, hl)
}

// finishBinder patches the binder into a ClientHello whose pre_shared_key
// extension ends the message.
//
// The MAC covers the message truncated to just before the binders list — that
// is, through the identities and no further. Everything after that point is
// (binders length, binder length, binder), so the truncation point is a fixed
// distance back from the end and the binder starts three bytes past it.
//
// msg is the full handshake message, header included, because that is what the
// transcript hashes.
func finishBinder(msg []byte, h func() hash.Hash, psk []byte) {
	hl := h().Size()
	tail := 2 + 1 + hl // binders length, binder length, binder
	if len(msg) < tail {
		return
	}
	truncated := msg[:len(msg)-tail]

	th := h()
	th.Write(truncated)

	mac := hmac.New(h, binderFinishedKey(h, psk))
	mac.Write(th.Sum(nil))
	copy(msg[len(msg)-hl:], mac.Sum(nil))
}

// pskOffer is what a handshake carries when it is trying to resume.
type pskOffer struct {
	ticket *sessionTicket
	age    uint32
}

// newPSKOffer takes a ticket for serverName out of the cache, if one is usable.
//
// The suite is the ticket's own, not one the handshake negotiated: a PSK is
// derived under a specific hash, and the binder has to be computed with it
// before the server has said anything. A server that then picks a different
// suite must reject the PSK, which is exactly what it does.
func newPSKOffer(cache *SessionCache, serverName string, suites []uint16, now time.Time) *pskOffer {
	if cache == nil {
		return nil
	}
	for _, suite := range suites {
		if t := cache.take(serverName, suite, now); t != nil {
			return &pskOffer{ticket: t, age: t.obfuscatedAge(now)}
		}
	}
	return nil
}

// parseSelectedIdentity reads the server's pre_shared_key extension out of a
// ServerHello's extension block and reports whether the offer was accepted.
//
// Absence is not an error: a server that declines simply omits the extension
// and the handshake proceeds as a full one. Only a selected_identity naming an
// offer that was never made is a protocol violation, and since exactly one is
// offered here, anything but zero is that.
func parseSelectedIdentity(exts []byte) (accepted bool, err error) {
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts)
		l := int(binary.BigEndian.Uint16(exts[2:]))
		if len(exts) < 4+l {
			return false, alertErrf(alertDecodeError, "truncated server hello extension")
		}
		if typ == extPreSharedKey {
			if l != 2 {
				return false, alertErrf(alertIllegalParameter,
					"pre_shared_key in server hello has %d-byte body, want 2", l)
			}
			if idx := binary.BigEndian.Uint16(exts[4:]); idx != 0 {
				return false, alertErrf(alertIllegalParameter,
					"server selected psk identity %d, but only one was offered", idx)
			}
			return true, nil
		}
		exts = exts[4+l:]
	}
	return false, nil
}
