package quic

import (
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo/internal/protocol"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo/internal/wire"

	quicprofile "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quic"
)

// FORK DELTA. Not present upstream.
//
// The shape of the client's first flight.
//
// Everything on the wire before the handshake completes is readable to anyone
// on the path: an Initial packet is protected with keys derived from a salt
// published in RFC 9001, so its frames are as visible as if they were in the
// clear. That makes the arrangement of the first flight a fingerprint in its
// own right, separate from the ClientHello inside it, and the two stacks
// arrange it very differently.
//
// quic-go sends the ClientHello as one CRYPTO frame in a 1280-byte datagram,
// with one run of padding at the end. Chrome sends a 1250-byte datagram
// carrying the hello cut into eight to twenty pieces, shuffled, with PING
// frames and several separate runs of padding scattered between them —
// Google's chaos protector, meant to leave a DPI box with no stable byte
// pattern to match on the one packet it can read.
//
// quic-go v0.59 has its own version of this, and it is not Chrome's: see
// crypto_stream.go, where the hello is cut in at most two places, chosen at the
// SNI and at the ECH extension. That is a smaller and much more regular
// signature than Chrome's, and being the only stack that produces it is worse
// than sending one plain frame. This file replaces it on the client.
//
// The pieces live here rather than in the files they change, so that
// crypto_stream.go and packet_packer.go carry a few lines each and stay easy to
// re-apply after a rebase. The distribution itself is not here either: cutting
// well took four corrections against the captures, so there is one copy of it,
// in internal/quic/chaos.go, and both this and the standalone builder call it.

const (
	// chromeInitialPacketSize is the datagram size Chrome sends Initials at.
	// The RFC requires 1200; quic-go uses 1280; every capture under
	// internal/quic/testdata is 1250 to the byte.
	chromeInitialPacketSize = 1250

	// chromeMaxCryptoFragment bounds a fragment so one always fits, whole, in
	// an empty Initial packet.
	//
	// The margin is generous on purpose. The long header is 18 bytes for this
	// profile but grows with a token — the resumed capture carries 70 bytes of
	// one — and an ACK may precede the fragments. Cutting the cap fine would buy
	// nothing: what matters is that a fragment is never so large that it has to
	// be split at a packet boundary, because a piece that ends exactly where the
	// datagram does is a constant, and constants are what this file removes.
	chromeMaxCryptoFragment = chromeInitialPacketSize - 256
)

// chromeConnectionIDForInitial generates the Destination Connection ID the
// client puts in its first Initial packet.
//
// Upstream draws a length uniformly between 8 and 20 bytes. That is legal — RFC
// 9000 section 7.2 sets a floor of 8 and no ceiling below 20 — and it is also
// something no browser does: Chrome's is 8 bytes in every capture, and so is the
// standalone builder's, which reads the length off the same reference. A
// seventeen-byte one puts nine unexpected bytes in the long header of the one
// packet on the path anyone can read, and moves every field after it.
//
// Only the length is pinned. The value has to stay unpredictable, because it is
// what the Initial keys are derived from: it is the only thing stopping someone
// who saw the first packet from writing a convincing second one.
func chromeConnectionIDForInitial() (protocol.ConnectionID, error) {
	return protocol.GenerateConnectionID(quicprofile.Chrome151QUIC.DCIDLen)
}

// chromeChaos holds the plan for one first flight: the fragments still to send,
// in the order to send them.
//
// It is built once, when the whole ClientHello has been queued, and then handed
// out a piece at a time as the packer asks. Planning up front is what allows the
// pieces to be shuffled — a fragment cannot be sent before the packer knows
// there is a later one to put in front of it.
type chromeChaos struct {
	frags   []quicprofile.Fragment
	planned bool

	// planLen is the length of the message the plan covers, kept so the write
	// buffer can be resliced exactly when the last fragment goes out.
	planLen int

	// done means the flight is out and this stream is a plain one again.
	// Anything written afterwards — a second ClientHello after a
	// HelloRetryRequest — is framed the ordinary way.
	done bool

	// stalls counts consecutive refusals to emit the head fragment because it
	// would not fit. See popCryptoFrame.
	stalls int
}

// write appends to the stream's buffer and plans the flight once the whole
// handshake message is there.
//
// Nothing can be planned from part of a message: the cuts are drawn across the
// finished ClientHello, and a fragment count chosen against half of one would
// be chosen against the wrong length. quic-go's own scrambler waits for the
// same reason, though it waits on finding the SNI rather than on the length.
func (c *chromeChaos) write(s *baseCryptoStream, p []byte) {
	s.writeBuf = append(s.writeBuf, p...)
	if c.done || c.planned {
		return
	}
	n, ok := handshakeMessageLen(s.writeBuf)
	if !ok {
		return
	}
	frags, err := quicprofile.SplitHandshake(n, chromeMaxCryptoFragment)
	if err != nil {
		// Splitting only fails if the randomness source does, which is not a
		// reason to fail a connection. Fall back to sending the message the
		// ordinary way: one plain CRYPTO frame is a worse fingerprint than this,
		// and a handshake that does not happen is worse than either.
		c.done = true
		return
	}
	c.frags = frags
	c.planLen = n
	c.planned = true
}

// hasData reports whether the packer has anything to ask for.
//
// It is false while the ClientHello is still arriving, which is what holds the
// first packet back until there is a plan to send.
func (c *chromeChaos) hasData(s *baseCryptoStream) bool {
	if c.done {
		return len(s.writeBuf) > 0
	}
	if !c.planned {
		return false
	}
	return len(c.frags) > 0
}

// popCryptoFrame returns the next fragment, if it fits in maxLen.
func (c *chromeChaos) popCryptoFrame(s *baseCryptoStream, maxLen protocol.ByteCount) *wire.CryptoFrame {
	if len(c.frags) == 0 {
		return nil
	}
	f := c.frags[0]
	frame := &wire.CryptoFrame{Offset: protocol.ByteCount(f.Offset)}
	room := frame.MaxDataLen(maxLen)
	if room <= 0 {
		return nil
	}

	n := protocol.ByteCount(f.Length)
	if room < n {
		// The fragment does not fit in what is left of this packet. Returning
		// nil closes the packet and the fragment goes whole into the next one,
		// which is what the captures show: no fragment there spans a datagram.
		//
		// Twice in a row means it would not fit in a fresh packet either — a
		// large ACK ahead of it, say — so the second refusal cuts it instead.
		// Without that this would be a livelock: HasData stays true, the packer
		// keeps asking, and nothing ever comes out.
		c.stalls++
		if c.stalls < 2 {
			return nil
		}
		n = room
	}
	c.stalls = 0

	frame.Data = s.writeBuf[f.Offset : f.Offset+uint64(n)]
	if n == protocol.ByteCount(f.Length) {
		c.frags = c.frags[1:]
	} else {
		c.frags[0].Offset += uint64(n)
		c.frags[0].Length -= int(n)
	}

	if len(c.frags) == 0 {
		// The flight is out. Hand the stream back in the state the plain path
		// expects: everything up to planLen sent, the rest still queued.
		s.writeOffset = protocol.ByteCount(c.planLen)
		s.writeBuf = s.writeBuf[c.planLen:]
		c.done = true
	}
	return frame
}

// pings returns how many PING frames to scatter through the packet being built,
// and whether the flight is still being sent at all.
//
// Bounded by room so a PING never displaces handshake data: the flight is what
// the packet is for, and a PING that pushed a fragment into another datagram
// would cost a round trip to look right.
func (c *chromeChaos) pings(room protocol.ByteCount) (int, bool) {
	if c.done || !c.planned {
		return 0, false
	}
	n, err := quicprofile.ChaosPings()
	if err != nil {
		return 0, true
	}
	if protocol.ByteCount(n) > room {
		n = int(room)
	}
	if n < 0 {
		n = 0
	}
	return n, true
}

// handshakeMessageLen returns the total length of the TLS handshake message at
// the front of b, once all of it is there.
//
// A handshake message is a one-byte type, a three-byte length, and the body
// (RFC 8446 section 4). Reading the length is exact where looking for the SNI is
// a guess: it says when the message is complete whatever the message contains,
// including one with no SNI at all.
func handshakeMessageLen(b []byte) (int, bool) {
	if len(b) < 4 {
		return 0, false
	}
	n := 4 + (int(b[1])<<16 | int(b[2])<<8 | int(b[3]))
	if len(b) < n {
		return 0, false
	}
	return n, true
}
