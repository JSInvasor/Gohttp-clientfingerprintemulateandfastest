// Package quic carries the HTTP/3 side of this client's identity.
//
// For now it is the half that reads rather than the half that writes: enough
// of QUIC to take a captured client Initial datagram apart and recover the
// ClientHello and transport parameters inside it. That is what turns
// reference.go's values into evidence — the same role internal/ctls's
// ClientHello parsing plays for the TCP profiles.
//
// Initial packets are the one part of QUIC that can be read without any key
// material from the capture. Their protection is derived from a salt published
// in RFC 9001 section 5.2 and the Destination Connection ID, which travels in
// the clear header. Anyone on the path can do this; so can a bot-detection
// stack, which is the reason the bytes below are worth pinning at all.
package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Version1 is QUIC v1 (RFC 9000).
const Version1 = 0x00000001

// initialSaltV1 is the QUIC v1 initial salt, RFC 9001 section 5.2.
var initialSaltV1 = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// ---------------------------------------------------------------- key schedule

func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < length; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// expandLabel is HKDF-Expand-Label from RFC 8446 section 7.1. QUIC reuses it
// verbatim with its own labels, which is why the TLS 1.3 key schedule in
// internal/ctls transfers to QUIC unchanged.
func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	return hkdfExpand(secret, info, length)
}

// initialKeys derives the client's Initial key, IV and header-protection key
// from the connection's original Destination Connection ID.
func initialKeys(origDCID []byte) (key, iv, hp []byte) {
	secret := hkdfExtract(initialSaltV1, origDCID)
	client := expandLabel(secret, "client in", 32)
	return expandLabel(client, "quic key", 16),
		expandLabel(client, "quic iv", 12),
		expandLabel(client, "quic hp", 16)
}

// --------------------------------------------------------------------- varint

// ReadVarint reads a QUIC variable-length integer (RFC 9000 section 16) and
// returns its value and the number of bytes it occupied.
//
// The encoding is not required to be minimal, so a value read here must not be
// re-encoded and compared against the original if the goal is byte fidelity.
func ReadVarint(b []byte) (val uint64, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	val = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		val = val<<8 | uint64(b[i])
	}
	return val, n, true
}

// --------------------------------------------------------------------- header

// LongHeader is the clear part of a long-header packet.
type LongHeader struct {
	FirstByte byte
	Version   uint32
	DCID      []byte
	SCID      []byte
	Token     []byte
	Length    uint64 // packet number + protected payload
	HeaderLen int    // bytes before the packet number
}

// PacketType names the long-header packet type for a version. The encoding
// differs between v1 and v2, which is itself worth getting right: a decoder
// that assumes v1 mislabels every v2 packet rather than failing on one.
func (h *LongHeader) PacketType() string {
	t := (h.FirstByte & 0x30) >> 4
	if h.Version == 0x6b3343cf { // QUIC v2, RFC 9369
		return [...]string{"Retry", "Initial", "0-RTT", "Handshake"}[t]
	}
	return [...]string{"Initial", "0-RTT", "Handshake", "Retry"}[t]
}

var errShort = errors.New("quic: packet truncated")

// ParseLongHeader reads the unprotected fields of a long-header packet.
//
// The first byte's low four bits are still header-protected at this point, so
// PacketType is only meaningful after Unprotect has run — except for the two
// high bits, which are never protected.
func ParseLongHeader(b []byte) (*LongHeader, error) {
	if len(b) < 7 {
		return nil, errShort
	}
	if b[0]&0x80 == 0 {
		return nil, errors.New("quic: not a long header")
	}
	h := &LongHeader{FirstByte: b[0], Version: binary.BigEndian.Uint32(b[1:5])}

	off := 5
	read := func(n int) ([]byte, error) {
		if off+n > len(b) {
			return nil, errShort
		}
		v := b[off : off+n]
		off += n
		return v, nil
	}
	l, err := read(1)
	if err != nil {
		return nil, err
	}
	if h.DCID, err = read(int(l[0])); err != nil {
		return nil, err
	}
	if l, err = read(1); err != nil {
		return nil, err
	}
	if h.SCID, err = read(int(l[0])); err != nil {
		return nil, err
	}

	tl, n, ok := ReadVarint(b[off:])
	if !ok {
		return nil, errShort
	}
	off += n
	if h.Token, err = read(int(tl)); err != nil {
		return nil, err
	}

	ln, n, ok := ReadVarint(b[off:])
	if !ok {
		return nil, errShort
	}
	off += n
	h.Length = ln
	h.HeaderLen = off
	return h, nil
}

// Packet is one decrypted Initial packet.
type Packet struct {
	Header    *LongHeader
	PacketNum uint64
	PNLen     int
	Reserved  byte   // must be zero on the wire; non-zero means we misread
	Payload   []byte // decrypted frames
	Trailing  []byte // rest of the datagram: a coalesced packet, if any
}

// Unprotect removes header protection and decrypts an Initial packet.
//
// origDCID is the Destination Connection ID from the connection's *first*
// Initial. Later Initials in the same connection carry the server's chosen
// Connection ID instead, but their keys stay derived from the original — so
// passing a packet's own DCID works for the first packet and silently fails
// the AEAD for the rest.
func Unprotect(datagram []byte, origDCID []byte) (*Packet, error) {
	h, err := ParseLongHeader(datagram)
	if err != nil {
		return nil, err
	}

	pnOff := h.HeaderLen
	// RFC 9001 section 5.4.2: the sample starts four bytes past the packet
	// number field, which is why a packet number can be up to four bytes long
	// and still leave the sample in the payload.
	sampleOff := pnOff + 4
	if sampleOff+16 > len(datagram) {
		return nil, errShort
	}
	key, iv, hp := initialKeys(origDCID)

	blk, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	var mask [16]byte
	blk.Encrypt(mask[:], datagram[sampleOff:sampleOff+16])

	hdr := make([]byte, pnOff+4)
	copy(hdr, datagram[:pnOff+4])
	hdr[0] = datagram[0] ^ (mask[0] & 0x0f)
	pnLen := int(hdr[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] = datagram[pnOff+i] ^ mask[1+i]
	}
	hdr = hdr[:pnOff+pnLen]

	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}

	bodyStart := pnOff + pnLen
	bodyEnd := pnOff + int(h.Length)
	if bodyEnd > len(datagram) || bodyEnd < bodyStart {
		return nil, fmt.Errorf("quic: length %d overruns a %d byte datagram", h.Length, len(datagram))
	}

	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	ab, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(ab)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, datagram[bodyStart:bodyEnd], hdr)
	if err != nil {
		return nil, fmt.Errorf("quic: initial AEAD failed (wrong original DCID?): %w", err)
	}

	h.FirstByte = hdr[0]
	return &Packet{
		Header:    h,
		PacketNum: pn,
		PNLen:     pnLen,
		Reserved:  (hdr[0] >> 2) & 0x03,
		Payload:   pt,
		Trailing:  datagram[bodyEnd:],
	}, nil
}

// --------------------------------------------------------------------- frames

// Frames is what one Initial packet's payload carried.
//
// Chrome does not put its ClientHello in a single CRYPTO frame. Google's QUIC
// stack runs the first flight through a chaos protector: the message is cut
// into randomly sized pieces, those are emitted out of order, and PING and
// PADDING frames are scattered between them — deliberately, so that a DPI box
// has no stable byte pattern to match. The layout of any one datagram is
// therefore random by construction and must not be pinned. What is stable, and
// what this package pins, is the reassembled handshake stream. That the
// fragmentation happens at all is itself part of the profile: a client that
// sends one tidy CRYPTO frame does not look like Chrome.
type Frames struct {
	Types     []string          // in wire order, PADDING runs collapsed
	Crypto    map[uint64][]byte // fragment by stream offset
	Pings     int
	PadRuns   int
	CryptoLen int // total fragment bytes in this packet
}

// ParseFrames walks one decrypted payload.
//
// It understands the frame types an Initial may carry (RFC 9000 section 12.4:
// PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE) and stops at anything else
// rather than guessing at a length it does not know.
func ParseFrames(b []byte) (*Frames, error) {
	f := &Frames{Crypto: map[uint64][]byte{}}
	i := 0
	for i < len(b) {
		t, n, ok := ReadVarint(b[i:])
		if !ok {
			return f, fmt.Errorf("quic: bad frame type at offset %d", i)
		}
		i += n
		switch t {
		case 0x00: // PADDING
			for i < len(b) && b[i] == 0x00 {
				i++
			}
			f.Types = append(f.Types, "PADDING")
			f.PadRuns++
		case 0x01: // PING
			f.Types = append(f.Types, "PING")
			f.Pings++
		case 0x02, 0x03: // ACK
			for k := 0; k < 4; k++ { // largest, delay, range count, first range
				_, n, ok = ReadVarint(b[i:])
				if !ok {
					return f, errors.New("quic: truncated ACK")
				}
				i += n
			}
			if t == 0x03 { // ECN counts
				for k := 0; k < 3; k++ {
					_, n, ok = ReadVarint(b[i:])
					if !ok {
						return f, errors.New("quic: truncated ACK ECN section")
					}
					i += n
				}
			}
			f.Types = append(f.Types, "ACK")
		case 0x06: // CRYPTO
			off, n, ok := ReadVarint(b[i:])
			if !ok {
				return f, errors.New("quic: truncated CRYPTO offset")
			}
			i += n
			ln, n, ok := ReadVarint(b[i:])
			if !ok {
				return f, errors.New("quic: truncated CRYPTO length")
			}
			i += n
			if i+int(ln) > len(b) {
				return f, errors.New("quic: CRYPTO frame overruns payload")
			}
			f.Crypto[off] = append([]byte(nil), b[i:i+int(ln)]...)
			f.CryptoLen += int(ln)
			i += int(ln)
			f.Types = append(f.Types, "CRYPTO")
		case 0x1c, 0x1d: // CONNECTION_CLOSE
			f.Types = append(f.Types, "CONNECTION_CLOSE")
			return f, nil
		default:
			return f, fmt.Errorf("quic: unhandled frame type 0x%x at offset %d", t, i-n)
		}
	}
	return f, nil
}

// Assemble merges CRYPTO fragments — from every packet of one connection —
// into the contiguous handshake stream.
//
// It returns an error naming the first hole rather than a buffer with a gap in
// it, because a ClientHello parsed across a hole fails in ways that look like a
// parser bug rather than a missing packet.
func Assemble(frags map[uint64][]byte) ([]byte, error) {
	var end uint64
	for off, d := range frags {
		if off+uint64(len(d)) > end {
			end = off + uint64(len(d))
		}
	}
	out := make([]byte, end)
	seen := make([]bool, end)
	for off, d := range frags {
		copy(out[off:], d)
		for i := range d {
			seen[off+uint64(i)] = true
		}
	}
	for i, ok := range seen {
		if !ok {
			return nil, fmt.Errorf("quic: handshake stream has a hole at %d of %d bytes "+
				"(a datagram of this connection is missing from the capture)", i, end)
		}
	}
	return out, nil
}
