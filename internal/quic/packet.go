package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// Building an Initial packet, which is the inverse of initial.go.
//
// The two halves are deliberately kept apart and then made to meet in the
// tests: a flight built here is decoded by the reader written against Chrome's
// own datagrams, and has to yield the same reference values. That closes a loop
// no amount of reading the RFC does — the decoder was already agreed with by a
// third party (see browserleaksJA4), so anything the builder gets wrong shows
// up as a disagreement rather than as two mistakes cancelling.

// InitialHeaderLen is the header this profile emits: one first byte, four
// version bytes, a length byte and eight bytes of Destination Connection ID, a
// zero Source Connection ID length, a zero token length, and a two-byte length
// varint.
//
// Chrome's captured headers are exactly this, and the two-byte length varint is
// part of it. The value would fit whatever varint it needed, but 1232 requires
// two bytes and a shorter encoding would move every byte after it.
const InitialHeaderLen = 1 + 4 + 1 + 8 + 1 + 1 + 2

// PayloadSizeFor returns how many bytes of frames fit in one Initial datagram
// of the profile's size, given a packet number length.
//
// datagram = header + packet number + payload + 16-byte AEAD tag
func PayloadSizeFor(ref Reference, pnLen int) int {
	return ref.DatagramSize - InitialHeaderLen - pnLen - 16
}

// BuildInitialFlight turns a handshake stream into the datagrams that carry it.
//
// The Destination Connection ID is generated here and returned, because it is
// both the header field and the input the Initial keys are derived from: a
// caller that made one up separately would produce packets it could not itself
// decrypt.
func BuildInitialFlight(ref Reference, handshake []byte) (datagrams [][]byte, dcid []byte, err error) {
	dcid = make([]byte, ref.DCIDLen)
	if _, err := rand.Read(dcid); err != nil {
		return nil, nil, err
	}

	// One byte of packet number for the first packet, two once the number
	// passes 255 — which is what the captures show, and what any
	// implementation does that encodes the number in as few bytes as the peer
	// can still reconstruct.
	payloads, err := ChaosProtect(handshake, PayloadSizeFor(ref, 1))
	if err != nil {
		return nil, nil, err
	}

	for i, payload := range payloads {
		dg, err := BuildInitial(ref, dcid, uint64(i), payload)
		if err != nil {
			return nil, nil, fmt.Errorf("quic: packet %d: %w", i, err)
		}
		datagrams = append(datagrams, dg)
	}
	return datagrams, dcid, nil
}

// BuildInitial assembles and protects one Initial packet.
//
// payload is the frame bytes, already padded to length by the chaos protector.
// pn is the packet number; this profile encodes it in one byte while it fits,
// which is what makes PayloadSizeFor's answer stable across a short flight.
func BuildInitial(ref Reference, dcid []byte, pn uint64, payload []byte) ([]byte, error) {
	if len(dcid) != ref.DCIDLen {
		return nil, fmt.Errorf("quic: DCID is %d bytes, profile uses %d", len(dcid), ref.DCIDLen)
	}
	pnLen := 1
	if pn > 0xff {
		pnLen = 2
	}
	if want := PayloadSizeFor(ref, pnLen); len(payload) != want {
		return nil, fmt.Errorf("quic: payload is %d bytes, want %d", len(payload), want)
	}

	// The length field covers the packet number and the protected payload,
	// which includes the 16-byte AEAD tag.
	length := uint64(pnLen + len(payload) + 16)

	hdr := make([]byte, 0, InitialHeaderLen+pnLen)
	// Long header, fixed bit set, Initial (type 00), reserved 00, and the
	// packet number length in the low two bits. Header protection will mask
	// the low four of these before the packet leaves.
	hdr = append(hdr, 0xc0|byte(pnLen-1))
	hdr = binary.BigEndian.AppendUint32(hdr, ref.ChosenVersion)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(ref.SCIDLen)) // zero-length Source Connection ID
	hdr = append(hdr, 0)                 // token length: none on a fresh Initial

	// Two bytes, to match the captured header. appendVarint is minimal and
	// gives two for anything above 63, which every real length here is.
	before := len(hdr)
	hdr = appendVarint(hdr, length)
	if len(hdr)-before != 2 {
		return nil, fmt.Errorf("quic: length %d encoded in %d bytes, want 2",
			length, len(hdr)-before)
	}
	if len(hdr) != InitialHeaderLen {
		return nil, fmt.Errorf("quic: header is %d bytes, want %d", len(hdr), InitialHeaderLen)
	}
	pnOff := len(hdr)
	for i := pnLen - 1; i >= 0; i-- {
		hdr = append(hdr, byte(pn>>(8*i)))
	}

	key, iv, hp := initialKeys(dcid)

	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// The whole header, packet number included, is the associated data.
	sealed := aead.Seal(nil, nonce, payload, hdr)

	pkt := make([]byte, 0, len(hdr)+len(sealed))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, sealed...)

	if err := applyHeaderProtection(pkt, pnOff, pnLen, hp); err != nil {
		return nil, err
	}
	if len(pkt) != ref.DatagramSize {
		return nil, fmt.Errorf("quic: datagram is %d bytes, profile sends %d",
			len(pkt), ref.DatagramSize)
	}
	return pkt, nil
}

// applyHeaderProtection masks the first byte's low four bits and the packet
// number, per RFC 9001 section 5.4.
//
// It is its own function because it is an involution: the same mask applied
// again removes the protection, which is what Unprotect does. Writing it twice
// would be two chances to get the sample offset wrong.
func applyHeaderProtection(pkt []byte, pnOff, pnLen int, hp []byte) error {
	sampleOff := pnOff + 4
	if sampleOff+16 > len(pkt) {
		return errors.New("quic: packet too short to sample for header protection")
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return err
	}
	var mask [16]byte
	block.Encrypt(mask[:], pkt[sampleOff:sampleOff+16])

	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return nil
}
