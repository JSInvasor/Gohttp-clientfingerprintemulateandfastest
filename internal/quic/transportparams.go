package quic

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

// Building the quic_transport_parameters extension the way Chrome builds it.
//
// This is the encoding side of what reference.go pins. Three of its decisions
// are measurements rather than readings of RFC 9000, and each one is a place a
// straightforward implementation would produce something distinguishable:
//
//   - The parameters are shuffled. Chrome emits them in a different order on
//     every connection, so a fixed order is the anomaly. Three captures put the
//     same set in three unrelated orders; see reference.go.
//   - Exactly one reserved parameter rides along, with a random 62-bit id of
//     the form 31*N+27 and a random value of random length.
//   - version_information carries QUIC v1 and one reserved version, and which
//     of the two comes first in the available-versions list also moves.
//
// The encoder writes minimal varints throughout. Non-minimal encodings are
// legal and would still parse, but they would change the extension's length,
// and length is visible without any of it being understood.

// EncodeTransportParams builds the extension body for a profile.
//
// scid is the Source Connection ID this client chose. Chrome uses a
// zero-length one, so initial_source_connection_id goes out present and empty;
// passing a non-empty value is supported because RFC 9000 section 7.3 requires
// the parameter to match the header, and a caller that changed one without the
// other would produce a connection the peer must close.
func EncodeTransportParams(ref Reference, scid []byte) ([]byte, error) {
	if ref.TransportParams == nil {
		return nil, fmt.Errorf("quic: reference has no transport parameters")
	}

	type param struct {
		id  uint64
		val []byte
	}
	out := make([]param, 0, len(ref.TransportParams)+4)

	for id, v := range ref.TransportParams {
		out = append(out, param{id, appendVarint(nil, v)})
	}

	// Present and empty for a zero-length Source Connection ID, which is what
	// the profile uses.
	out = append(out, param{TPInitialSourceConnectionID, append([]byte(nil), scid...)})

	vi, err := encodeVersionInformation(ref.ChosenVersion)
	if err != nil {
		return nil, err
	}
	out = append(out, param{TPVersionInformation, vi})

	if ref.ConnectionOptions != "" {
		out = append(out, param{TPGoogleConnectionOptions, []byte(ref.ConnectionOptions)})
	}

	greaseID, greaseVal, err := greaseTransportParam()
	if err != nil {
		return nil, err
	}
	out = append(out, param{greaseID, greaseVal})

	if err := shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] }); err != nil {
		return nil, err
	}

	var b []byte
	for _, p := range out {
		b = appendVarint(b, p.id)
		b = appendVarint(b, uint64(len(p.val)))
		b = append(b, p.val...)
	}
	return b, nil
}

// encodeVersionInformation builds parameter 0x11 (RFC 9368): the chosen
// version, then the list of versions this client is willing to speak.
//
// The list holds QUIC v1 and one reserved version, and their order is
// randomised — the two captures that carry it disagree about which comes first,
// so pinning either arrangement would produce a client that always looks the
// same where Chrome does not.
func encodeVersionInformation(chosen uint32) ([]byte, error) {
	greased, err := greaseVersion()
	if err != nil {
		return nil, err
	}
	first, err := randBool()
	if err != nil {
		return nil, err
	}

	b := make([]byte, 0, 12)
	b = binary.BigEndian.AppendUint32(b, chosen)
	if first {
		b = binary.BigEndian.AppendUint32(b, greased)
		b = binary.BigEndian.AppendUint32(b, Version1)
	} else {
		b = binary.BigEndian.AppendUint32(b, Version1)
		b = binary.BigEndian.AppendUint32(b, greased)
	}
	return b, nil
}

// greaseVersion returns a reserved QUIC version, which RFC 9368 section 3
// defines as any value matching 0x?a?a?a?a: every second nibble is 'a' and the
// rest are free. The capture carried 0x7a2aea4a, which is one of these.
func greaseVersion() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	var v uint32
	for _, x := range b {
		v = v<<8 | uint32((x&0xf0)|0x0a)
	}
	return v, nil
}

// greaseTransportParam returns a reserved parameter id and a random value.
//
// RFC 9000 section 18.1 reserves ids of the form 31*N+27. The captures show
// values of 12, 14 and 15 bytes, so the length is randomised too rather than
// fixed at whatever one capture happened to hold.
func greaseTransportParam() (uint64, []byte, error) {
	// N has to stay small enough that 31*N+27 fits the 62-bit varint space —
	// the largest legal id is (2^62-1-27)/31 — and large enough that the id
	// needs an eight-byte varint, which is what the captures show. The floor
	// buys the second condition without a rejection loop.
	const (
		maxN   = (1<<62 - 1 - 27) / 31
		floorN = 1 << 35
	)
	n, err := rand.Int(rand.Reader, big.NewInt(maxN-floorN))
	if err != nil {
		return 0, nil, err
	}
	id := (uint64(n.Int64())+floorN)*31 + 27

	ln, err := rand.Int(rand.Reader, big.NewInt(5))
	if err != nil {
		return 0, nil, err
	}
	val := make([]byte, 11+int(ln.Int64()))
	if _, err := rand.Read(val); err != nil {
		return 0, nil, err
	}
	return id, val, nil
}

// appendVarint writes v as a minimal QUIC variable-length integer.
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v <= 1073741823:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// shuffle is Fisher-Yates over crypto/rand.
func shuffle(n int, swap func(i, j int)) error {
	for i := n - 1; i > 0; i-- {
		bn, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		swap(i, int(bn.Int64()))
	}
	return nil
}

func randBool() (bool, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return false, err
	}
	return n.Int64() == 1, nil
}
