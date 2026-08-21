package wire

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo/internal/protocol"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo/quicvarint"
)

// FORK DELTA. Not present upstream.
//
// The client's quic_transport_parameters, encoded the way Chrome encodes them.
//
// This is the second half of a pair, and the halves have to stay together. The
// values themselves are set in connection.go where the client's
// TransportParameters are built, so that what quic-go enforces internally and
// what the peer is told are the same numbers; replacing only the encoding would
// advertise limits this stack does not keep. This file is the encoding.
//
// Four things differ from upstream's Marshal, all of them measured against the
// captures under internal/quic/testdata rather than read off a specification:
//
//   - The parameters are shuffled. Upstream emits them in a fixed order with
//     its greased value always first, which is a constant on the wire. Chrome
//     emits a different order on every connection; three captures produced
//     three unrelated orders. A fixed order is the distinguishable behaviour.
//   - version_information (0x11) is sent, carrying QUIC v1 and one reserved
//     version in an order that also moves. Upstream does not send it at all.
//   - google_connection_options (0x3128) is sent. Its value is per-origin
//     rather than per-client — "ORIG" to the Cloudflare hosts captured and
//     "ORIGECCP" to Google's — so the short form is used, which is what a
//     first connection to an arbitrary host carries.
//   - Four parameters upstream sends are omitted, because Chrome omits them:
//     ack_delay_exponent, max_ack_delay, disable_active_migration and
//     active_connection_id_limit. Their absence is as visible as their presence
//     would be, and each falls back to the default the RFC specifies.
//
// The GREASE parameter stays, but reshaped: upstream draws a one-byte multiplier
// and a length under 16, which yields a short id and often an empty value.
// Chrome's is an eight-byte varint id with eleven to fifteen bytes of value.

// chromeConnectionOptions is the value of google_connection_options on a first
// connection. See internal/quic/reference.go.
var chromeConnectionOptions = []byte("ORIG")

const (
	googleConnectionOptionsParameterID = 0x3128
	versionInformationParameterID      = 0x11
)

// marshalChromeClient encodes the client's parameters as Chrome does.
//
// Everything it emits comes from p, so a caller that changed a limit gets a
// hello that advertises the changed limit. Nothing is hard-coded here except
// the two parameters upstream has no field for.
func (p *TransportParameters) marshalChromeClient() []byte {
	type param struct {
		id  uint64
		val []byte
	}
	varint := func(id uint64, v uint64) param {
		return param{id: id, val: quicvarint.Append(nil, v)}
	}

	out := []param{
		varint(uint64(initialMaxStreamDataBidiLocalParameterID), uint64(p.InitialMaxStreamDataBidiLocal)),
		varint(uint64(initialMaxStreamDataBidiRemoteParameterID), uint64(p.InitialMaxStreamDataBidiRemote)),
		varint(uint64(initialMaxStreamDataUniParameterID), uint64(p.InitialMaxStreamDataUni)),
		varint(uint64(initialMaxDataParameterID), uint64(p.InitialMaxData)),
		varint(uint64(initialMaxStreamsBidiParameterID), uint64(p.MaxBidiStreamNum)),
		varint(uint64(initialMaxStreamsUniParameterID), uint64(p.MaxUniStreamNum)),
		varint(uint64(maxIdleTimeoutParameterID), uint64(p.MaxIdleTimeout/time.Millisecond)),
		varint(uint64(maxUDPPayloadSizeParameterID), uint64(p.MaxUDPPayloadSize)),
		// Present and empty for the zero-length Source Connection ID this
		// profile uses. RFC 9000 section 7.3 requires it to match the header,
		// so it is taken from p rather than assumed empty.
		{id: uint64(initialSourceConnectionIDParameterID), val: p.InitialSourceConnectionID.Bytes()},
		{id: googleConnectionOptionsParameterID, val: chromeConnectionOptions},
		{id: versionInformationParameterID, val: chromeVersionInformation()},
	}
	if p.MaxDatagramFrameSize != protocol.InvalidByteCount {
		out = append(out, varint(uint64(maxDatagramFrameSizeParameterID), uint64(p.MaxDatagramFrameSize)))
	}
	greaseID, greaseVal := chromeGreaseParameter()
	out = append(out, param{id: greaseID, val: greaseVal})

	shuffleParams(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })

	b := make([]byte, 0, 256)
	for _, e := range out {
		b = quicvarint.Append(b, e.id)
		b = quicvarint.Append(b, uint64(len(e.val)))
		b = append(b, e.val...)
	}
	return b
}

// chromeVersionInformation builds parameter 0x11 (RFC 9368): the chosen version,
// then the versions this client will speak.
//
// The list holds QUIC v1 and one reserved version, and which comes first moves
// per connection — the two captures that carry it disagree, so pinning either
// arrangement would make this client the one that always looks the same.
func chromeVersionInformation() []byte {
	greased := greaseVersion()
	b := make([]byte, 0, 12)
	b = appendUint32BE(b, uint32(protocol.Version1))
	if randBit() {
		b = appendUint32BE(b, greased)
		b = appendUint32BE(b, uint32(protocol.Version1))
	} else {
		b = appendUint32BE(b, uint32(protocol.Version1))
		b = appendUint32BE(b, greased)
	}
	return b
}

// greaseVersion returns a reserved QUIC version: 0x?a?a?a?a, every second
// nibble fixed (RFC 9368 section 3). The capture carried 0x7a2aea4a.
func greaseVersion() uint32 {
	var raw [4]byte
	rand.Read(raw[:])
	var v uint32
	for _, x := range raw {
		v = v<<8 | uint32((x&0xf0)|0x0a)
	}
	return v
}

// chromeGreaseParameter returns the reserved parameter Chrome carries: an
// eight-byte varint id of the form 31*N+27, and eleven to fifteen random bytes.
//
// The bound on N keeps 31*N+27 inside the 62-bit varint space; the floor keeps
// the id long enough to need eight bytes, which is what the captures show.
func chromeGreaseParameter() (id uint64, val []byte) {
	const (
		maxN   = (1<<62 - 1 - 27) / 31
		floorN = 1 << 35
	)
	n, err := rand.Int(rand.Reader, big.NewInt(maxN-floorN))
	if err != nil {
		// crypto/rand does not fail in practice, and a transport parameter is
		// not a place to start returning errors upstream never returns. Fall
		// back to a fixed multiplier rather than failing mid-handshake.
		n = big.NewInt(floorN)
	}
	id = (uint64(n.Int64())+floorN)*31 + 27

	ln, err := rand.Int(rand.Reader, big.NewInt(5))
	if err != nil {
		ln = big.NewInt(0)
	}
	val = make([]byte, 11+int(ln.Int64()))
	rand.Read(val)
	return id, val
}

func appendUint32BE(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func randBit() bool {
	var b [1]byte
	rand.Read(b[:])
	return b[0]&1 == 1
}

// shuffleParams is Fisher-Yates over crypto/rand.
func shuffleParams(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		bn, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return
		}
		swap(i, int(bn.Int64()))
	}
}
