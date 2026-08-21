package http3

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"slices"
	"sync"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/qpack"
	quicprofile "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quic"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo/quicvarint"
)

// FORK DELTA. Not present upstream.
//
// The HTTP/3 layer of the profile: what goes on the control stream before any
// request, and what order a request's fields go in.
//
// Everything here is measured. internal/quic/http3.go holds the reference —
// the SETTINGS and their order, the reserved entry, the frames that follow
// SETTINGS, and both header orders — taken from a report by a server that told
// Chrome what it had received. This file is the encoder for it, and it is kept
// apart from the files it changes so those carry a few lines each.
//
// Three things upstream does that a browser does not:
//
//   - Its SETTINGS carry a map, and Go map iteration is randomised, so the
//     order of the entries changes per connection. Chrome's does not move.
//   - Its control stream goes quiet after SETTINGS. Chrome sends a reserved
//     frame and then a PRIORITY_UPDATE, which is visible before a single
//     request byte.
//   - Its request headers come out of an http.Header map, which is again
//     randomised. Chrome's order is fixed and is one of the oldest and easiest
//     fingerprints there is.
//
// The QPACK streams are the fourth thing, and they are not in this file because
// they are not a matter of ordering: see conn.go, which opens them, and
// internal/qpack, which is a fork for exactly this reason.

// chromeQPACK are the limits this endpoint's decoder advertises, and they are
// the same numbers internal/quic/http3.go pins in SETTINGS. They are one thing
// stated twice on purpose: the SETTINGS say what this decoder will accept, and
// the decoder has to actually accept it. See internal/qpack/FORK.md.
const (
	chromeQPACKMaxTableCapacity = 65536
	chromeQPACKBlockedStreams   = 100
)

// uniStreamWriter is a unidirectional stream that can be written to before it
// exists.
//
// QPACK's two streams have to be handed to the encoder and decoder when those
// are built, which is before a stream can be opened: opening blocks, and the
// peer's limits are not known yet. Anything written in the meantime is held and
// flushed when the stream arrives.
//
// In practice almost nothing is held. The streams are opened as soon as the
// connection is up, in the same goroutine that sends SETTINGS, because Chrome
// opens all three at once and a client that opened its QPACK streams lazily —
// only when it first had something to insert — would be announcing when that
// was.
type uniStreamWriter struct {
	streamType uint64

	mu      sync.Mutex
	str     *quic.SendStream
	pending []byte
	err     error
}

func newUniStreamWriter(streamType uint64) *uniStreamWriter {
	return &uniStreamWriter{streamType: streamType}
}

// attach gives the writer its stream, writes the stream type, and flushes.
func (w *uniStreamWriter) attach(str *quic.SendStream) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	w.str = str
	b := quicvarint.Append(nil, w.streamType)
	b = append(b, w.pending...)
	w.pending = nil
	_, err := str.Write(b)
	if err != nil {
		w.err = err
	}
	return err
}

func (w *uniStreamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.str == nil {
		w.pending = append(w.pending, p...)
		return len(p), nil
	}
	n, err := w.str.Write(p)
	if err != nil {
		w.err = err
	}
	return n, err
}

// peerQPACKLimits reads the peer's QPACK settings out of the SETTINGS frame it
// sent.
//
// Upstream does not recognise either of them — it has no dynamic table — so
// they arrive in the catch-all map rather than in named fields. Absent means
// zero, which is the right reading: a peer that said nothing has promised
// nothing, and an encoder against it inserts nothing.
func peerQPACKLimits(s *Settings) (maxCapacity, maxBlocked uint64) {
	if s == nil {
		return 0, 0
	}
	return s.Other[quicprofile.H3SettingQPACKMaxTableCapacity],
		s.Other[quicprofile.H3SettingQPACKBlockedStreams]
}

// decodeBlock decodes a whole header block and hands it back as the iterator
// the parsers upstream expect.
//
// FORK DELTA. Upstream calls Decoder.Decode, which cannot wait and has nothing
// to acknowledge. With a dynamic table both matter: a block may reference
// entries whose insertions are still in flight on the encoder stream, and the
// peer cannot evict anything until it hears the block is done with them.
//
// The wait is bounded by ctx, which is the stream's, so a blocked block ends
// when the request does. A peer that referenced an entry it never inserts is
// the only way to reach that, and it is indistinguishable from one that is
// merely slow — which is why the answer is a deadline rather than a limit.
func decodeBlock(ctx context.Context, d *qpack.Decoder, streamID uint64, block []byte) (qpack.DecodeFunc, error) {
	fields, err := d.DecodeForStream(ctx, streamID, block)
	if err != nil {
		return nil, err
	}
	i := 0
	return func() (qpack.HeaderField, error) {
		if i >= len(fields) {
			return qpack.HeaderField{}, io.EOF
		}
		hf := fields[i]
		i++
		return hf, nil
	}, nil
}

// appendChromeSettings writes the SETTINGS frame Chrome sends.
//
// The entries go in the order internal/quic/http3.go records, which is the
// order they were seen in and which does not move between connections. The
// reserved entry goes last, and its shape is not a guess: the report gave the
// frame body as 31 bytes, the four known entries account for 15, and the only
// way to spend the remaining 16 is an eight-byte varint id with an eight-byte
// value. See TestSettingsFrameLengthImpliesAnEightByteGrease.
func appendChromeSettings(b []byte) []byte {
	ref := quicprofile.Chrome151H3

	var body []byte
	for _, s := range ref.Settings {
		body = quicvarint.Append(body, s.ID)
		body = quicvarint.Append(body, s.Value)
	}
	if ref.GreaseSetting {
		id, val := greaseSetting()
		body = quicvarint.Append(body, id)
		body = quicvarint.Append(body, val)
	}

	b = quicvarint.Append(b, 0x4) // SETTINGS
	b = quicvarint.Append(b, uint64(len(body)))
	return append(b, body...)
}

// greaseSetting returns a reserved setting identifier and value (RFC 9114
// section 7.2.4.1: 0x1f * N + 0x21), both encoded in eight bytes.
//
// The eight bytes are the point. A reserved setting drawn as a small number
// would encode short, the frame would come out a different length from
// Chrome's, and the randomness would have made the client more distinctive
// rather than less.
func greaseSetting() (id, value uint64) {
	const (
		// Keeping 0x1f*N+0x21 inside the 62-bit varint space, and above the
		// four-byte boundary so the identifier needs all eight.
		maxN   = (1<<62 - 1 - 0x21) / 0x1f
		floorN = 1 << 35
	)
	n, err := rand.Int(rand.Reader, big.NewInt(maxN-floorN))
	if err != nil {
		// crypto/rand does not fail in practice, and a SETTINGS frame is not a
		// place to start returning errors upstream never returns.
		n = big.NewInt(floorN)
	}
	id = (uint64(n.Int64())+floorN)*0x1f + 0x21

	v, err := rand.Int(rand.Reader, big.NewInt(1<<62-1))
	if err != nil {
		return id, 1 << 35
	}
	value = uint64(v.Int64())
	if value < 1<<30 {
		// Force the eight-byte encoding, which is what the frame length says.
		value |= 1 << 61
	}
	return id, value
}

// appendControlStreamTail writes what Chrome sends after SETTINGS.
//
// A control stream that stops at SETTINGS is its own signal, and this is the
// cheapest fingerprint in the whole profile to get wrong by omission: both
// frames are ignorable by any peer, so nothing ever fails because they are
// missing.
func appendControlStreamTail(b []byte) []byte {
	ref := quicprofile.Chrome151H3

	if ref.GreaseFrameAfterSettings {
		// A reserved frame type (RFC 9114 section 7.2.8, 0x1f * N + 0x21) with a
		// short random payload. Its whole purpose is to be ignored, which is how
		// a peer that cannot ignore it gets found.
		id, payload := greaseFrame()
		b = quicvarint.Append(b, id)
		b = quicvarint.Append(b, uint64(len(payload)))
		b = append(b, payload...)
	}

	for _, frameType := range ref.AfterSettings {
		switch frameType {
		case quicprofile.H3FramePriorityUpdate:
			// PRIORITY_UPDATE for a request stream, sent before any request
			// exists. The payload is the Priority Field Value of RFC 9218,
			// which is what a fetch carries.
			payload := append([]byte{}, quicvarint.Append(nil, 0)...) // Prioritized Element ID
			payload = append(payload, ref.DefaultPriority...)
			b = quicvarint.Append(b, frameType)
			b = quicvarint.Append(b, uint64(len(payload)))
			b = append(b, payload...)
		}
	}
	return b
}

func greaseFrame() (id uint64, payload []byte) {
	const (
		maxN   = (1<<62 - 1 - 0x21) / 0x1f
		floorN = 1 << 20
	)
	n, err := rand.Int(rand.Reader, big.NewInt(maxN-floorN))
	if err != nil {
		n = big.NewInt(floorN)
	}
	id = (uint64(n.Int64())+floorN)*0x1f + 0x21

	ln, err := rand.Int(rand.Reader, big.NewInt(8))
	if err != nil {
		ln = big.NewInt(0)
	}
	payload = make([]byte, int(ln.Int64()))
	rand.Read(payload)
	return id, payload
}

// orderFields puts a request's fields in the order the profile sends them.
//
// The pseudo-headers come first, in an order that is neither the one RFC 9114
// lists nor the one upstream emits. Then the regular headers, in the order a
// fetch produces, with anything the profile does not name kept in the order the
// caller gave.
//
// Keeping unnamed headers in the caller's order rather than sorting them is
// deliberate. A caller adding its own header is already off the profile, and
// the least surprising thing to do with it is nothing; sorting would be a
// second, invented order matching no browser. Upstream does not sort either —
// it iterates a Go map, so its order is randomised per request, which is worse
// than any fixed choice.
//
// Empty pseudoOrder or headerOrder means the profile's, which is what a
// Transport that was not configured otherwise gets.
func orderFields(fields []qpack.HeaderField, pseudoOrder, headerOrder []string) []qpack.HeaderField {
	ref := quicprofile.Chrome151H3
	if len(pseudoOrder) == 0 {
		pseudoOrder = ref.PseudoHeaderOrder
	}
	if len(headerOrder) == 0 {
		headerOrder = ref.FetchHeaderOrder
	}

	rank := make(map[string]int, len(pseudoOrder)+len(headerOrder))
	for i, name := range pseudoOrder {
		rank[name] = i
	}
	base := len(pseudoOrder)
	for i, name := range headerOrder {
		rank[name] = base + i
	}
	// Anything unnamed sorts after everything named, and keeps its position
	// among the other unnamed ones.
	unknown := base + len(headerOrder)

	out := slices.Clone(fields)
	slices.SortStableFunc(out, func(a, b qpack.HeaderField) int {
		ra, oka := rank[a.Name]
		rb, okb := rank[b.Name]
		if !oka {
			ra = unknown
		}
		if !okb {
			rb = unknown
		}
		return ra - rb
	})
	return out
}
