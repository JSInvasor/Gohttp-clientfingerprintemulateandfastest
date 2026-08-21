package qpack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// FORK DELTA. Not present upstream.
//
// The decoding half of a dynamic table: the peer's insertions, the blocking
// that sometimes has to happen before a header block can be read, and the
// acknowledgements that go back.
//
// This is the half that is not optional. SETTINGS_QPACK_MAX_TABLE_CAPACITY is
// a promise about what this endpoint's decoder will accept, and a peer that
// believes it will encode against the table. Upstream's decoder answers such a
// block with an error; this one answers it with the header fields.
//
// Three pieces of state, and they move at different times:
//
//   - The table itself, which only the peer's encoder stream changes.
//   - The insert count, which is how far this decoder has got through that
//     stream. A header block names the insert count it needs, and if this one
//     is behind, the block waits.
//   - What has been acknowledged back, which is how the peer learns it may
//     evict. Getting this wrong does not corrupt anything on this side; it
//     stalls the peer's encoder instead, which is harder to notice.
//
// Everything here is safe for concurrent use, because it has to be: the encoder
// stream is read by one goroutine for the whole connection while request
// goroutines decode header blocks against what it has produced.

// ErrBlocked is returned by Decode when a header block references dynamic table
// entries this decoder has not received yet.
//
// It is a real condition rather than a failure — the encoder is allowed to
// reference entries whose insertions are still in flight, and that is what
// SETTINGS_QPACK_BLOCKED_STREAMS is a budget for. Callers that can wait should
// use DecodeForStream, which waits.
var ErrBlocked = errors.New("qpack: header block is blocked on the dynamic table")

// DecoderConfig is what this endpoint advertises to the peer, and where its
// acknowledgements go.
type DecoderConfig struct {
	// MaxTableCapacity is SETTINGS_QPACK_MAX_TABLE_CAPACITY: the largest
	// dynamic table this decoder will keep. Zero means no dynamic table, which
	// is upstream's behaviour and what NewDecoder gives.
	MaxTableCapacity uint64

	// MaxBlockedStreams is SETTINGS_QPACK_BLOCKED_STREAMS. It is advertised for
	// the peer's encoder to respect; nothing here enforces it, because a
	// decoder that refused a block over the limit would be turning the peer's
	// bookkeeping error into a dead connection.
	MaxBlockedStreams uint64

	// DecoderStream is the unidirectional stream this decoder writes its
	// acknowledgements to. It may be nil, in which case none are sent — which
	// is correct only when there is no dynamic table, since a peer that never
	// hears back can never evict.
	DecoderStream io.Writer
}

// dynamicState is the decoder's connection-level QPACK state.
type dynamicState struct {
	cfg DecoderConfig

	mu    sync.Mutex
	table dynamicTable
	// waiters are woken every time the insert count moves.
	waiters []chan struct{}

	// pending is the peer's encoder stream, minus whatever has been parsed.
	// Instructions arrive split across reads and are only acted on whole.
	pending []byte

	// ackMu serialises writes to the decoder stream. Held separately from mu so
	// a slow stream cannot block a decode.
	ackMu sync.Mutex
	// acked is how much of the insert count the peer has been told about.
	// Insert Count Increment is a delta, so the running total has to be kept.
	acked uint64
}

// NewDecoderWithDynamicTable returns a Decoder that keeps a dynamic table.
//
// The zero-capacity case is deliberately not special: it produces a decoder
// that behaves exactly as NewDecoder's, because a table that can hold nothing
// is a table no encoder can reference.
func NewDecoderWithDynamicTable(cfg DecoderConfig) *Decoder {
	d := &Decoder{}
	if cfg.MaxTableCapacity > 0 || cfg.DecoderStream != nil {
		d.dyn = &dynamicState{cfg: cfg}
	}
	return d
}

// EncoderStream returns the writer to feed the peer's encoder stream into.
//
// The caller reads that QUIC stream and copies into this; it is an io.Writer
// rather than a Read loop so the caller keeps control of its own goroutine and
// its own errors. Partial instructions are held here until the rest arrives.
func (d *Decoder) EncoderStream() io.Writer {
	if d.dyn == nil {
		// Without a table there is nothing an insertion could mean. Reject
		// rather than discard: a peer sending on this stream believes something
		// about this endpoint that is not true, and silently ignoring it would
		// leave every later index unresolvable with no explanation.
		return errorWriter{errors.New("qpack: peer opened an encoder stream, but no dynamic table was advertised")}
	}
	return encoderStreamWriter{d.dyn}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type encoderStreamWriter struct{ s *dynamicState }

func (w encoderStreamWriter) Write(p []byte) (int, error) {
	if err := w.s.readEncoderStream(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// readEncoderStream applies every complete instruction in p.
func (s *dynamicState) readEncoderStream(p []byte) error {
	s.mu.Lock()
	s.pending = append(s.pending, p...)
	buf := s.pending
	var applied bool
	for len(buf) > 0 {
		ins, rest, err := parseEncoderInstruction(buf)
		if errors.Is(err, errNeedMore) {
			break
		}
		if err != nil {
			s.mu.Unlock()
			return err
		}
		if err := s.apply(ins); err != nil {
			s.mu.Unlock()
			return err
		}
		buf = rest
		applied = true
	}
	// Keep the tail, and let go of what was consumed rather than growing the
	// buffer for the life of the connection.
	s.pending = append(s.pending[:0], buf...)
	inserted := s.table.insertCount()
	if applied {
		s.wakeLocked()
	}
	s.mu.Unlock()

	if applied {
		// Tell the peer how far this decoder has got, so it can evict. The
		// increment is against what was last acknowledged, which
		// acknowledgeInserts tracks.
		return s.acknowledgeInserts(inserted)
	}
	return nil
}

// apply runs one instruction against the table. s.mu is held.
func (s *dynamicState) apply(ins encoderInstruction) error {
	switch ins.kind {
	case setDynamicTableCapacity:
		if ins.capacity > s.cfg.MaxTableCapacity {
			return fmt.Errorf("qpack: peer set a table capacity of %d, over the %d advertised",
				ins.capacity, s.cfg.MaxTableCapacity)
		}
		s.table.setCapacity(ins.capacity)
		return nil

	case insertNameReference:
		var name string
		if ins.static {
			hf, ok := staticAt(ins.index)
			if !ok {
				return invalidIndexError(ins.index)
			}
			name = hf.Name
		} else {
			hf, err := s.table.atRelativeToInsertCount(ins.index)
			if err != nil {
				return err
			}
			name = hf.Name
		}
		return s.table.insert(HeaderField{Name: name, Value: ins.value})

	case insertLiteralName:
		return s.table.insert(HeaderField{Name: ins.name, Value: ins.value})

	case duplicateEntry:
		hf, err := s.table.atRelativeToInsertCount(ins.index)
		if err != nil {
			return err
		}
		return s.table.insert(hf)
	}
	return fmt.Errorf("qpack: unhandled encoder instruction %d", ins.kind)
}

// wakeLocked releases everything waiting on the insert count. s.mu is held.
func (s *dynamicState) wakeLocked() {
	for _, ch := range s.waiters {
		close(ch)
	}
	s.waiters = nil
}

// waitFor blocks until the table holds at least n insertions.
func (s *dynamicState) waitFor(ctx context.Context, n uint64) error {
	for {
		s.mu.Lock()
		if s.table.insertCount() >= n {
			s.mu.Unlock()
			return nil
		}
		ch := make(chan struct{})
		s.waiters = append(s.waiters, ch)
		s.mu.Unlock()

		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// acknowledgedInserts is how much of the insert count the peer has been told
// about. Insert Count Increment is a delta, so this has to be remembered.
func (s *dynamicState) acknowledgeInserts(upTo uint64) error {
	s.ackMu.Lock()
	defer s.ackMu.Unlock()
	if s.cfg.DecoderStream == nil || upTo <= s.acked {
		return nil
	}
	b := appendInsertCountIncrement(nil, upTo-s.acked)
	s.acked = upTo
	_, err := s.cfg.DecoderStream.Write(b)
	return err
}

// acknowledgeSection tells the peer a header block on this stream has been
// decoded, which releases the entries it referenced.
func (s *dynamicState) acknowledgeSection(streamID uint64) error {
	s.ackMu.Lock()
	defer s.ackMu.Unlock()
	if s.cfg.DecoderStream == nil {
		return nil
	}
	_, err := s.cfg.DecoderStream.Write(appendSectionAcknowledgement(nil, streamID))
	return err
}

// CancelStream tells the peer that a stream was reset without its header block
// being decoded, so the entries it referenced can be released.
//
// A caller that abandons a request stream has to say so. Without it the peer's
// encoder holds those entries against eviction for the life of the connection,
// and its table slowly fills with things neither side can use.
func (d *Decoder) CancelStream(streamID uint64) error {
	if d.dyn == nil {
		return nil
	}
	d.dyn.ackMu.Lock()
	defer d.dyn.ackMu.Unlock()
	if d.dyn.cfg.DecoderStream == nil {
		return nil
	}
	_, err := d.dyn.cfg.DecoderStream.Write(appendStreamCancellation(nil, streamID))
	return err
}

// staticAt is the static table lookup, as a function rather than a method,
// because the encoder stream needs it and is not decoding a header block.
func staticAt(i uint64) (HeaderField, bool) {
	if i >= uint64(len(staticTableEntries)) {
		return HeaderField{}, false
	}
	return staticTableEntries[i], true
}
