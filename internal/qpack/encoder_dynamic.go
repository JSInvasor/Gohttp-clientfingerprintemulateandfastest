package qpack

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/net/http2/hpack"
)

// FORK DELTA. Not present upstream.
//
// The encoding half of a dynamic table: what this endpoint inserts, the encoder
// stream it announces the insertions on, and the peer's acknowledgements that
// say what may be evicted.
//
// Unlike the decoding half, none of this is required for a working connection.
// An encoder is always free to spell every field out, and a peer that never
// hears an insertion never references one. It is here because Chrome's encoder
// stream is not silent, and a client that advertises a 64 KiB table and then
// never inserts into it is distinguishable from one that does — at the QPACK
// layer, which sits behind everything else this repository matches.
//
// It is a whole-block API rather than an extension of upstream's Encoder, and
// that is forced rather than chosen. A header block's prefix carries the
// Required Insert Count and Base, and neither is known until every field has
// been encoded and it is settled which table entries were referenced. Upstream
// can write its prefix first because for a static-only encoder both are always
// zero. Building it this way also leaves encoder.go byte-identical to upstream,
// which is worth something on its own.
//
// Two rules constrain what may go in the table, and they pull in opposite
// directions:
//
//   - An entry may not be evicted while a header block that referenced it is
//     still unacknowledged (RFC 9204 section 2.1.1), or the peer will resolve
//     an index against something that is no longer there.
//   - Referencing an entry the peer has not inserted yet blocks that stream
//     until it has, and the peer's SETTINGS_QPACK_BLOCKED_STREAMS caps how many
//     streams may be blocked at once.
//
// Both are handled by declining rather than by failing. An encoder that cannot
// use the table writes a literal, which is always correct and merely larger, so
// no request is ever held up by table bookkeeping.

// EncoderTable is the connection-level state behind EncodeHeaderBlock.
//
// One per connection. The table is a property of the connection, and so is the
// stream the insertions go out on.
type EncoderTable struct {
	// writeMu orders whole encodings against each other, and is held across the
	// write to the encoder stream. mu is held only while the table is being
	// touched, and never across I/O.
	//
	// The split is not tidiness. The peer answers an insertion on its decoder
	// stream, which comes back into readDecoderStream and takes mu; a caller
	// that wires the two streams to each other directly — which is a reasonable
	// thing to do, and is what this package's own tests do — would deadlock
	// against a lock held across the write. The first version of this did, and
	// the loop test hung rather than failed.
	//
	// Order is always writeMu then mu. Nothing takes them the other way round.
	writeMu sync.Mutex

	mu    sync.Mutex
	table dynamicTable

	// stream is this endpoint's encoder stream. Nil gives an encoder that only
	// ever writes literals, which is upstream's behaviour and the right answer
	// for a peer that advertised no table.
	stream io.Writer

	maxCapacity  uint64 // the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY
	maxBlocked   uint64 // the peer's SETTINGS_QPACK_BLOCKED_STREAMS
	announced    bool   // whether the capacity has been sent
	ackedInserts uint64 // how far the peer says it has read

	// byField and byName find the newest matching entry, the newest being the
	// one furthest from eviction.
	byField map[HeaderField]uint64
	byName  map[string]uint64

	// sections records, per stream with an unacknowledged header block, the
	// oldest absolute index that block referenced. Nothing below the smallest
	// of these may be evicted.
	sections map[uint64]uint64
	// blocked counts sections that referenced entries the peer had not
	// acknowledged when they were written.
	blocked uint64

	// curMinRef is the oldest entry the block currently being encoded has
	// referenced or is about to, and curRefd says whether there is one.
	//
	// They are separate from sections because a block is not a section until it
	// is finished, and yet it constrains eviction from its first reference
	// onward: a block that indexed entry 0 and then inserted enough to evict it
	// would hand the peer an index resolving to nothing. That is not
	// hypothetical — it is what a small table did before this was here.
	curMinRef uint64
	curRefd   bool

	// pending is the peer's decoder stream, minus what has been parsed.
	pending []byte
}

// NewEncoderTable returns the shared encoder state for one connection.
//
// maxCapacity and maxBlocked are the peer's advertised limits, from its
// SETTINGS. stream is this endpoint's encoder stream.
func NewEncoderTable(stream io.Writer, maxCapacity, maxBlocked uint64) *EncoderTable {
	return &EncoderTable{
		stream:      stream,
		maxCapacity: maxCapacity,
		maxBlocked:  maxBlocked,
		byField:     map[HeaderField]uint64{},
		byName:      map[string]uint64{},
		sections:    map[uint64]uint64{},
	}
}

// DecoderStream returns the writer to feed the peer's decoder stream into.
//
// What arrives there is the peer saying how far it has read this endpoint's
// encoder stream and which header blocks it has finished with. Both release
// entries for eviction. A connection that never reads this stream keeps working
// and its table stops being useful, which looks like a performance problem
// rather than a bug — which is why it is worth wiring up deliberately.
func (t *EncoderTable) DecoderStream() io.Writer { return decoderStreamWriter{t} }

type decoderStreamWriter struct{ t *EncoderTable }

func (w decoderStreamWriter) Write(p []byte) (int, error) {
	if err := w.t.readDecoderStream(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *EncoderTable) readDecoderStream(p []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pending = append(t.pending, p...)
	buf := t.pending
	for len(buf) > 0 {
		ins, rest, err := parseDecoderInstruction(buf)
		if errors.Is(err, errNeedMore) {
			break
		}
		if err != nil {
			return err
		}
		switch ins.kind {
		case insertCountIncrement:
			if ins.value == 0 {
				return errors.New("qpack: peer sent an insert count increment of zero")
			}
			t.ackedInserts += ins.value
			if t.ackedInserts > t.table.insertCount() {
				return fmt.Errorf("qpack: peer acknowledged %d insertions, only %d were sent",
					t.ackedInserts, t.table.insertCount())
			}
		case sectionAcknowledgement, streamCancellation:
			t.releaseSection(ins.value)
		}
		buf = rest
	}
	t.pending = append(t.pending[:0], buf...)
	return nil
}

// releaseSection forgets a stream's outstanding header block. t.mu is held.
func (t *EncoderTable) releaseSection(streamID uint64) {
	if _, ok := t.sections[streamID]; !ok {
		return
	}
	delete(t.sections, streamID)
	if t.blocked > 0 {
		t.blocked--
	}
}

// evictionFloor is the oldest absolute index that has to be kept. t.mu is held.
// protect keeps an entry from being evicted for the rest of this block.
//
// It is called for everything the block references, and also for an entry the
// block is only considering — because an insertion made while considering it
// can evict it, and then the reference that follows resolves to nothing. Being
// conservative here costs at most a missed insertion. t.mu is held.
func (t *EncoderTable) protect(abs uint64) {
	if !t.curRefd || abs < t.curMinRef {
		t.curMinRef, t.curRefd = abs, true
	}
}

func (t *EncoderTable) evictionFloor() uint64 {
	floor := t.table.insertCount()
	for _, minRef := range t.sections {
		if minRef < floor {
			floor = minRef
		}
	}
	if t.curRefd && t.curMinRef < floor {
		floor = t.curMinRef
	}
	return floor
}

// canInsert reports whether an entry of this size fits without evicting
// anything an unacknowledged header block still references. t.mu is held.
func (t *EncoderTable) canInsert(sz uint64) bool {
	if sz > t.table.capacity {
		return false
	}
	if t.table.size+sz <= t.table.capacity {
		return true
	}
	floor := t.evictionFloor()
	freed := uint64(0)
	for i, hf := range t.table.entries {
		if t.table.dropped+uint64(i) >= floor {
			return false
		}
		freed += entrySize(hf)
		if t.table.size+sz-freed <= t.table.capacity {
			return true
		}
	}
	return false
}

// insert adds a field to the table and appends the instruction that announces
// it to out, returning its absolute index. t.mu is held.
//
// The instruction is appended rather than written because the write happens
// after mu is released; see the comment on writeMu. A false second return means
// the table declined, which is not an error: the caller writes a literal
// instead.
func (t *EncoderTable) insert(out []byte, hf HeaderField, nameAbs uint64, nameStatic, haveName bool) ([]byte, uint64, bool, error) {
	if t.stream == nil || t.maxCapacity == 0 {
		return out, 0, false, nil
	}
	if !t.announced {
		out = appendSetCapacity(out, t.maxCapacity)
		t.table.setCapacity(t.maxCapacity)
		t.announced = true
	}
	if !t.canInsert(entrySize(hf)) {
		return out, 0, false, nil
	}

	switch {
	case haveName && nameStatic:
		out = appendInsertWithNameReference(out, nameAbs, true, hf.Value)
	case haveName:
		// An encoder-stream index counts back from the newest entry, so it has
		// to be computed here, before the insertion moves the newest.
		out = appendInsertWithNameReference(out, t.table.insertCount()-1-nameAbs, false, hf.Value)
	default:
		out = appendInsertWithLiteralName(out, hf.Name, hf.Value)
	}

	// Note what is about to be evicted before it goes, so its index entries can
	// be dropped. Reading them back afterwards would be too late.
	doomed := t.entriesEvictedBy(entrySize(hf))
	if err := t.table.insert(hf); err != nil {
		// canInsert said this would fit, so the two disagree and the instruction
		// is already in the buffer. Nothing after this point could be trusted.
		return out, 0, false, fmt.Errorf("qpack: encoder stream and table have diverged: %w", err)
	}
	for abs, e := range doomed {
		t.forget(e, abs)
	}

	abs := t.table.insertCount() - 1
	t.byField[hf] = abs
	t.byName[hf.Name] = abs
	return out, abs, true, nil
}

// entriesEvictedBy returns what inserting sz bytes will drop. t.mu is held.
func (t *EncoderTable) entriesEvictedBy(sz uint64) map[uint64]HeaderField {
	out := map[uint64]HeaderField{}
	freed := uint64(0)
	for i, hf := range t.table.entries {
		if t.table.size+sz-freed <= t.table.capacity {
			break
		}
		out[t.table.dropped+uint64(i)] = hf
		freed += entrySize(hf)
	}
	return out
}

// forget drops an evicted entry's indices, but only where they still point at
// it: the same name may have been inserted again since.
func (t *EncoderTable) forget(hf HeaderField, abs uint64) {
	if t.byField[hf] == abs {
		delete(t.byField, hf)
	}
	if t.byName[hf.Name] == abs {
		delete(t.byName, hf.Name)
	}
}

// EncodeHeaderBlock encodes a whole field list for one stream.
//
// The fields go out in the order given, which for this repository is the whole
// point: header order is part of the profile, and an encoder that sorted or
// grouped them would undo it.
func (t *EncoderTable) EncodeHeaderBlock(streamID uint64, fields []HeaderField) ([]byte, error) {
	// writeMu keeps this encoding, and the encoder-stream bytes it produces,
	// ordered against any other. mu is taken inside it and released before the
	// write.
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	block, instructions, err := t.encodeLocked(streamID, fields)
	if err != nil {
		return nil, err
	}
	if len(instructions) > 0 {
		if _, err := t.stream.Write(instructions); err != nil {
			// The table has already been updated, so this endpoint and the peer
			// now disagree about what is in it. Nothing can be encoded against
			// the table after this, and the caller is expected to fail the
			// connection rather than carry on.
			return nil, fmt.Errorf("qpack: encoder stream: %w", err)
		}
	}
	return block, nil
}

// encodeLocked does the encoding and the table updates, and hands back the
// encoder-stream instructions for the caller to write once mu is released.
func (t *EncoderTable) encodeLocked(streamID uint64, fields []HeaderField) (block, instructions []byte, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.curRefd = false
	defer func() { t.curRefd = false }()

	base := t.table.insertCount()
	// mayBlock decides whether this block is allowed to reference entries the
	// peer has not acknowledged. Referencing one stalls this stream until the
	// insertion arrives, and the peer capped how many streams may be stalled.
	mayBlock := t.blocked < t.maxBlocked

	var body []byte
	var minRef, maxRef uint64
	var referenced bool
	noteRef := func(abs uint64) {
		if !referenced || abs < minRef {
			minRef = abs
		}
		if !referenced || abs > maxRef {
			maxRef = abs
		}
		referenced = true
		t.protect(abs)
	}

	for _, hf := range fields {
		staticIdx, staticName, staticExact := lookupStatic(hf)
		if staticExact {
			body = appendIndexedStatic(body, staticIdx)
			continue
		}

		// An entry already in the table beats inserting the same thing again.
		if abs, nameOnly, ok := t.lookup(hf); ok && (mayBlock || abs < t.ackedInserts) {
			if !nameOnly {
				body = appendIndexedDynamic(body, base, abs)
				noteRef(abs)
				continue
			}
			// The name is there but not this value. Inserting the pair is
			// usually worth it: a header that recurs with a changing value is
			// exactly what a dynamic table is for.
			//
			// Protect the entry first. Whether the insertion succeeds or not,
			// this block may end up referencing the name at abs, and the
			// insertion itself can evict it — which is what happened on the
			// second request of the churn test before this line existed.
			t.protect(abs)
			var newAbs uint64
			var inserted bool
			instructions, newAbs, inserted, err = t.insert(instructions, hf, abs, false, true)
			if err != nil {
				return nil, nil, err
			}
			if inserted && mayBlock {
				body = appendIndexedDynamic(body, base, newAbs)
				noteRef(newAbs)
				continue
			}
			body = appendLiteralWithDynamicName(body, base, abs, hf.Value)
			noteRef(abs)
			continue
		}

		// Not in the table. Try to put it there.
		var newAbs uint64
		var inserted bool
		instructions, newAbs, inserted, err = t.insert(instructions, hf, uint64(staticIdx), staticName, staticName)
		if err != nil {
			return nil, nil, err
		}
		if inserted && mayBlock {
			body = appendIndexedDynamic(body, base, newAbs)
			noteRef(newAbs)
			continue
		}
		if staticName {
			body = appendLiteralWithStaticName(body, staticIdx, hf.Value)
			continue
		}
		body = appendLiteralWithLiteralName(body, hf.Name, hf.Value)
	}

	var required uint64
	if referenced {
		required = maxRef + 1
	}
	out := appendBlockPrefix(nil, required, base, t.maxCapacity)
	out = append(out, body...)

	if referenced {
		t.sections[streamID] = minRef
		if required > t.ackedInserts {
			t.blocked++
		}
	}
	return out, instructions, nil
}

// CancelStream forgets a header block whose stream was reset before the peer
// acknowledged it, releasing the entries it held against eviction.
func (t *EncoderTable) CancelStream(streamID uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.releaseSection(streamID)
}

// lookup finds an entry by name and value, then by name alone. t.mu is held.
func (t *EncoderTable) lookup(hf HeaderField) (abs uint64, nameOnly, ok bool) {
	if abs, found := t.byField[hf]; found {
		if _, err := t.table.at(abs); err == nil {
			return abs, false, true
		}
	}
	if abs, found := t.byName[hf.Name]; found {
		if _, err := t.table.at(abs); err == nil {
			return abs, true, true
		}
	}
	return 0, false, false
}

// lookupStatic reports what the static table has for a field: an exact match if
// it can, otherwise an index for the name alone.
//
// It reads upstream's encoderMap, so a static-table lookup here and one in
// upstream's Encoder cannot disagree.
func lookupStatic(hf HeaderField) (idx uint8, haveName, exact bool) {
	e, ok := encoderMap[hf.Name]
	if !ok {
		return 0, false, false
	}
	if e.values != nil {
		if v, ok := e.values[hf.Value]; ok {
			return v, true, true
		}
	} else if len(hf.Value) == 0 {
		return e.idx, true, true
	}
	return e.idx, true, false
}

// The field line representations (RFC 9204 section 4.5). The three upstream
// also writes produce identical bytes; see TestStaticOnlyBlocksMatchUpstream.

func appendIndexedStatic(b []byte, idx uint8) []byte {
	off := len(b)
	b = appendVarInt(b, 6, uint64(idx))
	b[off] |= 0xc0 // 1Txxxxxx, T=1
	return b
}

// appendIndexedDynamic writes whichever of the two dynamic indexed forms
// reaches the entry: relative to Base going back, post-base going forward.
func appendIndexedDynamic(b []byte, base, abs uint64) []byte {
	off := len(b)
	if abs < base {
		b = appendVarInt(b, 6, base-1-abs)
		b[off] |= 0x80 // 1Txxxxxx, T=0
		return b
	}
	b = appendVarInt(b, 4, abs-base)
	b[off] |= 0x10 // 0001xxxx
	return b
}

func appendLiteralWithStaticName(b []byte, idx uint8, value string) []byte {
	off := len(b)
	b = appendVarInt(b, 4, uint64(idx))
	b[off] |= 0x50 // 01NTxxxx, N=0 T=1
	return appendValueString(b, value)
}

func appendLiteralWithDynamicName(b []byte, base, abs uint64, value string) []byte {
	off := len(b)
	if abs < base {
		b = appendVarInt(b, 4, base-1-abs)
		b[off] |= 0x40 // 01NTxxxx, N=0 T=0
		return appendValueString(b, value)
	}
	b = appendVarInt(b, 3, abs-base)
	b[off] |= 0x00 // 0000Nxxx, N=0
	return appendValueString(b, value)
}

func appendLiteralWithLiteralName(b []byte, name, value string) []byte {
	off := len(b)
	b = appendVarInt(b, 3, hpack.HuffmanEncodeLength(name))
	b[off] |= 0x28 // 001NHxxx, N=0 H=1
	b = hpack.AppendHuffmanString(b, name)
	return appendValueString(b, value)
}

// appendBlockPrefix writes the Required Insert Count and Delta Base.
//
// Base is this block's starting insert count, so anything inserted while
// encoding it is reached by a post-base index. That is what the sign bit is
// for: S=1 says Base is behind the Required Insert Count, which is precisely
// the case where a block references entries it caused to exist.
func appendBlockPrefix(b []byte, required, base, capacity uint64) []byte {
	b = appendVarInt(b, 8, encodeInsertCount(required, capacity))
	off := len(b)
	if base >= required {
		b = appendVarInt(b, 7, base-required)
		return b
	}
	b = appendVarInt(b, 7, required-base-1)
	b[off] |= 0x80 // S=1
	return b
}
