package qpack

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// An invalidIndexError is returned when decoding encounters an invalid index
// (e.g., an index that is out of bounds for the static table).
type invalidIndexError int

func (e invalidIndexError) Error() string {
	return fmt.Sprintf("invalid indexed representation index %d", int(e))
}

// errNoDynamicTable is upstream's answer to every reference to the dynamic
// table. Here it is narrowed to the case that is still true: a decoder built by
// NewDecoder, which has no table for a reference to mean anything against.
var errNoDynamicTable = errors.New("no dynamic table")

// A Decoder decodes QPACK header blocks.
// A Decoder can be reused to decode multiple header blocks on different streams
// on the same connection (e.g., headers then trailers).
type Decoder struct {
	// FORK DELTA: the connection's dynamic table, or nil when there is none.
	//
	// Nil is what NewDecoder gives and what upstream always has, and every
	// dynamic-table path below is guarded on it, so a caller that has not opted
	// in gets upstream's behaviour including its errors.
	dyn *dynamicState
}

// DecodeFunc is a function that decodes the next header field from a header block.
// It should be called repeatedly until it returns io.EOF.
// It returns io.EOF when all header fields have been decoded.
// Any error other than io.EOF indicates a decoding error.
type DecodeFunc func() (HeaderField, error)

// NewDecoder returns a new Decoder.
//
// It has no dynamic table. See NewDecoderWithDynamicTable for one that does,
// and internal/qpack/FORK.md for why this package carries both.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decode returns a function that decodes header fields from the given header block.
// It does not copy the slice; the caller must ensure it remains valid during decoding.
//
// FORK DELTA: a block that references dynamic table entries this decoder has not
// received yet returns ErrBlocked rather than being waited for. Decode cannot
// wait — it has neither a context to be cancelled by nor a stream to acknowledge
// on. DecodeForStream has both.
func (d *Decoder) Decode(p []byte) DecodeFunc {
	var readPrefix bool
	var base uint64

	return func() (HeaderField, error) {
		if !readPrefix {
			b, rest, err := d.readPrefix(p)
			if err != nil {
				return HeaderField{}, err
			}
			p = rest
			base = b
			readPrefix = true
		}

		if len(p) == 0 {
			return HeaderField{}, io.EOF
		}

		b := p[0]
		var hf HeaderField
		var rest []byte
		var err error
		switch {
		case (b & 0x80) > 0: // 1Txxxxxx
			hf, rest, err = d.parseIndexedHeaderField(p, base)
		case (b & 0xc0) == 0x40: // 01NTxxxx
			hf, rest, err = d.parseLiteralHeaderField(p, base)
		case (b & 0xe0) == 0x20: // 001NHxxx
			hf, rest, err = d.parseLiteralHeaderFieldWithoutNameReference(p)
		// FORK DELTA: the two post-base representations. Upstream rejects both
		// as an unexpected type byte, because without a dynamic table there is
		// no Base for them to be relative to.
		case (b & 0xf0) == 0x10: // 0001xxxx
			hf, rest, err = d.parseIndexedHeaderFieldPostBase(p, base)
		case (b & 0xf0) == 0x00: // 0000Nxxx
			hf, rest, err = d.parseLiteralHeaderFieldPostBase(p, base)
		default:
			err = fmt.Errorf("unexpected type byte: %#x", b)
		}
		p = rest
		if err != nil {
			return HeaderField{}, err
		}
		return hf, nil
	}
}

// DecodeForStream decodes a whole header block, waiting for the dynamic table
// to catch up if the block needs it, and acknowledging the block afterwards.
//
// FORK DELTA. Not present upstream, which has nothing to wait for and nothing
// to acknowledge.
//
// The acknowledgement is not bookkeeping that can be skipped: it is what lets
// the peer's encoder evict the entries this block referenced. A decoder that
// never sends one leaves the peer's table filling with entries it may not touch,
// and the failure shows up much later and somewhere else.
func (d *Decoder) DecodeForStream(ctx context.Context, streamID uint64, p []byte) ([]HeaderField, error) {
	if d.dyn != nil {
		required, err := d.requiredInsertCount(p)
		if err != nil {
			return nil, err
		}
		if required > 0 {
			if err := d.dyn.waitFor(ctx, required); err != nil {
				return nil, err
			}
		}
	}

	var fields []HeaderField
	decode := d.Decode(p)
	for {
		hf, err := decode()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		fields = append(fields, hf)
	}

	if d.dyn != nil {
		// Only a block that actually referenced the dynamic table needs
		// acknowledging (RFC 9204 section 4.4.1). Sending one for a block that
		// did not would advance the peer's idea of what this decoder has seen.
		required, err := d.requiredInsertCount(p)
		if err != nil {
			return nil, err
		}
		if required > 0 {
			if err := d.dyn.acknowledgeSection(streamID); err != nil {
				return nil, err
			}
		}
	}
	return fields, nil
}

// requiredInsertCount reads just the first field of the header block prefix.
func (d *Decoder) requiredInsertCount(p []byte) (uint64, error) {
	encoded, _, err := readVarInt(8, p)
	if err != nil {
		return 0, err
	}
	if d.dyn == nil {
		if encoded != 0 {
			return 0, errors.New("qpack: header block requires the dynamic table, which is not enabled")
		}
		return 0, nil
	}
	d.dyn.mu.Lock()
	total := d.dyn.table.insertCount()
	capacity := d.dyn.cfg.MaxTableCapacity
	d.dyn.mu.Unlock()
	return decodeInsertCount(encoded, total, capacity)
}

// readPrefix consumes the header block prefix and returns Base.
//
// FORK DELTA. Upstream reads the same two fields but requires both to be zero.
// The arithmetic here is RFC 9204 sections 4.5.1.1 and 4.5.1.2, and it is the
// part of QPACK that is easy to get subtly wrong: the Required Insert Count is
// sent modulo twice the table's maximum entry count, so decoding it needs this
// decoder's own progress to pick the right candidate, and Base is sent as a
// signed delta from it rather than as itself.
func (d *Decoder) readPrefix(p []byte) (base uint64, rest []byte, err error) {
	encodedInsertCount, rest, err := readVarInt(8, p)
	if err != nil {
		return 0, p, err
	}
	var required uint64
	if d.dyn == nil {
		if encodedInsertCount != 0 {
			return 0, p, errors.New("expected Required Insert Count to be zero")
		}
	} else {
		d.dyn.mu.Lock()
		total := d.dyn.table.insertCount()
		capacity := d.dyn.cfg.MaxTableCapacity
		d.dyn.mu.Unlock()
		required, err = decodeInsertCount(encodedInsertCount, total, capacity)
		if err != nil {
			return 0, p, err
		}
		if required > total {
			return 0, p, fmt.Errorf("%w: needs %d insertions, have %d", ErrBlocked, required, total)
		}
	}

	if len(rest) == 0 {
		return 0, p, io.ErrUnexpectedEOF
	}
	sign := rest[0]&0x80 != 0
	deltaBase, rest, err := readVarInt(7, rest)
	if err != nil {
		return 0, p, err
	}
	if d.dyn == nil {
		if deltaBase != 0 || sign {
			return 0, p, errors.New("expected Base to be zero")
		}
		return 0, rest, nil
	}
	if sign {
		// S=1: Base = Required Insert Count - Delta Base - 1. The encoder uses
		// this when the block references entries older than the ones it just
		// inserted for it.
		if deltaBase+1 > required {
			return 0, p, fmt.Errorf("qpack: Base underflows: required insert count %d, delta %d",
				required, deltaBase)
		}
		return required - deltaBase - 1, rest, nil
	}
	return required + deltaBase, rest, nil
}

// dynamicRelativeToBase and dynamicPostBase resolve the two kinds of dynamic
// reference a header block can carry, under the table's lock.
//
// They exist rather than one absolute-index helper so that the arithmetic lives
// in exactly one place, beside the table it indexes. An earlier revision worked
// out base-1-index and base+index here instead, which meant dynamic_table.go's
// tests and these paths could disagree — and did not notice when one of them
// was deliberately broken to check that they would.
func (d *Decoder) dynamicRelativeToBase(base, rel uint64) (HeaderField, error) {
	if d.dyn == nil {
		return HeaderField{}, errNoDynamicTable
	}
	d.dyn.mu.Lock()
	defer d.dyn.mu.Unlock()
	return d.dyn.table.atRelativeToBase(base, rel)
}

func (d *Decoder) dynamicPostBase(base, post uint64) (HeaderField, error) {
	if d.dyn == nil {
		return HeaderField{}, errNoDynamicTable
	}
	d.dyn.mu.Lock()
	defer d.dyn.mu.Unlock()
	return d.dyn.table.atPostBase(base, post)
}

func (d *Decoder) parseIndexedHeaderField(buf []byte, base uint64) (_ HeaderField, rest []byte, _ error) {
	static := buf[0]&0x40 != 0
	index, rest, err := readVarInt(6, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	if !static {
		// FORK DELTA: T=0 means the dynamic table, relative to Base. Upstream
		// returns errNoDynamicTable here.
		hf, err := d.dynamicRelativeToBase(base, index)
		if err != nil {
			return HeaderField{}, buf, err
		}
		return hf, rest, nil
	}
	hf, ok := staticAt(index)
	if !ok {
		return HeaderField{}, buf, invalidIndexError(index)
	}
	return hf, rest, nil
}

// parseIndexedHeaderFieldPostBase handles 0001xxxx.
//
// FORK DELTA. Not present upstream. The index counts forward from Base rather
// than back from it, which is how a header block references entries the encoder
// inserted while encoding that same block.
func (d *Decoder) parseIndexedHeaderFieldPostBase(buf []byte, base uint64) (_ HeaderField, rest []byte, _ error) {
	index, rest, err := readVarInt(4, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	hf, err := d.dynamicPostBase(base, index)
	if err != nil {
		return HeaderField{}, buf, err
	}
	return hf, rest, nil
}

func (d *Decoder) parseLiteralHeaderField(buf []byte, base uint64) (_ HeaderField, rest []byte, _ error) {
	static := buf[0]&0x10 != 0
	// We don't need to check the value of the N-bit here.
	// It's only relevant when re-encoding header fields, and determines whether
	// the header field may be added to a dynamic table. This decoder never
	// re-encodes what it decoded, so it can ignore it.
	index, rest, err := readVarInt(4, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	var hf HeaderField
	if static {
		var ok bool
		hf, ok = staticAt(index)
		if !ok {
			return HeaderField{}, buf, invalidIndexError(index)
		}
	} else {
		// FORK DELTA: T=0 means the dynamic table, relative to Base.
		hf, err = d.dynamicRelativeToBase(base, index)
		if err != nil {
			return HeaderField{}, buf, err
		}
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, buf, io.ErrUnexpectedEOF
	}
	usesHuffman := buf[0]&0x80 > 0
	val, rest, err := d.readString(rest, 7, usesHuffman)
	if err != nil {
		return HeaderField{}, rest, err
	}
	hf.Value = val
	return hf, rest, nil
}

// parseLiteralHeaderFieldPostBase handles 0000Nxxx.
//
// FORK DELTA. Not present upstream.
func (d *Decoder) parseLiteralHeaderFieldPostBase(buf []byte, base uint64) (_ HeaderField, rest []byte, _ error) {
	index, rest, err := readVarInt(3, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	hf, err := d.dynamicPostBase(base, index)
	if err != nil {
		return HeaderField{}, buf, err
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, buf, io.ErrUnexpectedEOF
	}
	usesHuffman := buf[0]&0x80 > 0
	val, rest, err := d.readString(rest, 7, usesHuffman)
	if err != nil {
		return HeaderField{}, rest, err
	}
	hf.Value = val
	return hf, rest, nil
}

func (d *Decoder) parseLiteralHeaderFieldWithoutNameReference(buf []byte) (_ HeaderField, rest []byte, _ error) {
	usesHuffmanForName := buf[0]&0x8 > 0
	name, rest, err := d.readString(buf, 3, usesHuffmanForName)
	if err != nil {
		return HeaderField{}, rest, err
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, rest, io.ErrUnexpectedEOF
	}
	usesHuffmanForVal := buf[0]&0x80 > 0
	val, rest, err := d.readString(buf, 7, usesHuffmanForVal)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: val}, rest, nil
}

// FORK DELTA: the body moved to instructions.go as readStringLiteral, because
// the encoder-stream parser needs the same code and is not decoding a header
// block. The behaviour, including the errors, is upstream's.
func (d *Decoder) readString(buf []byte, n uint8, usesHuffman bool) (string, []byte, error) {
	return readStringLiteral(buf, n, usesHuffman)
}

func (d *Decoder) at(i uint64) (hf HeaderField, ok bool) {
	return staticAt(i)
}
