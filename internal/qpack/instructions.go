package qpack

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/http2/hpack"
)

// FORK DELTA. Not present upstream.
//
// The two unidirectional streams QPACK runs alongside the request streams, and
// the instructions that travel on them (RFC 9204 sections 4.3 and 4.4).
//
// Upstream needs neither. Without a dynamic table there is nothing to insert
// and nothing to acknowledge, so its encoder and decoder are pure functions of
// one header block and the connection has no QPACK state at all. With a dynamic
// table both sides are stateful, and the state is kept in sync by these two
// streams:
//
//	encoder stream  →  what I inserted, so you can resolve my references
//	decoder stream  ←  what I have processed, so you know what you may evict
//
// The instructions are self-delimiting but a stream delivers them in arbitrary
// chunks, so everything here reports "not enough bytes yet" separately from
// "these bytes are wrong". Treating the first as the second would close a
// working connection at a packet boundary, which is the kind of bug that only
// shows up under load.

// errNeedMore means the buffer holds the start of a valid instruction but not
// all of it. It never reaches a caller outside this package.
var errNeedMore = errors.New("qpack: incomplete instruction")

// Encoder stream instructions, by their leading bits (RFC 9204 section 4.3).
const (
	// insertWithNameRef is 1Txxxxxx. T selects the static table.
	insertWithNameRefMask = 0x80
	insertNameRefStatic   = 0x40
	// insertWithLiteralName is 01Hxxxxx. H says the name is Huffman coded.
	insertWithLiteralNameMask  = 0xc0
	insertWithLiteralNameValue = 0x40
	insertLiteralNameHuffman   = 0x20
	// setCapacity is 001xxxxx.
	setCapacityMask  = 0xe0
	setCapacityValue = 0x20
	// duplicate is 000xxxxx.
	duplicateMask  = 0xe0
	duplicateValue = 0x00
)

// Decoder stream instructions, by their leading bits (RFC 9204 section 4.4).
const (
	sectionAckMask   = 0x80
	sectionAckValue  = 0x80
	streamCancelMask = 0xc0
	streamCancelVal  = 0x40
	insertCountMask  = 0xc0
	insertCountVal   = 0x00
)

// encoderInstruction is one decoded instruction from the peer's encoder stream.
type encoderInstruction struct {
	kind encoderInstructionKind

	// capacity, for setDynamicTableCapacity.
	capacity uint64
	// index, for insertWithNameReference and duplicate. For an insert it is a
	// static index when static is true and an encoder-stream relative index
	// otherwise; for a duplicate it is always relative.
	index  uint64
	static bool
	// name is set only when the instruction carried a literal one.
	name  string
	value string
}

type encoderInstructionKind int

const (
	insertNameReference encoderInstructionKind = iota
	insertLiteralName
	setDynamicTableCapacity
	duplicateEntry
)

// parseEncoderInstruction reads one instruction from the front of buf.
//
// It returns errNeedMore if buf holds only part of one, in which case the
// caller keeps the bytes and tries again with more.
func parseEncoderInstruction(buf []byte) (encoderInstruction, []byte, error) {
	if len(buf) == 0 {
		return encoderInstruction{}, buf, errNeedMore
	}
	b := buf[0]
	switch {
	case b&insertWithNameRefMask != 0:
		ins := encoderInstruction{
			kind:   insertNameReference,
			static: b&insertNameRefStatic != 0,
		}
		idx, rest, err := readVarIntNeedingMore(6, buf)
		if err != nil {
			return ins, buf, err
		}
		ins.index = idx
		val, rest, err := readValueString(rest)
		if err != nil {
			return ins, buf, err
		}
		ins.value = val
		return ins, rest, nil

	case b&insertWithLiteralNameMask == insertWithLiteralNameValue:
		ins := encoderInstruction{kind: insertLiteralName}
		name, rest, err := readInstructionString(buf, 5, b&insertLiteralNameHuffman != 0)
		if err != nil {
			return ins, buf, err
		}
		ins.name = name
		val, rest, err := readValueString(rest)
		if err != nil {
			return ins, buf, err
		}
		ins.value = val
		return ins, rest, nil

	case b&setCapacityMask == setCapacityValue:
		c, rest, err := readVarIntNeedingMore(5, buf)
		if err != nil {
			return encoderInstruction{}, buf, err
		}
		return encoderInstruction{kind: setDynamicTableCapacity, capacity: c}, rest, nil

	case b&duplicateMask == duplicateValue:
		idx, rest, err := readVarIntNeedingMore(5, buf)
		if err != nil {
			return encoderInstruction{}, buf, err
		}
		return encoderInstruction{kind: duplicateEntry, index: idx}, rest, nil
	}
	// Unreachable: the four cases above partition the first byte. Kept so that
	// a change to the masks fails loudly rather than falling through.
	return encoderInstruction{}, buf, fmt.Errorf("qpack: unrecognised encoder instruction %#x", b)
}

// appendSetCapacity writes a Set Dynamic Table Capacity instruction.
func appendSetCapacity(b []byte, capacity uint64) []byte {
	off := len(b)
	b = appendVarInt(b, 5, capacity)
	b[off] |= setCapacityValue
	return b
}

// appendInsertWithNameReference writes an insert that names its field by index.
func appendInsertWithNameReference(b []byte, index uint64, static bool, value string) []byte {
	off := len(b)
	b = appendVarInt(b, 6, index)
	b[off] |= insertWithNameRefMask
	if static {
		b[off] |= insertNameRefStatic
	}
	return appendValueString(b, value)
}

// appendInsertWithLiteralName writes an insert that spells its name out.
func appendInsertWithLiteralName(b []byte, name, value string) []byte {
	off := len(b)
	b = appendVarInt(b, 5, hpack.HuffmanEncodeLength(name))
	b[off] |= insertWithLiteralNameValue | insertLiteralNameHuffman
	b = hpack.AppendHuffmanString(b, name)
	return appendValueString(b, value)
}

// appendDuplicate writes a Duplicate instruction, which re-inserts an entry the
// table already holds so that it stops being the oldest and stops being next to
// be evicted.
func appendDuplicate(b []byte, relativeIndex uint64) []byte {
	off := len(b)
	b = appendVarInt(b, 5, relativeIndex)
	b[off] |= duplicateValue
	return b
}

// decoderInstruction is one decoded instruction from the peer's decoder stream.
type decoderInstruction struct {
	kind decoderInstructionKind
	// streamID for an acknowledgement or a cancellation, increment otherwise.
	value uint64
}

type decoderInstructionKind int

const (
	sectionAcknowledgement decoderInstructionKind = iota
	streamCancellation
	insertCountIncrement
)

func parseDecoderInstruction(buf []byte) (decoderInstruction, []byte, error) {
	if len(buf) == 0 {
		return decoderInstruction{}, buf, errNeedMore
	}
	b := buf[0]
	switch {
	case b&sectionAckMask == sectionAckValue:
		v, rest, err := readVarIntNeedingMore(7, buf)
		if err != nil {
			return decoderInstruction{}, buf, err
		}
		return decoderInstruction{kind: sectionAcknowledgement, value: v}, rest, nil
	case b&streamCancelMask == streamCancelVal:
		v, rest, err := readVarIntNeedingMore(6, buf)
		if err != nil {
			return decoderInstruction{}, buf, err
		}
		return decoderInstruction{kind: streamCancellation, value: v}, rest, nil
	case b&insertCountMask == insertCountVal:
		v, rest, err := readVarIntNeedingMore(6, buf)
		if err != nil {
			return decoderInstruction{}, buf, err
		}
		return decoderInstruction{kind: insertCountIncrement, value: v}, rest, nil
	}
	return decoderInstruction{}, buf, fmt.Errorf("qpack: unrecognised decoder instruction %#x", b)
}

func appendSectionAcknowledgement(b []byte, streamID uint64) []byte {
	off := len(b)
	b = appendVarInt(b, 7, streamID)
	b[off] |= sectionAckValue
	return b
}

func appendStreamCancellation(b []byte, streamID uint64) []byte {
	off := len(b)
	b = appendVarInt(b, 6, streamID)
	b[off] |= streamCancelVal
	return b
}

func appendInsertCountIncrement(b []byte, increment uint64) []byte {
	off := len(b)
	b = appendVarInt(b, 6, increment)
	b[off] |= insertCountVal
	return b
}

// appendValueString writes a value in the Hxxxxxxx form the instructions and
// the field line representations share.
func appendValueString(b []byte, value string) []byte {
	off := len(b)
	b = appendVarInt(b, 7, hpack.HuffmanEncodeLength(value))
	b[off] |= 0x80
	return hpack.AppendHuffmanString(b, value)
}

// readInstructionString is readStringLiteral with truncation renamed. On a
// stream, running out of bytes means the rest has not arrived; inside a header
// block, which arrives whole, it means the block is malformed. Same bytes, two
// different things to do about it.
func readInstructionString(buf []byte, n uint8, usesHuffman bool) (string, []byte, error) {
	s, rest, err := readStringLiteral(buf, n, usesHuffman)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "", buf, errNeedMore
	}
	return s, rest, err
}

func readValueString(buf []byte) (string, []byte, error) {
	if len(buf) == 0 {
		return "", buf, errNeedMore
	}
	return readInstructionString(buf, 7, buf[0]&0x80 != 0)
}

// readVarIntNeedingMore is readVarInt with the truncation case named, so that a
// stream that has not delivered the rest of an instruction is not mistaken for
// a peer that sent a broken one.
func readVarIntNeedingMore(n byte, p []byte) (uint64, []byte, error) {
	i, rest, err := readVarInt(n, p)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return 0, p, errNeedMore
	}
	return i, rest, err
}

// readStringLiteral reads a length-prefixed, optionally Huffman coded string.
//
// This is upstream's Decoder.readString, lifted to a function because the
// instructions above need it and are not decoding a header block. decoder.go's
// method now calls it, so there is one copy and it keeps upstream's error
// behaviour exactly: io.ErrUnexpectedEOF when the bytes run out.
func readStringLiteral(buf []byte, n uint8, usesHuffman bool) (string, []byte, error) {
	l, buf, err := readVarInt(n, buf)
	if err != nil {
		return "", nil, err
	}
	if uint64(len(buf)) < l {
		return "", nil, io.ErrUnexpectedEOF
	}
	var val string
	if usesHuffman {
		val, err = hpack.HuffmanDecodeToString(buf[:l])
		if err != nil {
			return "", nil, err
		}
	} else {
		val = string(buf[:l])
	}
	return val, buf[l:], nil
}
