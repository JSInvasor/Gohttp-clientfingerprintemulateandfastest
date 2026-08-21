package qpack_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	upstream "github.com/quic-go/qpack"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/qpack"
)

// chromeRequestHeaders is the field list a Chrome fetch produces, in Chrome's
// order — see internal/quic/http3.go, which pins that order from a server that
// reported what it received.
//
// It is used here rather than a synthetic list because the thing being measured
// is how well a real request compresses, and because header order is part of
// the profile: an encoder that reordered fields would pass a round trip and
// still be wrong for this repository's purposes.
var chromeRequestHeaders = []qpack.HeaderField{
	{Name: ":method", Value: "GET"},
	{Name: ":authority", Value: "example.com"},
	{Name: ":scheme", Value: "https"},
	{Name: ":path", Value: "/api/v1/resource"},
	{Name: "sec-ch-ua-platform", Value: `"Windows"`},
	{Name: "user-agent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/151.0.0.0"},
	{Name: "sec-ch-ua", Value: `"Chromium";v="151", "Not?A_Brand";v="24"`},
	{Name: "sec-ch-ua-mobile", Value: "?0"},
	{Name: "accept", Value: "*/*"},
	{Name: "origin", Value: "https://example.com"},
	{Name: "sec-fetch-site", Value: "same-origin"},
	{Name: "sec-fetch-mode", Value: "cors"},
	{Name: "sec-fetch-dest", Value: "empty"},
	{Name: "accept-encoding", Value: "gzip, deflate, br, zstd"},
	{Name: "accept-language", Value: "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"},
	{Name: "priority", Value: "u=1, i"},
}

// connection wires an encoder on one side to a decoder on the other, the way a
// QUIC connection wires the two unidirectional QPACK streams.
//
// The streams are connected directly rather than buffered, so an insertion has
// arrived by the time the header block that references it is decoded. That is
// the ordering a real connection does not guarantee, which is what blocking is
// for and what decoder_dynamic_test.go covers separately.
type connection struct {
	enc *qpack.EncoderTable
	dec *qpack.Decoder

	encoderStream *countingWriter
	decoderStream *countingWriter
}

type countingWriter struct {
	mu    sync.Mutex
	to    io.Writer
	bytes int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.bytes += len(p)
	w.mu.Unlock()
	return w.to.Write(p)
}

func (w *countingWriter) written() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bytes
}

func newConnection(capacity, blocked uint64) *connection {
	c := &connection{}
	c.decoderStream = &countingWriter{}
	c.dec = qpack.NewDecoderWithDynamicTable(qpack.DecoderConfig{
		MaxTableCapacity:  capacity,
		MaxBlockedStreams: blocked,
		DecoderStream:     c.decoderStream,
	})
	c.encoderStream = &countingWriter{to: c.dec.EncoderStream()}
	c.enc = qpack.NewEncoderTable(c.encoderStream, capacity, blocked)
	c.decoderStream.to = c.enc.DecoderStream()
	return c
}

// testCtx bounds every decode in these tests.
//
// DecodeForStream waits for insertions that a header block says are coming, and
// nothing but the context stops that wait — which is correct, because a peer
// that referenced an entry has promised to insert it and only the connection
// knows when to give up. In a test it means a regression that breaks table
// synchronisation hangs instead of failing, which is how the first deliberate
// break of the eviction rule presented: eighty seconds and a timeout, rather
// than a line saying what went wrong.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func (c *connection) roundTrip(t *testing.T, streamID uint64, fields []qpack.HeaderField) []byte {
	t.Helper()
	block, err := c.enc.EncodeHeaderBlock(streamID, fields)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := c.dec.DecodeForStream(testCtx(t), streamID, block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != len(fields) {
		t.Fatalf("decoded %d fields, want %d:\n got  %v\n want %v", len(got), len(fields), got, fields)
	}
	for i := range fields {
		if got[i] != fields[i] {
			t.Fatalf("field %d = %v, want %v (order and content both matter)", i, got[i], fields[i])
		}
	}
	return block
}

// TestStaticOnlyBlocksMatchUpstream keeps the two encoders in this package
// honest against each other and against upstream.
//
// EncodeHeaderBlock is a second encoder beside the one in encoder.go, written
// so that encoder.go could stay byte-identical to upstream. Two encoders is a
// liability unless they agree, so this pins the case where they must: with no
// dynamic table, the whole-block path has to produce exactly what upstream's
// field-at-a-time path does.
func TestStaticOnlyBlocksMatchUpstream(t *testing.T) {
	table := qpack.NewEncoderTable(nil, 0, 0)
	got, err := table.EncodeHeaderBlock(0, chromeRequestHeaders)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var want bytes.Buffer
	enc := upstream.NewEncoder(&want)
	for _, f := range chromeRequestHeaders {
		if err := enc.WriteField(upstream.HeaderField{Name: f.Name, Value: f.Value}); err != nil {
			t.Fatalf("upstream encode: %v", err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("upstream close: %v", err)
	}

	if !bytes.Equal(got, want.Bytes()) {
		t.Errorf("the whole-block encoder disagrees with upstream on a static-only block\n"+
			"  ours     %x\n  upstream %x", got, want.Bytes())
	}
}

// TestEncoderAndDecoderAgreeOverAConnection is the loop: this package's encoder
// on one side, this package's decoder on the other, and the two QPACK streams
// between them.
//
// It cannot prove either side reads the wire format the way another
// implementation does — interop_test.go is what covers that, as far as
// upstream's static-only support reaches. What it does prove is that the
// dynamic table stays synchronised across many requests, which is the part with
// state in it and therefore the part that goes wrong late.
func TestEncoderAndDecoderAgreeOverAConnection(t *testing.T) {
	c := newConnection(4096, 100)
	for i := uint64(0); i < 40; i++ {
		fields := append([]qpack.HeaderField(nil), chromeRequestHeaders...)
		// A changing path and a changing value on a repeated name, which is the
		// pattern that exercises insertion, lookup and eventually eviction.
		fields[3] = qpack.HeaderField{Name: ":path", Value: pathFor(i)}
		c.roundTrip(t, i*4, fields)
	}
}

func pathFor(i uint64) string {
	return "/api/v1/resource/" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
}

// TestTheSecondRequestCostsAlmostNothing is what the dynamic table is for.
//
// The measurement is the whole cost on the wire — the header block plus the
// insertions on the encoder stream — and not the block alone. The first version
// of this test compared block sizes and failed at once, for a reason worth
// keeping: this encoder inserts while encoding the first block and then
// references what it inserted by post-base index, so the very first request is
// already sixteen indices and two bytes of prefix. The compression is real but
// it is not in the block, it is in the block plus what paid for it.
func TestTheSecondRequestCostsAlmostNothing(t *testing.T) {
	c := newConnection(4096, 100)

	before := c.encoderStream.written()
	firstBlock := c.roundTrip(t, 0, chromeRequestHeaders)
	firstStream := c.encoderStream.written() - before
	first := len(firstBlock) + firstStream

	before = c.encoderStream.written()
	secondBlock := c.roundTrip(t, 4, chromeRequestHeaders)
	secondStream := c.encoderStream.written() - before
	second := len(secondBlock) + secondStream

	if firstStream == 0 {
		t.Fatal("the first request inserted nothing; the dynamic table is not being used")
	}
	if secondStream != 0 {
		t.Errorf("the second identical request inserted %d more bytes; "+
			"everything it needs is already in the table", secondStream)
	}
	// A repeat of the same headers should be almost entirely indices. A tenth
	// is a loose bound on purpose: the exact ratio depends on the header values,
	// and pinning it would make this a change detector rather than a check.
	if second > first/10 {
		t.Errorf("the second request cost %d bytes (%d block, %d stream) against "+
			"the first's %d (%d block, %d stream)",
			second, len(secondBlock), secondStream, first, len(firstBlock), firstStream)
	}
}

// TestEncoderStreamIsNotSilent is the fingerprint claim, stated as a test.
//
// Chrome advertises a 64 KiB dynamic table and uses it. A client that
// advertised the same and left its encoder stream empty would be distinguishable
// at the QPACK layer, behind everything else this repository matches, and would
// look like exactly what it is: a stack that copied the settings without the
// behaviour.
func TestEncoderStreamIsNotSilent(t *testing.T) {
	c := newConnection(65536, 100)
	c.roundTrip(t, 0, chromeRequestHeaders)

	if c.encoderStream.written() == 0 {
		t.Fatal("nothing was written to the encoder stream")
	}
	if c.decoderStream.written() == 0 {
		t.Error("nothing came back on the decoder stream; the peer can never evict")
	}
}

// TestNoStreamMeansNoInsertions is the other side of it. An endpoint whose peer
// advertised no table has nowhere to put insertions, and must not invent one.
func TestNoStreamMeansNoInsertions(t *testing.T) {
	var stream bytes.Buffer
	table := qpack.NewEncoderTable(&stream, 0, 0)
	if _, err := table.EncodeHeaderBlock(0, chromeRequestHeaders); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if stream.Len() != 0 {
		t.Errorf("the encoder stream carries %d bytes against a peer that advertised no table",
			stream.Len())
	}
}

// TestEvictionWaitsForAcknowledgement is the rule that makes the table safe.
//
// An entry referenced by a header block the peer has not acknowledged may not
// be evicted, or the peer resolves an index against something that is gone. The
// encoder is never obliged to use the table, so the correct response to "this
// would evict something still in use" is a literal, and the connection carries
// on. This runs a table small enough that the rule binds constantly and checks
// that everything still decodes.
func TestEvictionWaitsForAcknowledgement(t *testing.T) {
	// Room for about three entries, against sixteen header fields.
	c := newConnectionWithoutAcks(200, 100)

	for i := uint64(0); i < 10; i++ {
		fields := append([]qpack.HeaderField(nil), chromeRequestHeaders...)
		fields[3] = qpack.HeaderField{Name: ":path", Value: pathFor(i)}

		block, err := c.enc.EncodeHeaderBlock(i*4, fields)
		if err != nil {
			t.Fatalf("request %d: encode: %v", i, err)
		}
		got, err := c.dec.DecodeForStream(testCtx(t), i*4, block)
		if err != nil {
			t.Fatalf("request %d: decode: %v", i, err)
		}
		for j := range fields {
			if j >= len(got) || got[j] != fields[j] {
				t.Fatalf("request %d field %d: got %v, want %v", i, j, got, fields)
			}
		}
	}
}

// newConnectionWithoutAcks is a connection whose decoder-stream traffic is
// dropped, so no section is ever acknowledged and the eviction floor never
// moves. It is the worst case the rule above has to survive.
func newConnectionWithoutAcks(capacity, blocked uint64) *connection {
	c := &connection{}
	c.decoderStream = &countingWriter{to: io.Discard}
	c.dec = qpack.NewDecoderWithDynamicTable(qpack.DecoderConfig{
		MaxTableCapacity:  capacity,
		MaxBlockedStreams: blocked,
		DecoderStream:     c.decoderStream,
	})
	c.encoderStream = &countingWriter{to: c.dec.EncoderStream()}
	c.enc = qpack.NewEncoderTable(c.encoderStream, capacity, blocked)
	return c
}

// TestEntriesSurviveUntilTheirBlockIsDecoded is the rule the rest of this file
// could not reach, and getting here took two deliberate breaks rather than one.
//
// The rule is that an entry referenced by a header block the peer has not
// acknowledged may not be evicted. Every other test decodes each block as soon
// as it is encoded, so a section is finished before the next begins and the rule
// never binds; deleting it failed nothing.
//
// Deferring the decoding was not enough either, and the reason is worth
// recording. With repeating header names, each new block looks up the entries
// the last one inserted, which protects them for the duration of that block —
// so the table filled once and then nothing was ever evicted, with or without
// the rule. The protection that was doing the work was the current block's, not
// the outstanding sections'.
//
// So the names here are disjoint between requests. Nothing a later block sends
// is in the table, every one of them wants to insert, and the only thing
// standing between them and the entries the first block referenced is the rule
// under test. What a correct encoder does then is decline to insert and spell
// the fields out, which costs bytes and keeps every outstanding block readable.
func TestEntriesSurviveUntilTheirBlockIsDecoded(t *testing.T) {
	// Small enough that one request's fields fill it.
	c := newConnectionWithoutAcks(220, 100)

	const requests = 20
	var blocks [][]byte
	var lists [][]qpack.HeaderField

	for i := uint64(0); i < requests; i++ {
		fields := []qpack.HeaderField{
			{Name: fmt.Sprintf("x-alpha-%d", i), Value: strings.Repeat("a", 20)},
			{Name: fmt.Sprintf("x-beta-%d", i), Value: strings.Repeat("b", 20)},
			{Name: fmt.Sprintf("x-gamma-%d", i), Value: strings.Repeat("c", 20)},
			{Name: fmt.Sprintf("x-delta-%d", i), Value: strings.Repeat("d", 20)},
		}
		block, err := c.enc.EncodeHeaderBlock(i*4, fields)
		if err != nil {
			t.Fatalf("request %d: encode: %v", i, err)
		}
		blocks = append(blocks, block)
		lists = append(lists, fields)
	}

	// Now decode them all, oldest first. Every one has to still resolve.
	for i, block := range blocks {
		got, err := c.dec.DecodeForStream(testCtx(t), uint64(i)*4, block)
		if err != nil {
			t.Fatalf("request %d decoded %d requests later: %v", i, requests-i, err)
		}
		for j := range lists[i] {
			if j >= len(got) || got[j] != lists[i][j] {
				t.Fatalf("request %d field %d: got %v, want %v", i, j, got, lists[i])
			}
		}
	}
}

// TestTablesStayInStepUnderChurn is the one that would catch a state bug the
// tidy tests miss.
//
// Everything else here runs a fixed script. This runs a few thousand requests
// with values that change, table sizes that force constant eviction, and
// acknowledgements that arrive for some streams and never for others — which is
// what a real connection looks like when requests are cancelled. Any drift
// between the two tables shows up as a header field that decodes to the wrong
// value or to nothing at all, and it shows up hundreds of requests after the
// mistake, which is exactly why a scripted test would not find it.
func TestTablesStayInStepUnderChurn(t *testing.T) {
	for _, capacity := range []uint64{128, 512, 4096} {
		for _, blocked := range []uint64{0, 8, 100} {
			c := newConnection(capacity, blocked)
			rnd := rand.New(rand.NewPCG(uint64(capacity), blocked))

			for i := uint64(0); i < 400; i++ {
				fields := []qpack.HeaderField{
					{Name: ":method", Value: "GET"},
					{Name: ":scheme", Value: "https"},
					{Name: ":authority", Value: hostFor(rnd.IntN(6))},
					{Name: ":path", Value: pathFor(uint64(rnd.IntN(50)))},
					{Name: "cookie", Value: strings.Repeat("c", 1+rnd.IntN(40))},
					{Name: "x-request-id", Value: pathFor(i)},
					{Name: "accept", Value: "*/*"},
				}
				rnd.Shuffle(len(fields), func(a, b int) { fields[a], fields[b] = fields[b], fields[a] })

				streamID := i * 4
				block, err := c.enc.EncodeHeaderBlock(streamID, fields)
				if err != nil {
					t.Fatalf("capacity %d blocked %d request %d: encode: %v",
						capacity, blocked, i, err)
				}
				got, err := c.dec.DecodeForStream(testCtx(t), streamID, block)
				if err != nil {
					t.Fatalf("capacity %d blocked %d request %d: decode: %v",
						capacity, blocked, i, err)
				}
				if len(got) != len(fields) {
					t.Fatalf("capacity %d blocked %d request %d: %d fields, want %d",
						capacity, blocked, i, len(got), len(fields))
				}
				for j := range fields {
					if got[j] != fields[j] {
						t.Fatalf("capacity %d blocked %d request %d field %d: %v, want %v",
							capacity, blocked, i, j, got[j], fields[j])
					}
				}

				// One request in five is abandoned rather than acknowledged,
				// which is what a cancelled fetch does. The entries it held
				// have to be released, or the encoder's table slowly fills with
				// things it may not evict and may not reuse.
				if rnd.IntN(5) == 0 {
					c.enc.CancelStream(streamID)
				}
			}
		}
	}
}

func hostFor(i int) string {
	return string(rune('a'+i)) + ".example.com"
}

// TestBlockedStreamBudgetIsRespected checks the encoder declines to reference
// unacknowledged entries once the peer's budget is used up.
//
// With a budget of zero, nothing may be referenced before it is acknowledged,
// which for a connection whose acknowledgements are dropped means nothing may
// ever be referenced. The blocks must still decode, and the decoder must never
// have to wait — the point of the budget is that a peer can bound how many
// streams it might have to hold.
func TestBlockedStreamBudgetIsRespected(t *testing.T) {
	c := newConnectionWithoutAcks(4096, 0)
	for i := uint64(0); i < 5; i++ {
		block, err := c.enc.EncodeHeaderBlock(i*4, chromeRequestHeaders)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		// Required Insert Count zero means the block references nothing
		// dynamic, so a decoder can read it whatever state its table is in.
		if block[0] != 0 {
			t.Fatalf("request %d referenced the dynamic table with a blocked-stream budget of zero", i)
		}
		if _, err := c.dec.DecodeForStream(testCtx(t), i*4, block); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
}
