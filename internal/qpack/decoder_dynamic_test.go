package qpack

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// The decoder against a peer that uses the dynamic table.
//
// The header blocks here are built byte by byte rather than by this package's
// own encoder, and each byte is decomposed in a comment. That is deliberate:
// an encoder written from the same reading of the spec as the decoder would
// agree with it whatever the reading was, so the round trip proves consistency
// and not correctness. Writing the bytes out is at least a second look at the
// bit layouts, and the decomposition is there so a reader can check it without
// running anything.
//
// The instructions on the encoder stream do come from this package's own
// append* helpers, because those are what a peer's encoder stream will look
// like and because interop_test.go already pins the shared wire format against
// an implementation this repository did not write.

// recordingStream is the decoder stream, kept so the acknowledgements can be
// read back.
type recordingStream struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *recordingStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *recordingStream) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf.Bytes()...)
}

// peerEncoderStream builds what a peer's encoder would send to fill a table
// with two entries, at a capacity of 220 bytes.
func peerEncoderStream() []byte {
	var b []byte
	b = appendSetCapacity(b, 220)
	// :authority is static index 0; :path is static index 1.
	b = appendInsertWithNameReference(b, 0, true, "www.example.com") // absolute 0
	b = appendInsertWithNameReference(b, 1, true, "/sample/path")    // absolute 1
	return b
}

func newTestDecoder(stream *recordingStream) *Decoder {
	return NewDecoderWithDynamicTable(DecoderConfig{
		MaxTableCapacity:  4096,
		MaxBlockedStreams: 100,
		DecoderStream:     stream,
	})
}

func TestDecodesPostBaseReferences(t *testing.T) {
	stream := &recordingStream{}
	d := newTestDecoder(stream)

	if _, err := d.EncoderStream().Write(peerEncoderStream()); err != nil {
		t.Fatalf("encoder stream: %v", err)
	}

	// Required Insert Count 2 at a capacity of 220: maxEntries is 6, so the
	// encoded form is 2 mod 12 plus 1, which is 3.
	//
	//	0x03  Required Insert Count, encoded 3 -> 2
	//	0x81  1000 0001: S=1, Delta Base 1 -> Base = 2 - 1 - 1 = 0
	//	0x10  0001 0000: indexed field line, post-base index 0 -> absolute 0
	//	0x11  0001 0001: indexed field line, post-base index 1 -> absolute 1
	block := []byte{0x03, 0x81, 0x10, 0x11}

	got, err := d.DecodeForStream(context.Background(), 4, block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []HeaderField{
		{Name: ":authority", Value: "www.example.com"},
		{Name: ":path", Value: "/sample/path"},
	}
	if len(got) != len(want) {
		t.Fatalf("decoded %d fields, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d = %v, want %v", i, got[i], want[i])
		}
	}

	// Two things had to go back on the decoder stream: how far this decoder got
	// through the peer's insertions, and that the block on stream 4 is done
	// with the entries it referenced. Without the second the peer may never
	// evict them.
	acks := stream.bytes()
	if len(acks) != 2 {
		t.Fatalf("decoder stream carries %d bytes (%x), want an increment and an acknowledgement",
			len(acks), acks)
	}
	ins, rest, err := parseDecoderInstruction(acks)
	if err != nil {
		t.Fatalf("first acknowledgement: %v", err)
	}
	if ins.kind != insertCountIncrement || ins.value != 2 {
		t.Errorf("first instruction = kind %d value %d, want an insert count increment of 2",
			ins.kind, ins.value)
	}
	ins, _, err = parseDecoderInstruction(rest)
	if err != nil {
		t.Fatalf("second acknowledgement: %v", err)
	}
	if ins.kind != sectionAcknowledgement || ins.value != 4 {
		t.Errorf("second instruction = kind %d value %d, want a section acknowledgement for stream 4",
			ins.kind, ins.value)
	}
}

func TestDecodesRelativeReferencesAgainstBase(t *testing.T) {
	d := newTestDecoder(&recordingStream{})
	if _, err := d.EncoderStream().Write(peerEncoderStream()); err != nil {
		t.Fatalf("encoder stream: %v", err)
	}

	//	0x03  Required Insert Count 2
	//	0x00  0000 0000: S=0, Delta Base 0 -> Base = 2 + 0 = 2
	//	0x81  1000 0001: indexed, T=0 dynamic, relative 1 -> absolute 2-1-1 = 0
	//	0x80  1000 0000: indexed, T=0 dynamic, relative 0 -> absolute 2-1-0 = 1
	//	0xd1  1101 0001: indexed, T=1 static, index 17 -> :method GET
	block := []byte{0x03, 0x00, 0x81, 0x80, 0xd1}

	got, err := d.DecodeForStream(context.Background(), 0, block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []HeaderField{
		{Name: ":authority", Value: "www.example.com"},
		{Name: ":path", Value: "/sample/path"},
		{Name: ":method", Value: "GET"},
	}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("decoded %v, want %v", got, want)
		}
	}
}

func TestDecodesLiteralWithDynamicNameReference(t *testing.T) {
	d := newTestDecoder(&recordingStream{})
	if _, err := d.EncoderStream().Write(peerEncoderStream()); err != nil {
		t.Fatalf("encoder stream: %v", err)
	}

	//	0x03  Required Insert Count 2
	//	0x00  S=0, Delta Base 0 -> Base 2
	//	0x40  0100 0000: literal with name reference, N=0, T=0 dynamic,
	//	      index 0 -> absolute 2-1-0 = 1, the :path entry
	//	then the value as a literal string.
	block := append([]byte{0x03, 0x00, 0x40}, appendValueString(nil, "/other")...)

	got, err := d.DecodeForStream(context.Background(), 0, block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Name != ":path" || got[0].Value != "/other" {
		t.Errorf("decoded %v, want [:path /other]", got)
	}
}

func TestDecodesLiteralWithPostBaseNameReference(t *testing.T) {
	d := newTestDecoder(&recordingStream{})
	if _, err := d.EncoderStream().Write(peerEncoderStream()); err != nil {
		t.Fatalf("encoder stream: %v", err)
	}

	//	0x03  Required Insert Count 2
	//	0x81  S=1, Delta Base 1 -> Base 0
	//	0x01  0000 0001: literal with post-base name reference, N=0,
	//	      index 1 -> absolute 0+1 = 1, the :path entry
	block := append([]byte{0x03, 0x81, 0x01}, appendValueString(nil, "/post-base")...)

	got, err := d.DecodeForStream(context.Background(), 0, block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Name != ":path" || got[0].Value != "/post-base" {
		t.Errorf("decoded %v, want [:path /post-base]", got)
	}
}

func TestDuplicateInstructionReinsertsAnEntry(t *testing.T) {
	d := newTestDecoder(&recordingStream{})
	s := d.dyn
	if _, err := d.EncoderStream().Write(peerEncoderStream()); err != nil {
		t.Fatalf("encoder stream: %v", err)
	}
	// Duplicate relative index 1, which on the encoder stream counts back from
	// the newest: absolute 0, the :authority entry.
	if _, err := d.EncoderStream().Write(appendDuplicate(nil, 1)); err != nil {
		t.Fatalf("duplicate: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if got := s.table.insertCount(); got != 3 {
		t.Fatalf("insert count = %d after a duplicate, want 3", got)
	}
	hf, err := s.table.at(2)
	if err != nil {
		t.Fatalf("absolute 2: %v", err)
	}
	if hf.Name != ":authority" || hf.Value != "www.example.com" {
		t.Errorf("the duplicated entry is %v, want the :authority one", hf)
	}
}

// TestEncoderStreamSurvivesArbitraryChunking is the property a stream forces on
// this code and a byte slice does not.
//
// Instructions are self-delimiting but QUIC delivers whatever it has, so every
// instruction here can be split at every byte. A parser that treated a short
// read as a malformed instruction would work in every test that hands it a
// whole buffer and close connections in production at a packet boundary.
func TestEncoderStreamSurvivesArbitraryChunking(t *testing.T) {
	full := peerEncoderStream()
	full = append(full, appendInsertWithLiteralName(nil, "sec-ch-ua-platform", "\"Windows\"")...)

	reference := newTestDecoder(&recordingStream{})
	if _, err := reference.EncoderStream().Write(full); err != nil {
		t.Fatalf("whole stream: %v", err)
	}
	reference.dyn.mu.Lock()
	wantCount := reference.dyn.table.insertCount()
	reference.dyn.mu.Unlock()

	for split := 1; split < len(full); split++ {
		d := newTestDecoder(&recordingStream{})
		w := d.EncoderStream()
		if _, err := w.Write(full[:split]); err != nil {
			t.Fatalf("split at %d, first half: %v", split, err)
		}
		if _, err := w.Write(full[split:]); err != nil {
			t.Fatalf("split at %d, second half: %v", split, err)
		}
		d.dyn.mu.Lock()
		got := d.dyn.table.insertCount()
		last, err := d.dyn.table.at(got - 1)
		d.dyn.mu.Unlock()
		if err != nil {
			t.Fatalf("split at %d: %v", split, err)
		}
		if got != wantCount {
			t.Fatalf("split at %d: insert count %d, want %d", split, got, wantCount)
		}
		if last.Name != "sec-ch-ua-platform" {
			t.Fatalf("split at %d: newest entry is %q", split, last.Name)
		}
	}

	// And one byte at a time, which is the worst a stream can do.
	d := newTestDecoder(&recordingStream{})
	w := d.EncoderStream()
	for i := range full {
		if _, err := w.Write(full[i : i+1]); err != nil {
			t.Fatalf("byte %d: %v", i, err)
		}
	}
	d.dyn.mu.Lock()
	got := d.dyn.table.insertCount()
	d.dyn.mu.Unlock()
	if got != wantCount {
		t.Errorf("one byte at a time: insert count %d, want %d", got, wantCount)
	}
}

// TestDecodeForStreamWaitsForTheInsertion is what SETTINGS_QPACK_BLOCKED_STREAMS
// is a budget for. An encoder may reference an entry whose insertion is still
// in flight, because the two travel on different streams and QUIC does not
// order them against each other.
func TestDecodeForStreamWaitsForTheInsertion(t *testing.T) {
	d := newTestDecoder(&recordingStream{})
	block := []byte{0x03, 0x81, 0x10, 0x11} // needs 2 insertions

	// Nothing has been inserted, so the non-blocking path has to say so rather
	// than inventing a header field.
	decode := d.Decode(block)
	if _, err := decode(); !errors.Is(err, ErrBlocked) {
		t.Fatalf("Decode on a blocked block returned %v, want ErrBlocked", err)
	}

	done := make(chan []HeaderField, 1)
	errc := make(chan error, 1)
	go func() {
		fields, err := d.DecodeForStream(context.Background(), 4, block)
		if err != nil {
			errc <- err
			return
		}
		done <- fields
	}()

	select {
	case <-done:
		t.Fatal("the block decoded before its entries were inserted")
	case err := <-errc:
		t.Fatalf("decode: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if _, err := d.EncoderStream().Write(peerEncoderStream()); err != nil {
		t.Fatalf("encoder stream: %v", err)
	}

	select {
	case fields := <-done:
		if len(fields) != 2 {
			t.Errorf("decoded %d fields, want 2", len(fields))
		}
	case err := <-errc:
		t.Fatalf("decode: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the block never unblocked after its entries arrived")
	}
}

func TestBlockedDecodeRespectsItsContext(t *testing.T) {
	d := newTestDecoder(&recordingStream{})
	ctx, cancel := context.WithCancel(context.Background())

	errc := make(chan error, 1)
	go func() {
		_, err := d.DecodeForStream(ctx, 4, []byte{0x03, 0x81, 0x10, 0x11})
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("blocked decode returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled context did not release a blocked decode")
	}
}

// TestPeerCannotExceedTheAdvertisedCapacity guards the promise in the other
// direction. This endpoint said 4096 in SETTINGS; a peer that sets more has
// lost track, and every index it sends afterwards is against a table this
// endpoint does not have.
func TestPeerCannotExceedTheAdvertisedCapacity(t *testing.T) {
	d := NewDecoderWithDynamicTable(DecoderConfig{MaxTableCapacity: 4096, DecoderStream: &recordingStream{}})
	_, err := d.EncoderStream().Write(appendSetCapacity(nil, 4097))
	if err == nil {
		t.Fatal("a peer set a table capacity over the advertised maximum")
	}
	if !strings.Contains(err.Error(), "4097") {
		t.Errorf("error does not name the offending capacity: %v", err)
	}
}

// TestNoTableMeansNoEncoderStream is the coherent refusal. A decoder that never
// advertised a table has nothing an insertion could mean, and a peer opening
// that stream believes something untrue about this endpoint.
func TestNoTableMeansNoEncoderStream(t *testing.T) {
	if _, err := NewDecoder().EncoderStream().Write([]byte{0x00}); err == nil {
		t.Error("a decoder with no dynamic table accepted an encoder stream")
	}
}

// TestABlockThatUsesNoDynamicEntriesIsNotAcknowledged keeps the acknowledgement
// honest. RFC 9204 section 4.4.1 ties a Section Acknowledgment to a block that
// referenced the dynamic table; sending one for a block that did not would move
// the peer's idea of what this decoder has processed.
func TestABlockThatUsesNoDynamicEntriesIsNotAcknowledged(t *testing.T) {
	stream := &recordingStream{}
	d := newTestDecoder(stream)

	// 0x00 0x00 is Required Insert Count 0 and Base 0; 0xd1 is :method GET.
	if _, err := d.DecodeForStream(context.Background(), 4, []byte{0x00, 0x00, 0xd1}); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if acks := stream.bytes(); len(acks) != 0 {
		t.Errorf("decoder stream carries %x after a block that referenced nothing dynamic", acks)
	}
}
