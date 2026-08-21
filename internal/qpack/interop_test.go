package qpack_test

import (
	"bytes"
	"io"
	"testing"

	upstream "github.com/quic-go/qpack"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/qpack"
)

// The one oracle in this package that this repository did not write.
//
// internal/qpack is a fork, and the risk a fork carries is that its tests are
// written by the same hand as its code: a misreading of the wire format would
// be encoded twice and round-trip perfectly. github.com/quic-go/qpack is still
// a dependency of this module, so it can be imported here alongside the fork,
// and it is a QPACK implementation that has interoperated with others for
// years.
//
// It cannot check everything. Upstream has no dynamic table, which is the whole
// reason for the fork, so what it pins is the part they share: the static
// table, the literal representations, Huffman coding, the varint prefixes, and
// the header block prefix in the case where nothing is dynamic. That is most of
// the bytes on the wire even when the dynamic table is in use.
//
// What upstream cannot check is checked two other ways: dynamic_table_test.go
// tests the index arithmetic against its own definition, and dynamic_test.go
// round-trips whole exchanges through both halves of this package.
//
// RFC 9204's Appendix B carries worked examples with exact bytes, which would
// be better than any of this. They are not here because the RFC could not be
// fetched from the environment this was written in — see FORK.md.

var interopFields = []qpack.HeaderField{
	{Name: ":method", Value: "GET"},                         // static, name and value
	{Name: ":path", Value: "/index.html"},                   // static name, literal value
	{Name: ":authority", Value: "www.example.com"},          // static name, literal value
	{Name: "user-agent", Value: "Mozilla/5.0 (Windows NT)"}, // static name, long value
	{Name: "sec-ch-ua-platform", Value: "\"Windows\""},      // no static entry at all
	{Name: "accept-encoding", Value: "gzip, deflate, br"},   // static name, literal value
	{Name: "if-none-match", Value: ""},                      // empty value
	{Name: "x-custom", Value: "çöğüş"},                      // non-ASCII, exercises Huffman
}

func toUpstream(f qpack.HeaderField) upstream.HeaderField {
	return upstream.HeaderField{Name: f.Name, Value: f.Value}
}

// TestForkDecodesWhatUpstreamEncodes is the direction that matters most: it is
// the one a real server exercises when it does not use the dynamic table, which
// most servers do not.
func TestForkDecodesWhatUpstreamEncodes(t *testing.T) {
	var buf bytes.Buffer
	enc := upstream.NewEncoder(&buf)
	for _, f := range interopFields {
		if err := enc.WriteField(toUpstream(f)); err != nil {
			t.Fatalf("upstream encode %q: %v", f.Name, err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("upstream close: %v", err)
	}

	got := decodeAll(t, qpack.NewDecoder(), buf.Bytes())
	assertFields(t, got, interopFields)

	// And the same block through a decoder that does have a dynamic table. A
	// block that references nothing dynamic has to decode identically, or every
	// static-only server on the internet breaks the moment this client
	// advertises a table.
	withTable := qpack.NewDecoderWithDynamicTable(qpack.DecoderConfig{
		MaxTableCapacity: 4096,
		DecoderStream:    io.Discard,
	})
	assertFields(t, decodeAll(t, withTable, buf.Bytes()), interopFields)
}

// TestUpstreamDecodesWhatForkEncodes is the other direction, and it is what
// stops the fork's encoder from drifting into a private dialect. A server on
// upstream's decoder has to be able to read what this client writes.
func TestUpstreamDecodesWhatForkEncodes(t *testing.T) {
	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	for _, f := range interopFields {
		if err := enc.WriteField(f); err != nil {
			t.Fatalf("encode %q: %v", f.Name, err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	dec := upstream.NewDecoder()
	decode := dec.Decode(buf.Bytes())
	var got []qpack.HeaderField
	for {
		hf, err := decode()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("upstream decode: %v", err)
		}
		got = append(got, qpack.HeaderField{Name: hf.Name, Value: hf.Value})
	}
	assertFields(t, got, interopFields)
}

// TestForkAndUpstreamProduceTheSameBytes is stricter than either round trip and
// is the reason both are worth having.
//
// A fork whose encoder produced different but valid bytes would pass the two
// tests above and still be a different fingerprint on the wire, which for this
// repository is the failure that matters. The static-table path must not have
// moved at all.
func TestForkAndUpstreamProduceTheSameBytes(t *testing.T) {
	var ours, theirs bytes.Buffer

	oe := qpack.NewEncoder(&ours)
	ue := upstream.NewEncoder(&theirs)
	for _, f := range interopFields {
		if err := oe.WriteField(f); err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := ue.WriteField(toUpstream(f)); err != nil {
			t.Fatalf("upstream encode: %v", err)
		}
	}
	_ = oe.Close()
	_ = ue.Close()

	if !bytes.Equal(ours.Bytes(), theirs.Bytes()) {
		t.Errorf("the fork's encoder no longer agrees with upstream's byte for byte\n"+
			"  ours   %x\n  theirs %x", ours.Bytes(), theirs.Bytes())
	}
}

// TestStaticOnlyDecoderStillRefusesTheDynamicTable keeps upstream's behaviour
// where it is still the right one. NewDecoder has no table, and a peer that
// references one is talking to something else.
func TestStaticOnlyDecoderStillRefusesTheDynamicTable(t *testing.T) {
	// Required Insert Count 1, Base 0, then an indexed field line with T=0.
	block := []byte{0x01, 0x00, 0x80}
	decode := qpack.NewDecoder().Decode(block)
	if _, err := decode(); err == nil {
		t.Error("a static-only decoder accepted a dynamic table reference")
	}
}

func decodeAll(t *testing.T, d *qpack.Decoder, block []byte) []qpack.HeaderField {
	t.Helper()
	decode := d.Decode(block)
	var got []qpack.HeaderField
	for {
		hf, err := decode()
		if err == io.EOF {
			return got
		}
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		got = append(got, hf)
	}
}

func assertFields(t *testing.T, got, want []qpack.HeaderField) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("decoded %d fields, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d = %q: %q, want %q: %q",
				i, got[i].Name, got[i].Value, want[i].Name, want[i].Value)
		}
	}
}
