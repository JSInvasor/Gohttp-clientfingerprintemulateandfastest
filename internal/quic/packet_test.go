package quic

import (
	"bytes"
	"slices"
	"testing"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/ctls"
)

// The round trip.
//
// These build a first flight and then read it back with the decoder written
// against Chrome's own datagrams — the same Unprotect, ParseFrames, Assemble
// and ParseClientHello the capture tests use. Nothing here is a private path:
// if the builder and the reader agreed on something wrong, the reference values
// would still catch it, because those came from Chrome and were confirmed by a
// third party.

// buildFlight makes a complete Chrome-shaped first flight.
func buildFlight(t *testing.T) (datagrams [][]byte, dcid []byte) {
	t.Helper()

	tp, err := EncodeTransportParams(Chrome151QUIC, nil)
	if err != nil {
		t.Fatalf("encode transport parameters: %v", err)
	}
	hello, err := ctls.BuildChromeQUICClientHello(ctls.QUICHelloConfig{
		ServerName:      testServerName,
		ALPN:            Chrome151QUIC.ALPN,
		TransportParams: tp,
	})
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}
	datagrams, dcid, err = BuildInitialFlight(Chrome151QUIC, hello.Bytes)
	if err != nil {
		t.Fatalf("build flight: %v", err)
	}
	return datagrams, dcid
}

// readFlight decodes a flight the way the capture tests decode Chrome's.
func readFlight(t *testing.T, datagrams [][]byte, dcid []byte) ([]byte, *Frames) {
	t.Helper()

	frags := map[uint64][]byte{}
	total := &Frames{Crypto: frags}
	for i, dg := range datagrams {
		p, err := Unprotect(dg, dcid)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if p.Reserved != 0 {
			t.Errorf("datagram %d: reserved bits = %d, want 0", i, p.Reserved)
		}
		if got := p.PacketNum; got != uint64(i) {
			t.Errorf("datagram %d carries packet number %d", i, got)
		}
		f, err := ParseFrames(p.Payload)
		if err != nil {
			t.Fatalf("datagram %d frames: %v", i, err)
		}
		for off, d := range f.Crypto {
			frags[off] = d
		}
		total.Pings += f.Pings
		total.PadRuns += f.PadRuns
		total.CryptoLen += f.CryptoLen
		total.Types = append(total.Types, f.Types...)
		total.CryptoOrder = append(total.CryptoOrder, f.CryptoOrder...)
	}
	stream, err := Assemble(frags)
	if err != nil {
		t.Fatalf("assemble what we just built: %v", err)
	}
	return stream, total
}

func TestFlightRoundTripsToTheSameJA4(t *testing.T) {
	datagrams, dcid := buildFlight(t)
	stream, _ := readFlight(t, datagrams, dcid)

	ch, err := ParseClientHello(stream)
	if err != nil {
		t.Fatalf("parse the hello we sent: %v", err)
	}
	ja4, ja4r := ch.JA4()
	if ja4 != Chrome151QUIC.JA4 {
		t.Errorf("JA4 off the wire = %s\n         Chrome's = %s", ja4, Chrome151QUIC.JA4)
	}
	if ja4r != Chrome151QUIC.JA4R {
		t.Errorf("JA4_r off the wire = %s\n           Chrome's = %s", ja4r, Chrome151QUIC.JA4R)
	}
}

func TestFlightHeaderMatchesReference(t *testing.T) {
	ref := Chrome151QUIC
	datagrams, dcid := buildFlight(t)

	if len(datagrams) < 2 {
		t.Errorf("flight is %d datagram(s); Chrome's ClientHello needs two", len(datagrams))
	}
	for i, dg := range datagrams {
		if len(dg) != ref.DatagramSize {
			t.Errorf("datagram %d is %d bytes, want %d", i, len(dg), ref.DatagramSize)
		}
		h, err := ParseLongHeader(dg)
		if err != nil {
			t.Fatalf("datagram %d header: %v", i, err)
		}
		if h.Version != ref.ChosenVersion {
			t.Errorf("datagram %d version = 0x%08x, want 0x%08x", i, h.Version, ref.ChosenVersion)
		}
		if !bytes.Equal(h.DCID, dcid) {
			t.Errorf("datagram %d carries a different DCID than the flight's", i)
		}
		if len(h.DCID) != ref.DCIDLen {
			t.Errorf("datagram %d DCID is %d bytes, want %d", i, len(h.DCID), ref.DCIDLen)
		}
		if len(h.SCID) != ref.SCIDLen {
			t.Errorf("datagram %d SCID is %d bytes, want %d", i, len(h.SCID), ref.SCIDLen)
		}
		if len(h.Token) != ref.TokenLen {
			t.Errorf("datagram %d token is %d bytes, want %d", i, len(h.Token), ref.TokenLen)
		}
		if h.HeaderLen != InitialHeaderLen {
			t.Errorf("datagram %d header is %d bytes, want %d", i, h.HeaderLen, InitialHeaderLen)
		}
	}
}

// TestFlightHeaderMatchesChromesByteForByte compares the clear part of our
// first datagram against the clear part of Chrome's, field by field. Only the
// Connection ID itself may differ — it is random by definition.
func TestFlightHeaderMatchesChromesByteForByte(t *testing.T) {
	datagrams, _ := buildFlight(t)
	ours := datagrams[0]

	theirs := readCapture(t, capturePath)[0]

	// Everything before the DCID.
	if !bytes.Equal(ours[1:6], theirs[1:6]) {
		t.Errorf("version and DCID length differ:\n ours   %x\n Chrome %x", ours[1:6], theirs[1:6])
	}
	// Everything after it: SCID length, token length, packet length varint.
	n := Chrome151QUIC.DCIDLen
	if !bytes.Equal(ours[6+n:InitialHeaderLen], theirs[6+n:InitialHeaderLen]) {
		t.Errorf("SCID length, token length or packet length differ:\n ours   %x\n Chrome %x",
			ours[6+n:InitialHeaderLen], theirs[6+n:InitialHeaderLen])
	}
}

// TestFlightIsChaotic requires the flight to have the shape Chrome's does. A
// single tidy CRYPTO frame would round-trip perfectly and be wrong.
func TestFlightIsChaotic(t *testing.T) {
	datagrams, dcid := buildFlight(t)
	stream, frames := readFlight(t, datagrams, dcid)

	if n := len(frames.Crypto); n < 8 {
		t.Errorf("CRYPTO fragments = %d; Chrome's captures show 9 to 18", n)
	}
	if frames.Pings == 0 {
		t.Error("no PING frames: the chaos protector interleaves them")
	}
	if frames.PadRuns < 2 {
		t.Errorf("PADDING runs = %d; the captures show several per flight", frames.PadRuns)
	}
	if frames.CryptoLen != len(stream) {
		t.Errorf("fragments total %d bytes but the stream is %d: they overlap",
			frames.CryptoLen, len(stream))
	}

	// Out of order, not merely fragmented. With eight or more fragments the
	// chance of a shuffle landing on sorted order is under 1 in 40000, so a
	// single sorted flight is a bug rather than luck.
	if !frames.CryptoOutOfOrder() {
		t.Errorf("the %d CRYPTO fragments arrived in ascending offset order; "+
			"Chrome shuffles them", len(frames.CryptoOrder))
	}
}

// TestFlightSizesVary is the other half: the fragment sizes have to spread, not
// come out near-equal the way dividing a length by a count would give.
func TestFlightSizesVary(t *testing.T) {
	datagrams, dcid := buildFlight(t)
	_, frames := readFlight(t, datagrams, dcid)

	var sizes []int
	for _, d := range frames.Crypto {
		sizes = append(sizes, len(d))
	}
	slices.Sort(sizes)
	smallest, largest := sizes[0], sizes[len(sizes)-1]
	if largest < smallest*8 {
		t.Errorf("fragment sizes run %d..%d, too even; Chrome's captures span "+
			"1..824 and 4..822", smallest, largest)
	}
}

// TestFlightDiffersEveryTime is what the whole file is for. Two flights of the
// same ClientHello must not produce the same bytes, or the randomisation is
// decoration.
func TestFlightDiffersEveryTime(t *testing.T) {
	a, _ := buildFlight(t)
	b, _ := buildFlight(t)

	if len(a) == len(b) && bytes.Equal(a[0], b[0]) {
		t.Error("two flights produced identical first datagrams")
	}
}

// TestSplitHandshakeShuffles covers the exported half of the splitter — the one
// internal/quicgo calls, where a fragment's place in the slice is the order it
// goes on the wire rather than an accident of how it was cut.
func TestSplitHandshakeShuffles(t *testing.T) {
	const streamLen = 1758

	sorted := 0
	for i := 0; i < 20; i++ {
		frags, err := SplitHandshake(streamLen, 994)
		if err != nil {
			t.Fatalf("split: %v", err)
		}
		if len(frags) < defaultChaos.minFragments {
			t.Fatalf("split into %d fragments, minimum is %d",
				len(frags), defaultChaos.minFragments)
		}

		// Every byte exactly once: a fragment that overlapped another would
		// still reassemble, because the later copy overwrites the earlier one,
		// and a gap would hang the peer's handshake rather than fail it.
		covered := make([]bool, streamLen)
		for _, f := range frags {
			if f.Length < 1 {
				t.Fatalf("fragment at %d is %d bytes", f.Offset, f.Length)
			}
			for j := f.Offset; j < f.Offset+uint64(f.Length); j++ {
				if j >= uint64(streamLen) {
					t.Fatalf("fragment at %d runs %d bytes past the end", f.Offset, f.Length)
				}
				if covered[j] {
					t.Fatalf("byte %d is in two fragments", j)
				}
				covered[j] = true
			}
		}
		for j, ok := range covered {
			if !ok {
				t.Fatalf("byte %d is in no fragment", j)
			}
		}

		if slices.IsSortedFunc(frags, func(a, b Fragment) int {
			return int(a.Offset) - int(b.Offset)
		}) {
			sorted++
		}
	}
	if sorted > 1 {
		t.Errorf("%d of 20 splits came out in ascending offset order; the "+
			"fragments are supposed to be shuffled", sorted)
	}
}

// TestChaosPadRunsSpendEverything is the property the packer depends on: the
// runs have to add up to exactly the padding it was given, or the packet comes
// out the wrong length. That is a whole-flight failure rather than a fingerprint
// one, which is why it is checked here rather than left to the wire tests.
func TestChaosPadRunsSpendEverything(t *testing.T) {
	multiRun := 0
	for i := 0; i < 200; i++ {
		const total, gaps = 400, 12
		runs, err := ChaosPadRuns(total, gaps)
		if err != nil {
			t.Fatalf("pad runs: %v", err)
		}
		if len(runs) != gaps {
			t.Fatalf("got %d runs for %d gaps", len(runs), gaps)
		}
		sum, nonEmpty := 0, 0
		for j, r := range runs {
			if r < 0 {
				t.Fatalf("run %d is %d bytes", j, r)
			}
			if r > 0 {
				nonEmpty++
			}
			if j < gaps-1 && r > defaultChaos.maxPadRun {
				t.Errorf("interior run %d is %d bytes, over the %d cap",
					j, r, defaultChaos.maxPadRun)
			}
			sum += r
		}
		if sum != total {
			t.Fatalf("runs total %d bytes, want %d", sum, total)
		}
		if nonEmpty > 1 {
			multiRun++
		}
	}
	// Not every draw scatters — one gap in four carries padding, so all-tail is
	// a legitimate outcome. Never scattering is not.
	if multiRun < 100 {
		t.Errorf("only %d of 200 draws produced more than one run of padding; "+
			"Chrome's packets carry several", multiRun)
	}
}

// TestChaosPadRunsWithNothingToSpend covers the case the packer hits on a full
// packet: a payload with no room left to pad still has to come back with a run
// for every gap, all of them empty.
func TestChaosPadRunsWithNothingToSpend(t *testing.T) {
	runs, err := ChaosPadRuns(0, 5)
	if err != nil {
		t.Fatalf("pad runs: %v", err)
	}
	if len(runs) != 5 {
		t.Fatalf("got %d runs, want 5", len(runs))
	}
	for i, r := range runs {
		if r != 0 {
			t.Errorf("run %d is %d bytes with nothing to pad", i, r)
		}
	}
	if _, err := ChaosPadRuns(100, 0); err == nil {
		t.Error("padding into zero gaps was accepted; the bytes would vanish")
	}
}

// TestBuildInitialRejectsAWrongPayload guards the arithmetic that ties the
// payload size to the datagram size. Getting it wrong produces a packet that is
// the wrong length rather than one that fails to parse, which is the kind of
// mistake that survives a working handshake and shows up only as a fingerprint.
func TestBuildInitialRejectsAWrongPayload(t *testing.T) {
	dcid := make([]byte, Chrome151QUIC.DCIDLen)
	want := PayloadSizeFor(Chrome151QUIC, 1)

	if _, err := BuildInitial(Chrome151QUIC, dcid, 0, make([]byte, want)); err != nil {
		t.Fatalf("a correctly sized payload was rejected: %v", err)
	}
	for _, n := range []int{want - 1, want + 1} {
		if _, err := BuildInitial(Chrome151QUIC, dcid, 0, make([]byte, n)); err == nil {
			t.Errorf("a %d byte payload was accepted; only %d fits", n, want)
		}
	}
}

// TestPayloadSizeMatchesChromesPlaintext ties the arithmetic to a measurement
// rather than to arithmetic alone: Chrome's first captured Initial decrypts to
// exactly this many bytes.
func TestPayloadSizeMatchesChromesPlaintext(t *testing.T) {
	grams := readCapture(t, capturePath)
	h, err := ParseLongHeader(grams[0])
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	p, err := Unprotect(grams[0], h.DCID)
	if err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if got, want := len(p.Payload), PayloadSizeFor(Chrome151QUIC, p.PNLen); got != want {
		t.Errorf("Chrome's plaintext is %d bytes, our arithmetic says %d", got, want)
	}
}
