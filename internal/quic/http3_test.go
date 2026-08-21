package quic

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// browserleaksJA4 is the QUIC JA4 that https://quic.browserleaks.com/ computed
// for Chrome 151.0.7922.77 on Windows 10 on 2026-08-21, from the connection it
// received rather than from anything in this repository.
//
// It is written out here as a literal on purpose. Everything else in this
// package traces back to one capture and one decoder, so a bug in the decoder
// would be invisible: reference.go would agree with the tests and both would be
// wrong together. This string was produced by someone else's implementation
// reading someone else's copy of the bytes, and it is the only value in the
// package that can contradict the rest.
const browserleaksJA4 = "q13d0313h3_55b375c5d22e_226f3f127bbe"

// TestJA4AgreesWithAnIndependentImplementation closes the loop between three
// paths to the same string: a third-party server's computation, the value
// pinned in reference.go, and what this package's own decoder derives from the
// raw Initial bytes under testdata.
func TestJA4AgreesWithAnIndependentImplementation(t *testing.T) {
	if Chrome151QUICResumed.JA4 != browserleaksJA4 {
		t.Errorf("reference disagrees with the independent capture:\n"+
			" reference   %s\n browserleaks %s",
			Chrome151QUICResumed.JA4, browserleaksJA4)
	}

	_, stream, _ := decodeCapture(t, "testdata/chrome151-google-resumed.txt")
	ch, err := ParseClientHello(stream)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}
	ja4, _ := ch.JA4()
	if ja4 != browserleaksJA4 {
		t.Errorf("this package's decoder disagrees with the independent capture:\n"+
			" decoded      %s\n browserleaks %s", ja4, browserleaksJA4)
	}
}

// TestH3FingerprintMatchesSettings rebuilds the settings half of the HTTP/3
// fingerprint string from the pinned Settings slice. The two are written down
// separately, so this is what stops them drifting apart — a setting added to
// one and not the other is a silent disagreement otherwise.
func TestH3FingerprintMatchesSettings(t *testing.T) {
	h3 := Chrome151H3

	var parts []string
	for _, s := range h3.Settings {
		parts = append(parts, fmt.Sprintf("%d:%d", s.ID, s.Value))
	}
	if h3.GreaseSetting {
		parts = append(parts, "GREASE")
	}
	want := strings.Join(parts, ";")

	fields := strings.Split(h3.Fingerprint, "|")
	if len(fields) != 4 {
		t.Fatalf("fingerprint has %d fields, want 4: %q", len(fields), h3.Fingerprint)
	}
	if fields[0] != want {
		t.Errorf("settings rebuilt from Settings do not match the fingerprint:\n"+
			" rebuilt %s\n pinned  %s", want, fields[0])
	}

	// The third field is the PRIORITY_UPDATE frame type in decimal, not a value.
	if got, want := fields[2], fmt.Sprintf("%d", H3FramePriorityUpdate); got != want {
		t.Errorf("fingerprint field 3 = %s, want %s (0x%x, PRIORITY_UPDATE)",
			got, want, H3FramePriorityUpdate)
	}

	// And the fourth is the pseudo-header order, initials only.
	var initials []string
	for _, p := range h3.PseudoHeaderOrder {
		initials = append(initials, string(p[1]))
	}
	if got, want := fields[3], strings.Join(initials, ","); got != want {
		t.Errorf("fingerprint pseudo-header order = %s, want %s", got, want)
	}
}

// TestSettingsFrameLengthImpliesAnEightByteGrease turns a pinned number into a
// derived one, and gets a fact out of it that nothing else in the profile
// records.
//
// The browserleaks report gave the SETTINGS entries and the frame's body length
// separately. The entries only account for part of that length; what is left has
// to be the reserved entry, whose id and value the report could not print
// because both are random. Sixteen bytes left over is an eight-byte varint id
// and an eight-byte varint value — the largest encoding QUIC has, and not what a
// small random number would produce on its own.
//
// That matters for the encoder rather than for the reference: a GREASE entry
// drawn as a small id with a short value would be a different frame length, and
// therefore visible, however random it looked.
func TestSettingsFrameLengthImpliesAnEightByteGrease(t *testing.T) {
	// RFC 9000 section 16: a varint is 1, 2, 4 or 8 bytes by magnitude.
	varintLen := func(v uint64) int {
		switch {
		case v < 1<<6:
			return 1
		case v < 1<<14:
			return 2
		case v < 1<<30:
			return 4
		default:
			return 8
		}
	}

	known := 0
	for _, s := range Chrome151H3.Settings {
		known += varintLen(s.ID) + varintLen(s.Value)
	}

	rest := Chrome151H3.SettingsFrameLen - known
	if !Chrome151H3.GreaseSetting {
		if rest != 0 {
			t.Errorf("the pinned settings encode to %d bytes but the frame body is "+
				"%d; %d bytes are unaccounted for", known, Chrome151H3.SettingsFrameLen, rest)
		}
		return
	}
	if rest != 16 {
		t.Errorf("the reserved setting takes %d bytes (%d of body %d used by the "+
			"four pinned entries); an eight-byte id and an eight-byte value is 16",
			rest, known, Chrome151H3.SettingsFrameLen)
	}
}

// TestH3SettingsAreCoherentWithTransportParameters checks the one cross-layer
// claim in the profile. SETTINGS_H3_DATAGRAM and the transport parameter
// max_datagram_frame_size are two halves of the same capability, announced at
// different layers of the same handshake; advertising one without the other is
// a contradiction a server can see.
func TestH3SettingsAreCoherentWithTransportParameters(t *testing.T) {
	var h3Datagram bool
	for _, s := range Chrome151H3.Settings {
		if s.ID == H3SettingDatagram {
			h3Datagram = s.Value != 0
		}
	}
	_, tpDatagram := Chrome151QUIC.TransportParams[TPMaxDatagramFrameSize]

	if h3Datagram != tpDatagram {
		t.Errorf("SETTINGS_H3_DATAGRAM=%v but max_datagram_frame_size present=%v; "+
			"the two announce the same capability and must agree",
			h3Datagram, tpDatagram)
	}
}

// TestH3ControlStreamIsNotSilentAfterSettings pins the shape that a
// straightforward HTTP/3 implementation gets wrong by omission: Chrome does not
// stop at SETTINGS. It sends a reserved frame and a PRIORITY_UPDATE on the same
// control stream before any request, and a stream that goes quiet after
// SETTINGS is distinguishable before a single byte of a request is written.
func TestH3ControlStreamIsNotSilentAfterSettings(t *testing.T) {
	h3 := Chrome151H3
	if !h3.GreaseFrameAfterSettings {
		t.Error("no reserved frame after SETTINGS; Chrome sends one")
	}
	if !slices.Contains(h3.AfterSettings, H3FramePriorityUpdate) {
		t.Error("no PRIORITY_UPDATE after SETTINGS; Chrome sends one before its first request")
	}
	if h3.SettingsStreamID != 2 {
		t.Errorf("control stream = %d, want 2 (the client's first unidirectional stream)",
			h3.SettingsStreamID)
	}
}

// TestPseudoHeaderOrderMatchesTheHTTP2Profile records that Chrome uses one
// pseudo-header order across both protocols. A client whose h3 order differed
// from its h2 order would be claiming to be two browsers.
func TestPseudoHeaderOrderMatchesTheHTTP2Profile(t *testing.T) {
	// The HTTP/2 profile's order, from fingerprint.go: :method, :authority,
	// :scheme, :path.
	want := []string{":method", ":authority", ":scheme", ":path"}
	if !slices.Equal(Chrome151H3.PseudoHeaderOrder, want) {
		t.Errorf("HTTP/3 pseudo-header order = %v, want %v (the HTTP/2 profile's)",
			Chrome151H3.PseudoHeaderOrder, want)
	}
}

// TestClientHintsLeadTheHeaderOrder pins the part of the header order most
// likely to be lost. Chrome puts sec-ch-ua-platform first, ahead of user-agent
// — not alphabetical, not insertion order for any obvious insertion, and not
// what a Go http.Header would produce, since net/http sorts.
func TestClientHintsLeadTheHeaderOrder(t *testing.T) {
	order := Chrome151H3.FetchHeaderOrder
	if len(order) < 4 {
		t.Fatalf("header order has %d entries", len(order))
	}
	if order[0] != "sec-ch-ua-platform" {
		t.Errorf("first header = %q, want sec-ch-ua-platform", order[0])
	}
	if order[1] != "user-agent" {
		t.Errorf("second header = %q, want user-agent", order[1])
	}

	sorted := slices.Clone(order)
	slices.Sort(sorted)
	if slices.Equal(sorted, order) {
		t.Error("the pinned header order is alphabetical, which is what a sorting " +
			"client produces and not what Chrome sends")
	}
}
