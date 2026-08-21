package quic

import (
	"slices"
	"testing"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/ctls"
)

// What this client emits, checked against what Chrome emits.
//
// The rest of the package reads a capture and pins what was in it. These tests
// close the circle from the other side: they build a ClientHello with
// internal/ctls, decode it with this package's own parser, and require the
// result to match the reference the captures produced. A hello that parses but
// hashes differently fails here, which is the only place that can catch it —
// nothing else in the tree compares the bytes we send against the bytes Chrome
// sends.
//
// The parser is shared with the capture tests on purpose. It is the piece an
// independent implementation already agreed with (see browserleaksJA4 in
// http3_test.go), so using it on both sides is not circular: it is a
// measurement instrument that has been calibrated against a third party.

const testServerName = "cloudflare-quic.com"

// buildHello returns a freshly built QUIC ClientHello, already parsed.
func buildHello(t *testing.T) *ClientHello {
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
	ch, err := ParseClientHello(hello.Bytes)
	if err != nil {
		t.Fatalf("parse the hello we just built: %v", err)
	}
	return ch
}

func TestBuiltHelloMatchesReference(t *testing.T) {
	ref := Chrome151QUIC
	ch := buildHello(t)

	if ch.SNI != testServerName {
		t.Errorf("SNI = %q, want %q", ch.SNI, testServerName)
	}
	if !slices.Equal(ch.ALPN, ref.ALPN) {
		t.Errorf("ALPN = %v, want %v", ch.ALPN, ref.ALPN)
	}
	if ch.SessionID != ref.SessionIDLen {
		t.Errorf("legacy session id = %d bytes, want %d — the TCP profile sends 32, "+
			"QUIC sends none", ch.SessionID, ref.SessionIDLen)
	}
	if !slices.Equal(ch.Ciphers, ref.Ciphers) {
		t.Errorf("ciphers = %04x, want %04x", ch.Ciphers, ref.Ciphers)
	}
	if !slices.Equal(ch.Groups, ref.Groups) {
		t.Errorf("groups = %04x, want %04x", ch.Groups, ref.Groups)
	}
	if !slices.Equal(ch.KeyShares, ref.KeyShares) {
		t.Errorf("key shares = %04x, want %04x", ch.KeyShares, ref.KeyShares)
	}
	if !slices.Equal(ch.SigAlgs, ref.SigAlgs) {
		t.Errorf("signature algorithms = %04x, want %04x", ch.SigAlgs, ref.SigAlgs)
	}
	if !slices.Equal(ch.Versions, ref.TLSVersions) {
		t.Errorf("supported versions = %04x, want %04x", ch.Versions, ref.TLSVersions)
	}

	got := slices.Clone(ch.Extensions)
	slices.Sort(got)
	if !slices.Equal(got, ref.ExtensionSet) {
		t.Errorf("extension set = %04x\n            want %04x", got, ref.ExtensionSet)
	}
}

// TestBuiltHelloJA4MatchesReference is the one that matters. Everything above
// can pass while this fails, because JA4 is a function of the counts as well as
// the values.
func TestBuiltHelloJA4MatchesReference(t *testing.T) {
	ch := buildHello(t)
	ja4, ja4r := ch.JA4()
	if ja4 != Chrome151QUIC.JA4 {
		t.Errorf("JA4 of what we send   = %s\n  Chrome's            = %s", ja4, Chrome151QUIC.JA4)
	}
	if ja4r != Chrome151QUIC.JA4R {
		t.Errorf("JA4_r of what we send = %s\n  Chrome's            = %s", ja4r, Chrome151QUIC.JA4R)
	}
}

// TestBuiltHelloCarriesNoGREASE is the finding this builder exists to honour.
// Reusing the TCP profile's GREASE placement here is the natural mistake, and
// it is visible to a server on the first packet.
func TestBuiltHelloCarriesNoGREASE(t *testing.T) {
	ch := buildHello(t)
	for _, g := range []struct {
		name string
		vals []uint16
	}{
		{"cipher", ch.Ciphers},
		{"extension", ch.Extensions},
		{"supported group", ch.Groups},
		{"key share", ch.KeyShares},
		{"supported version", ch.Versions},
	} {
		for _, v := range g.vals {
			if IsGREASE(v) {
				t.Errorf("we emit a GREASE %s 0x%04x; Chrome's QUIC hello has none", g.name, v)
			}
		}
	}
}

// TestBuiltHelloPermutesExtensions checks the other half of the same coin: the
// order has to move, because a client that emits a stable one is as
// distinguishable as a client that greases where Chrome does not.
//
// Eleven extensions have 11! orders, so two draws colliding is a 1-in-40-million
// accident. Ten draws all matching is not an accident.
func TestBuiltHelloPermutesExtensions(t *testing.T) {
	first := buildHello(t).Extensions
	var moved bool
	for i := 0; i < 10 && !moved; i++ {
		if !slices.Equal(buildHello(t).Extensions, first) {
			moved = true
		}
	}
	if !moved {
		t.Error("ten hellos in a row carried the same extension order; " +
			"Chrome permutes per connection and a fixed order is the anomaly")
	}
}

// TestBuiltTransportParamsMatchReference decodes the extension we build with
// the same reader used on the captures, and holds it to the same standard.
func TestBuiltTransportParamsMatchReference(t *testing.T) {
	ref := Chrome151QUIC
	ch := buildHello(t)

	params, err := ch.TransportParams()
	if err != nil {
		t.Fatalf("transport parameters: %v", err)
	}

	got := map[uint64]uint64{}
	var greased int
	var sawSourceCID, sawVersionInfo bool
	var connOpts string

	for _, p := range params {
		switch {
		case IsGREASETransportParam(p.ID):
			greased++
			if len(p.Value) == 0 {
				t.Error("GREASE transport parameter has an empty value")
			}
		case p.ID == TPInitialSourceConnectionID:
			sawSourceCID = true
			if len(p.Value) != ref.SCIDLen {
				t.Errorf("initial_source_connection_id is %d bytes, want %d",
					len(p.Value), ref.SCIDLen)
			}
		case p.ID == TPVersionInformation:
			sawVersionInfo = true
			if len(p.Value) != 12 {
				t.Fatalf("version_information is %d bytes, want 12", len(p.Value))
			}
			chosen := uint32(p.Value[0])<<24 | uint32(p.Value[1])<<16 |
				uint32(p.Value[2])<<8 | uint32(p.Value[3])
			if chosen != ref.ChosenVersion {
				t.Errorf("chosen version = 0x%08x, want 0x%08x", chosen, ref.ChosenVersion)
			}
			// The available list holds QUIC v1 and one reserved version, in
			// either order.
			var sawV1, sawGrease bool
			for i := 4; i+4 <= len(p.Value); i += 4 {
				v := uint32(p.Value[i])<<24 | uint32(p.Value[i+1])<<16 |
					uint32(p.Value[i+2])<<8 | uint32(p.Value[i+3])
				switch {
				case v == Version1:
					sawV1 = true
				case isGREASEVersion(v):
					sawGrease = true
				default:
					t.Errorf("available version 0x%08x is neither v1 nor reserved", v)
				}
			}
			if !sawV1 {
				t.Error("available versions omit QUIC v1")
			}
			if !sawGrease {
				t.Error("available versions carry no reserved version")
			}
		case p.ID == TPGoogleConnectionOptions:
			connOpts = string(p.Value)
		default:
			v, ok := p.Uint()
			if !ok {
				t.Errorf("transport parameter 0x%02x is not a varint", p.ID)
				continue
			}
			got[p.ID] = v
		}
	}

	if !sawSourceCID {
		t.Error("no initial_source_connection_id")
	}
	if !sawVersionInfo {
		t.Error("no version_information")
	}
	if greased != 1 {
		t.Errorf("GREASE transport parameters = %d, want exactly 1", greased)
	}
	if connOpts != ref.ConnectionOptions {
		t.Errorf("google connection options = %q, want %q", connOpts, ref.ConnectionOptions)
	}
	for id, want := range ref.TransportParams {
		if got[id] != want {
			t.Errorf("transport parameter 0x%02x = %d, want %d", id, got[id], want)
		}
	}
	for id, v := range got {
		if _, known := ref.TransportParams[id]; !known {
			t.Errorf("we emit an unpinned transport parameter 0x%02x = %d", id, v)
		}
	}
}

// TestBuiltTransportParamsShuffle mirrors the capture-side test: the order has
// to move between connections, or reference.go would have been wrong to hold a
// map.
func TestBuiltTransportParamsShuffle(t *testing.T) {
	ids := func() []uint64 {
		ch := buildHello(t)
		params, err := ch.TransportParams()
		if err != nil {
			t.Fatalf("transport parameters: %v", err)
		}
		out := make([]uint64, 0, len(params))
		for _, p := range params {
			if IsGREASETransportParam(p.ID) {
				continue // random id, so it would prove nothing
			}
			out = append(out, p.ID)
		}
		return out
	}
	first := ids()
	for i := 0; i < 10; i++ {
		if !slices.Equal(ids(), first) {
			return
		}
	}
	t.Error("ten hellos in a row put the transport parameters in the same order")
}

// isGREASEVersion reports whether v is a reserved QUIC version: 0x?a?a?a?a
// (RFC 9368 section 3).
func isGREASEVersion(v uint32) bool {
	for i := 0; i < 4; i++ {
		if byte(v>>(8*i))&0x0f != 0x0a {
			return false
		}
	}
	return true
}
