package quic

import (
	"bufio"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"
)

// The capture is the authority. These tests decode the committed Initial
// datagrams of a real Chrome and check reference.go against what comes out, so
// every value there is a measurement rather than a claim.

// readCapture loads the hex-encoded datagrams from a testdata file.
func readCapture(t *testing.T, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	defer f.Close()

	var out [][]byte
	var cur strings.Builder
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		b, err := hex.DecodeString(cur.String())
		if err != nil {
			t.Fatalf("capture hex: %v", err)
		}
		out = append(out, b)
		cur.Reset()
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "datagram "):
			flush()
		default:
			cur.WriteString(line)
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		t.Fatalf("read capture: %v", err)
	}
	return out
}

// decodeCapture unprotects every datagram of one connection and returns the
// reassembled handshake stream along with the first packet's header.
func decodeCapture(t *testing.T, path string) (*Packet, []byte, *Frames) {
	t.Helper()
	grams := readCapture(t, path)
	if len(grams) == 0 {
		t.Fatal("capture holds no datagrams")
	}

	// The original DCID is the one the client chose for its first Initial;
	// later Initials carry the server's and must still key from this one.
	h0, err := ParseLongHeader(grams[0])
	if err != nil {
		t.Fatalf("first datagram header: %v", err)
	}
	orig := h0.DCID

	frags := map[uint64][]byte{}
	total := &Frames{Crypto: frags}
	var lead *Packet
	for i, g := range grams {
		p, err := Unprotect(g, orig)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if i == 0 {
			lead = p
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
	}

	stream, err := Assemble(frags)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	return lead, stream, total
}

const capturePath = "testdata/chrome151-cloudflare-quic.txt"

func TestInitialHeaderMatchesReference(t *testing.T) {
	ref := Chrome151QUIC
	grams := readCapture(t, capturePath)

	h0, err := ParseLongHeader(grams[0])
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	if h0.Version != Version1 {
		t.Errorf("version = 0x%08x, want 0x%08x", h0.Version, Version1)
	}
	if got := len(h0.DCID); got != ref.DCIDLen {
		t.Errorf("DCID length = %d, want %d", got, ref.DCIDLen)
	}
	if got := len(h0.SCID); got != ref.SCIDLen {
		t.Errorf("SCID length = %d, want %d", got, ref.SCIDLen)
	}
	if got := len(h0.Token); got != ref.TokenLen {
		t.Errorf("token length = %d, want %d", got, ref.TokenLen)
	}
	for i, g := range grams {
		if len(g) != ref.DatagramSize {
			t.Errorf("datagram %d is %d bytes, want %d", i, len(g), ref.DatagramSize)
		}
	}

	p, err := Unprotect(grams[0], h0.DCID)
	if err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if p.Header.PacketType() != "Initial" {
		t.Errorf("packet type = %s, want Initial", p.Header.PacketType())
	}
	if p.Reserved != 0 {
		t.Errorf("reserved bits = %d, want 0 — header protection was misread", p.Reserved)
	}
	if len(p.Trailing) != 0 {
		t.Errorf("datagram carries %d trailing bytes; the profile does not coalesce here",
			len(p.Trailing))
	}
}

// TestChaosProtection records that Chrome fragments and shuffles its
// ClientHello rather than sending it as one CRYPTO frame. The exact layout is
// randomised per connection and is not pinned; what is checked is that the
// fragmentation is there at all, because a single tidy CRYPTO frame is the
// shape this client must not have.
func TestChaosProtection(t *testing.T) {
	_, stream, frames := decodeCapture(t, capturePath)

	if n := len(frames.Crypto); n < 3 {
		t.Errorf("CRYPTO fragments = %d, want several: Chrome's chaos protector "+
			"splits the first flight", n)
	}
	if frames.Pings == 0 {
		t.Error("no PING frames: the chaos protector interleaves them with the fragments")
	}
	if frames.CryptoLen != len(stream) {
		t.Errorf("fragments total %d bytes but the stream is %d: they overlap",
			frames.CryptoLen, len(stream))
	}

	offs := make([]uint64, 0, len(frames.Crypto))
	for off := range frames.Crypto {
		offs = append(offs, off)
	}
	slices.Sort(offs)
	if len(offs) > 0 && offs[0] != 0 {
		t.Errorf("lowest CRYPTO fragment is at offset %d, want 0", offs[0])
	}
}

func TestClientHelloMatchesReference(t *testing.T) {
	ref := Chrome151QUIC
	_, stream, _ := decodeCapture(t, capturePath)

	ch, err := ParseClientHello(stream)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}

	if ch.SNI != ref.Target {
		t.Errorf("SNI = %q, want %q", ch.SNI, ref.Target)
	}
	if !slices.Equal(ch.ALPN, ref.ALPN) {
		t.Errorf("ALPN = %v, want %v", ch.ALPN, ref.ALPN)
	}
	if ch.SessionID != ref.SessionIDLen {
		t.Errorf("session id = %d bytes, want %d", ch.SessionID, ref.SessionIDLen)
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

	sorted := slices.Clone(ch.Extensions)
	slices.Sort(sorted)
	if !slices.Equal(sorted, ref.ExtensionSet) {
		t.Errorf("extension set = %04x, want %04x", sorted, ref.ExtensionSet)
	}
}

// TestNoGREASEInTheHello pins the finding that most invites a wrong
// implementation: Chrome greases its TLS-over-TCP ClientHello heavily and its
// QUIC one not at all. An implementation that reuses the TCP profile's GREASE
// placement here would be distinguishable on the first packet.
func TestNoGREASEInTheHello(t *testing.T) {
	_, stream, _ := decodeCapture(t, capturePath)
	ch, err := ParseClientHello(stream)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}
	for _, group := range []struct {
		name string
		vals []uint16
	}{
		{"cipher", ch.Ciphers},
		{"extension", ch.Extensions},
		{"supported group", ch.Groups},
		{"key share", ch.KeyShares},
		{"supported version", ch.Versions},
	} {
		for _, v := range group.vals {
			if IsGREASE(v) {
				t.Errorf("GREASE %s 0x%04x: the QUIC hello carries none", group.name, v)
			}
		}
	}
}

func TestJA4MatchesReference(t *testing.T) {
	ref := Chrome151QUIC
	_, stream, _ := decodeCapture(t, capturePath)
	ch, err := ParseClientHello(stream)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}
	ja4, ja4r := ch.JA4()
	if ja4 != ref.JA4 {
		t.Errorf("JA4  = %s\n want %s", ja4, ref.JA4)
	}
	if ja4r != ref.JA4R {
		t.Errorf("JA4_r = %s\n  want %s", ja4r, ref.JA4R)
	}
}

func TestTransportParametersMatchReference(t *testing.T) {
	ref := Chrome151QUIC
	_, stream, _ := decodeCapture(t, capturePath)
	ch, err := ParseClientHello(stream)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}
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
		case p.ID == TPInitialSourceConnectionID:
			sawSourceCID = true
			if len(p.Value) != ref.SCIDLen {
				t.Errorf("initial_source_connection_id is %d bytes, want %d",
					len(p.Value), ref.SCIDLen)
			}
		case p.ID == TPVersionInformation:
			sawVersionInfo = true
			if len(p.Value) < 4 {
				t.Fatalf("version_information is %d bytes", len(p.Value))
			}
			chosen := uint32(p.Value[0])<<24 | uint32(p.Value[1])<<16 |
				uint32(p.Value[2])<<8 | uint32(p.Value[3])
			if chosen != ref.ChosenVersion {
				t.Errorf("chosen version = 0x%08x, want 0x%08x", chosen, ref.ChosenVersion)
			}
		case p.ID == TPGoogleConnectionOptions:
			connOpts = string(p.Value)
		default:
			if v, ok := p.Uint(); ok {
				got[p.ID] = v
			}
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
			t.Errorf("unpinned transport parameter 0x%02x = %d", id, v)
		}
	}
}

// TestWrongOriginalDCIDFails guards the trap the decoder exists to avoid: a
// later Initial in the same connection carries the server's Connection ID, and
// deriving keys from that instead of the original produces an AEAD failure
// rather than plausible-looking garbage.
func TestWrongOriginalDCIDFails(t *testing.T) {
	grams := readCapture(t, capturePath)
	h, err := ParseLongHeader(grams[0])
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	wrong := slices.Clone(h.DCID)
	wrong[0] ^= 0xff
	if _, err := Unprotect(grams[0], wrong); err == nil {
		t.Error("unprotect accepted a wrong original DCID")
	}
}
