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
		total.CryptoOrder = append(total.CryptoOrder, f.CryptoOrder...)
	}

	stream, err := Assemble(frags)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	return lead, stream, total
}

// The captures, and the reference each one is evidence for.
//
// Two independent connections stand behind the fresh profile on purpose. They
// were taken minutes apart to different server IPs and they disagree about
// everything Chrome randomises — extension order, transport parameter order,
// the chaos protector's fragment sizes — while agreeing on every value
// reference.go pins. One capture could not tell those two categories apart.
var captures = []struct {
	name string
	path string
	ref  Reference
}{
	{"cloudflare-quic", "testdata/chrome151-cloudflare-quic.txt", Chrome151QUIC},
	{"cloudflare-quic-2", "testdata/chrome151-cloudflare-quic-2.txt", Chrome151QUIC},
	{"google-resumed", "testdata/chrome151-google-resumed.txt", Chrome151QUICResumed},
}

// TPGoogleInitialRTT is Google's initial_rtt parameter, in microseconds. It
// appears on some connections and not others and carries a different value
// every time, which is exactly right for what it is: a measurement of the path
// rather than a property of the client. Tolerated, never pinned — a client
// that sent a constant here would be claiming every network is the same.
const TPGoogleInitialRTT = 0x3127

const capturePath = "testdata/chrome151-cloudflare-quic.txt"

func TestInitialHeaderMatchesReference(t *testing.T) {
	for _, c := range captures {
		t.Run(c.name, func(t *testing.T) {
			ref := c.ref
			grams := readCapture(t, c.path)

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
			// A resumed connection replays a server-issued token; a fresh one
			// has nothing to replay. Which of the two it is has to be visible
			// from the header alone.
			if ref.Resumed && len(h0.Token) == 0 {
				t.Error("resumed connection carries no token")
			}
			if !ref.Resumed && len(h0.Token) != 0 {
				t.Errorf("fresh connection carries a %d byte token", len(h0.Token))
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
		})
	}
}

// TestChaosProtection records that Chrome fragments and shuffles its
// ClientHello rather than sending it as one CRYPTO frame. The exact layout is
// randomised per connection and is not pinned; what is checked is that the
// fragmentation is there at all, because a single tidy CRYPTO frame is the
// shape this client must not have.
func TestChaosProtection(t *testing.T) {
	for _, c := range captures {
		t.Run(c.name, func(t *testing.T) {
			_, stream, frames := decodeCapture(t, c.path)

			if n := len(frames.Crypto); n < 3 {
				t.Errorf("CRYPTO fragments = %d, want several: Chrome's chaos "+
					"protector splits the first flight", n)
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

			// Shuffled, not merely fragmented. This is the claim the builder in
			// chaos.go is written against, so it has to be true of Chrome's own
			// flights or the builder is reproducing something imagined.
			if !frames.CryptoOutOfOrder() {
				t.Error("Chrome's CRYPTO fragments arrived in ascending offset order")
			}
		})
	}
}

// TestChaosLayoutDiffersBetweenConnections is the check that makes the two
// cloudflare-quic captures worth having: if the fragment layout were stable,
// pinning it would be correct and reference.go would be leaving a fingerprint
// on the table. It is not stable, so it must not be pinned.
func TestChaosLayoutDiffersBetweenConnections(t *testing.T) {
	_, _, a := decodeCapture(t, "testdata/chrome151-cloudflare-quic.txt")
	_, _, b := decodeCapture(t, "testdata/chrome151-cloudflare-quic-2.txt")

	sizes := func(f *Frames) []int {
		out := make([]int, 0, len(f.Crypto))
		for _, d := range f.Crypto {
			out = append(out, len(d))
		}
		slices.Sort(out)
		return out
	}
	if slices.Equal(sizes(a), sizes(b)) {
		t.Error("two connections produced identical CRYPTO fragment sizes; " +
			"if the chaos layout is deterministic it belongs in reference.go")
	}
}

func TestClientHelloMatchesReference(t *testing.T) {
	for _, c := range captures {
		t.Run(c.name, func(t *testing.T) {
			ref := c.ref
			_, stream, _ := decodeCapture(t, c.path)

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
		})
	}
}

// TestExtensionOrderDiffersBetweenConnections is the measurement behind
// reference.go holding no extension order. Same argument as the chaos layout:
// what varies must not be pinned, and only two captures can tell the
// difference.
func TestExtensionOrderDiffersBetweenConnections(t *testing.T) {
	read := func(path string) []uint16 {
		_, stream, _ := decodeCapture(t, path)
		ch, err := ParseClientHello(stream)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return ch.Extensions
	}
	a := read("testdata/chrome151-cloudflare-quic.txt")
	b := read("testdata/chrome151-cloudflare-quic-2.txt")

	if slices.Equal(a, b) {
		t.Error("two connections produced the same extension order; " +
			"if Chrome does not permute on QUIC the order belongs in reference.go")
	}
	sa, sb := slices.Clone(a), slices.Clone(b)
	slices.Sort(sa)
	slices.Sort(sb)
	if !slices.Equal(sa, sb) {
		t.Errorf("the two connections disagree on the extension SET, not just the order:\n"+
			" %04x\n %04x", sa, sb)
	}
}

// TestNoGREASEInTheHello pins the finding that most invites a wrong
// implementation: Chrome greases its TLS-over-TCP ClientHello heavily and its
// QUIC one not at all. An implementation that reuses the TCP profile's GREASE
// placement here would be distinguishable on the first packet.
func TestNoGREASEInTheHello(t *testing.T) {
	for _, c := range captures {
		t.Run(c.name, func(t *testing.T) {
			_, stream, _ := decodeCapture(t, c.path)
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
						t.Errorf("GREASE %s 0x%04x: the QUIC hello carries none",
							group.name, v)
					}
				}
			}
		})
	}
}

func TestJA4MatchesReference(t *testing.T) {
	for _, c := range captures {
		t.Run(c.name, func(t *testing.T) {
			_, stream, _ := decodeCapture(t, c.path)
			ch, err := ParseClientHello(stream)
			if err != nil {
				t.Fatalf("parse ClientHello: %v", err)
			}
			ja4, ja4r := ch.JA4()
			if ja4 != c.ref.JA4 {
				t.Errorf("JA4   = %s\n want %s", ja4, c.ref.JA4)
			}
			if ja4r != c.ref.JA4R {
				t.Errorf("JA4_r = %s\n want %s", ja4r, c.ref.JA4R)
			}
		})
	}
}

func TestTransportParametersMatchReference(t *testing.T) {
	for _, c := range captures {
		t.Run(c.name, func(t *testing.T) {
			ref := c.ref
			_, stream, _ := decodeCapture(t, c.path)
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
						t.Errorf("chosen version = 0x%08x, want 0x%08x",
							chosen, ref.ChosenVersion)
					}
					// The rest is the available-versions list: QUIC v1 plus one
					// reserved value, in an order that moves per connection.
					if len(p.Value) != 12 {
						t.Errorf("version_information is %d bytes, want 12", len(p.Value))
					}
				case p.ID == TPGoogleConnectionOptions:
					connOpts = string(p.Value)
				case p.ID == TPGoogleInitialRTT:
					// A path measurement, so it differs every time by design.
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
				t.Errorf("google connection options = %q, want %q",
					connOpts, ref.ConnectionOptions)
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
		})
	}
}

// TestTransportParameterOrderDiffersBetweenConnections is the measurement that
// corrected PLAN.md. The parameters are shuffled per connection, so the wire
// order is noise and reference.go holds a map rather than a slice.
func TestTransportParameterOrderDiffersBetweenConnections(t *testing.T) {
	ids := func(path string) []uint64 {
		_, stream, _ := decodeCapture(t, path)
		ch, err := ParseClientHello(stream)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		params, err := ch.TransportParams()
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		out := make([]uint64, 0, len(params))
		for _, p := range params {
			if IsGREASETransportParam(p.ID) {
				continue // its id is random too, so it proves nothing
			}
			out = append(out, p.ID)
		}
		return out
	}
	a := ids("testdata/chrome151-cloudflare-quic.txt")
	b := ids("testdata/chrome151-cloudflare-quic-2.txt")
	if slices.Equal(a, b) {
		t.Error("two connections produced the same transport parameter order; " +
			"if Chrome does not shuffle them the order belongs in reference.go")
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

// TestServerConnectionIDStillKeysFromOriginal exercises the case the second
// cloudflare capture was chosen to include: its third datagram carries the
// server's 20-byte Connection ID, and it decrypts only under the client's
// original 8-byte one.
func TestServerConnectionIDStillKeysFromOriginal(t *testing.T) {
	const path = "testdata/chrome151-cloudflare-quic-2.txt"
	grams := readCapture(t, path)
	if len(grams) < 3 {
		t.Skip("capture has no follow-up Initial")
	}
	h0, err := ParseLongHeader(grams[0])
	if err != nil {
		t.Fatalf("first header: %v", err)
	}
	last, err := ParseLongHeader(grams[len(grams)-1])
	if err != nil {
		t.Fatalf("last header: %v", err)
	}
	if len(last.DCID) == len(h0.DCID) {
		t.Skip("no datagram with a server-chosen Connection ID")
	}
	if _, err := Unprotect(grams[len(grams)-1], last.DCID); err == nil {
		t.Error("decrypted under the server's Connection ID; keys must come from the original")
	}
	if _, err := Unprotect(grams[len(grams)-1], h0.DCID); err != nil {
		t.Errorf("failed to decrypt under the original DCID: %v", err)
	}
}
