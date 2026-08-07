package ctls

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestChromeExtensionsShuffle verifies that successive ClientHello builds
// produce different extension orderings (Chrome 110+ behavior). Without
// shuffle, the SHA-256 of just the extension type sequence would be
// identical across builds and detection systems would observe zero JA3
// entropy.
func TestChromeExtensionsShuffle(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}

	const iterations = 16
	seen := make(map[string]int, iterations)

	for i := 0; i < iterations; i++ {
		gs := newGreaseSet()
		exts, err := buildChromeExtensions("example.com", []string{"h2", "http/1.1"}, km, gs)
		if err != nil {
			t.Fatalf("buildChromeExtensions iter %d: %v", i, err)
		}

		// Hash only the extension type sequence (skip lengths/data so that
		// random GREASE/key_share values don't dominate the signal).
		h := sha256.New()
		off := 0
		for off < len(exts) {
			if off+4 > len(exts) {
				t.Fatalf("truncated extension at offset %d", off)
			}
			h.Write([]byte{exts[off], exts[off+1]})
			extLen := int(uint16(exts[off+2])<<8 | uint16(exts[off+3]))
			off += 4 + extLen
		}
		seen[hex.EncodeToString(h.Sum(nil))]++
	}

	if len(seen) < 2 {
		t.Fatalf("expected multiple distinct extension orderings across %d builds, got %d", iterations, len(seen))
	}
	t.Logf("observed %d distinct extension orderings across %d builds", len(seen), iterations)
}

// realChromeJA4 is the JA4 of a real Chrome 151, captured via tls.peet.ws.
// JA4 sorts extensions before hashing, so unlike JA3 it survives the
// per-connection shuffle and is stable.
//
// The extension count is 16, not the 17 an earlier revision documented: that
// figure came from a resumed-session capture carrying pre_shared_key (0x0029),
// which this builder never sends. The device confirms 16.
var realChromeJA4 = ChromeReference.JA4

// realChromeJA4RExts is the sorted extension list the device reports in ja4_r.
// It matches this builder exactly, which is what makes the count above certain.
var realChromeJA4RExts = ChromeReference.JA4RExtensions

func TestChromeClientHelloJA4(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}

	// Run several times: the shuffle must not move JA4.
	for i := 0; i < 8; i++ {
		raw, err := buildChromeClientHello("tls.peet.ws", []string{"h2", "http/1.1"}, km)
		if err != nil {
			t.Fatalf("buildChromeClientHello: %v", err)
		}
		ch, err := parseClientHello(raw)
		if err != nil {
			t.Fatalf("parseClientHello: %v", err)
		}
		if got := ch.ja4(); got != realChromeJA4 {
			t.Fatalf("JA4 mismatch on build %d\n got: %s\nwant: %s", i, got, realChromeJA4)
		}

		// The sorted extension list is the JA4_c input the device reports, so
		// pin it directly too — a mismatch here localises the failure to the
		// extension set rather than leaving it ambiguous with the sigalgs.
		var hashed []uint16
		for _, e := range dropGrease(ch.extTypes) {
			if e == extServerName || e == extALPN {
				continue
			}
			hashed = append(hashed, e)
		}
		if got := joinHexSorted(hashed); got != realChromeJA4RExts {
			t.Fatalf("ja4_r extension list mismatch\n got: %s\nwant: %s", got, realChromeJA4RExts)
		}

		// The full ja4_r is unhashed, so a failure names the exact cipher,
		// extension or signature algorithm that drifted. It survives the
		// per-connection shuffle because it sorts the extension list.
		if got := ch.ja4R(); got != ChromeReference.JA4R {
			t.Fatalf("JA4_r mismatch on build %d\n got: %s\nwant: %s", i, got, ChromeReference.JA4R)
		}
	}
}

// TestChromeSigAlgsIncludeMLDSA pins the post-quantum signature algorithms.
// Chrome 150 leads signature_algorithms with ML-DSA; the Chrome 146 profile
// omitted all three, which put JA4_c at d8a2da3f94cd instead of 806a8c22fdea.
func TestChromeSigAlgsIncludeMLDSA(t *testing.T) {
	if len(chromeSigAlgs) != 11 {
		t.Fatalf("got %d signature algorithms, want 11", len(chromeSigAlgs))
	}
	for i, want := range []uint16{0x0904, 0x0905, 0x0906} {
		if chromeSigAlgs[i] != want {
			t.Errorf("sigalg[%d] = 0x%04x, want 0x%04x (ML-DSA leads the list)",
				i, chromeSigAlgs[i], want)
		}
	}
	for _, a := range chromeSigAlgs {
		if a == 0x0201 {
			t.Error("rsa_pkcs1_sha1 (0x0201) present; Chrome does not offer SHA1")
		}
	}
}

// TestChromeALPSOffersOnlyH2 guards against reusing the ALPN list for ALPS.
// ALPS is defined only over HTTP/2, so a real Chrome lists h2 alone even though
// its ALPN carries h2 and http/1.1.
func TestChromeALPSOffersOnlyH2(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	raw, err := buildChromeClientHello("tls.peet.ws", []string{"h2", "http/1.1"}, km)
	if err != nil {
		t.Fatalf("buildChromeClientHello: %v", err)
	}
	ch, err := parseClientHello(raw)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}

	// ALPN must still offer both.
	if len(ch.alpn) != 2 || ch.alpn[0] != "h2" || ch.alpn[1] != "http/1.1" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", ch.alpn)
	}

	got := parseALPSProtocols(t, raw)
	if len(got) != 1 || got[0] != "h2" {
		t.Errorf("ALPS = %v, want [h2]", got)
	}
}

// parseALPSProtocols pulls the protocol list out of the application_settings
// extension. Its payload is framed like ALPN: a 2-byte list length followed by
// length-prefixed protocol names.
func parseALPSProtocols(t *testing.T, msg []byte) []string {
	t.Helper()
	data, ok := findExtension(msg, extALPS)
	if !ok {
		t.Fatal("application_settings (0x44CD) extension not present")
	}
	if len(data) < 2 {
		t.Fatalf("ALPS payload too short: %d bytes", len(data))
	}
	var out []string
	for i := 2; i < len(data); {
		n := int(data[i])
		if i+1+n > len(data) {
			t.Fatalf("ALPS protocol at offset %d overruns payload", i)
		}
		out = append(out, string(data[i+1:i+1+n]))
		i += 1 + n
	}
	return out
}

// TestChromeGreaseExtensionShapes pins the payloads of the two GREASE
// extensions.
//
// BoringSSL's ssl_add_clienthello_tlsext writes the first GREASE extension with
// a zero-length body and the second with exactly one 0x00 byte (RFC 8701 §3.1
// suggests varying them; BoringSSL picks these two shapes and never varies).
// Chrome inherits that verbatim, so a hello carrying two 1-byte GREASE bodies
// is one byte longer than any real Chrome's. JA3 and JA4 hash extension type
// IDs only and cannot see it — the raw ClientHello can.
func TestChromeGreaseExtensionShapes(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}

	for i := 0; i < 8; i++ {
		gs := newGreaseSet()
		exts, err := buildChromeExtensions("example.com", []string{"h2", "http/1.1"}, km, gs)
		if err != nil {
			t.Fatalf("buildChromeExtensions: %v", err)
		}

		type ext struct {
			typ  uint16
			data []byte
		}
		var all []ext
		for off := 0; off < len(exts); {
			if off+4 > len(exts) {
				t.Fatalf("truncated extension at offset %d", off)
			}
			typ := uint16(exts[off])<<8 | uint16(exts[off+1])
			n := int(uint16(exts[off+2])<<8 | uint16(exts[off+3]))
			if off+4+n > len(exts) {
				t.Fatalf("extension 0x%04x overruns the block", typ)
			}
			all = append(all, ext{typ: typ, data: exts[off+4 : off+4+n]})
			off += 4 + n
		}

		first, last := all[0], all[len(all)-1]
		if !isGreaseValue(first.typ) {
			t.Fatalf("first extension is 0x%04x, want a GREASE value", first.typ)
		}
		if !isGreaseValue(last.typ) {
			t.Fatalf("last extension is 0x%04x, want a GREASE value", last.typ)
		}
		if len(first.data) != 0 {
			t.Errorf("first GREASE extension carries %d bytes, want 0 (BoringSSL sends it empty)", len(first.data))
		}
		if len(last.data) != 1 || last.data[0] != 0x00 {
			t.Errorf("last GREASE extension carries %v, want a single 0x00 byte", last.data)
		}
	}
}

// TestChromeECHGreaseShape pins the layout and payload length of the ECH GREASE
// extension against a real Chrome 151 capture, whose extension body was:
//
//	00 0001 0001 4e 0020 <32-byte enc> 00d0 <208-byte payload>
//
// JA3 and JA4 hash extension IDs only, so neither can see any of this — but the
// raw ClientHello can, and Chrome's payload length is deterministic for a given
// target rather than random. An earlier revision used 144 on the same claim of
// being captured; the device says 208.
func TestChromeECHGreaseShape(t *testing.T) {
	data, err := buildECHGrease()
	if err != nil {
		t.Fatalf("buildECHGrease: %v", err)
	}

	const (
		wantEncLen     = 32
		wantPayloadLen = 208
		// type(1) + kdf(2) + aead(2) + config_id(1) + enc_len(2) + enc + payload_len(2) + payload
		wantTotal = 1 + 2 + 2 + 1 + 2 + wantEncLen + 2 + wantPayloadLen
	)

	if len(data) != wantTotal {
		t.Fatalf("ECH GREASE body = %d bytes, want %d", len(data), wantTotal)
	}
	if data[0] != 0x00 {
		t.Errorf("client_hello_type = %d, want 0 (outer)", data[0])
	}
	if got := binary.BigEndian.Uint16(data[1:]); got != 0x0001 {
		t.Errorf("kdf_id = 0x%04x, want 0x0001 (HKDF-SHA256)", got)
	}
	if got := binary.BigEndian.Uint16(data[3:]); got != 0x0001 {
		t.Errorf("aead_id = 0x%04x, want 0x0001 (AES-128-GCM)", got)
	}
	if got := binary.BigEndian.Uint16(data[6:]); got != wantEncLen {
		t.Fatalf("enc_len = %d, want %d", got, wantEncLen)
	}
	if got := binary.BigEndian.Uint16(data[8+wantEncLen:]); got != wantPayloadLen {
		t.Errorf("payload_len = %d, want %d — a real Chrome 151 against an "+
			"11-character hostname sends 0x00d0", got, wantPayloadLen)
	}

	// The padding rule the length follows: inner hello padded to a multiple of
	// 32, plus the 16-byte AEAD tag. Stated so a future adjustment has to stay
	// on the grid rather than picking an arbitrary number.
	if (wantPayloadLen-16)%32 != 0 {
		t.Errorf("payload_len %d is not 32*k + 16", wantPayloadLen)
	}
}

// TestChromeECHGreaseIsRandomPerHello checks the config_id, HPKE key and payload
// are freshly drawn each time. They are GREASE: a constant would make every
// connection from this client linkable to every other.
func TestChromeECHGreaseIsRandomPerHello(t *testing.T) {
	first, err := buildECHGrease()
	if err != nil {
		t.Fatalf("buildECHGrease: %v", err)
	}
	second, err := buildECHGrease()
	if err != nil {
		t.Fatalf("buildECHGrease: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Error("two ECH GREASE bodies are identical; config_id, enc and payload must be random")
	}
}
