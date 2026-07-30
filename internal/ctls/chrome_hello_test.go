package ctls

import (
	"crypto/sha256"
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
		exts, err := buildChromeExtensions("example.com", []string{"h2", "http/1.1"}, km, gs, nil)
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

// realChromeJA4 is the JA4 of a real Chrome 150, captured via tls.peet.ws.
// JA4 sorts extensions before hashing, so unlike JA3 it survives the
// per-connection shuffle and is stable.
//
// The extension count is 16, not the 17 an earlier revision documented: that
// figure came from a resumed-session capture carrying pre_shared_key (0x0029),
// which this builder never sends. The device confirms 16.
const realChromeJA4 = "t13d1516h2_8daaf6152771_806a8c22fdea"

// realChromeJA4RExts is the sorted extension list the device reports in ja4_r.
// It matches this builder exactly, which is what makes the count above certain.
const realChromeJA4RExts = "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01"

func TestChromeClientHelloJA4(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}

	// Run several times: the shuffle must not move JA4.
	for i := 0; i < 8; i++ {
		raw, err := buildChromeClientHello("tls.peet.ws", []string{"h2", "http/1.1"}, km, nil)
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
	raw, err := buildChromeClientHello("tls.peet.ws", []string{"h2", "http/1.1"}, km, nil)
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
