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

// realChromeJA4 is the JA4 this builder emits. JA4 sorts extensions before
// hashing, so unlike JA3 it survives the per-connection shuffle and is stable.
//
// The extension count is 16, not the 17 an earlier revision documented: that
// figure came from a resumed-session capture carrying pre_shared_key (0x0029),
// which this builder never sends.
const realChromeJA4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"

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
	}
}
