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
