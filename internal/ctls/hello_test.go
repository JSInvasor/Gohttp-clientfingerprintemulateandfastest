package ctls

import "testing"

// TestGreaseExtensionValuesDiffer covers a bug that made roughly 6% of all
// connections fail against strict servers.
//
// extFirst and extLast become the types of two real extensions in the same
// ClientHello. RFC 8446 §4.2 forbids two extensions of the same type, and Go's
// crypto/tls server answers a duplicate with a decode_error alert instead of a
// ServerHello. newGreaseSet used to draw both independently from the 16 GREASE
// values, so they collided 1 in 16 times.
func TestGreaseExtensionValuesDiffer(t *testing.T) {
	for i := 0; i < 20000; i++ {
		gs := newGreaseSet()
		if gs.extFirst == gs.extLast {
			t.Fatalf("draw %d: extFirst == extLast == 0x%04x; the ClientHello would "+
				"carry two extensions of that type and a strict server would reject it",
				i, gs.extFirst)
		}
	}
}

// TestNoDuplicateExtensionTypes asserts the property end to end, on the bytes
// each builder actually emits, so a future change that reintroduces a repeated
// extension by some other route still fails.
func TestNoDuplicateExtensionTypes(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}

	builders := map[string]func(string, []string, *keyMaterial) ([]byte, error){
		"safari": buildSafariClientHello,
		"chrome": buildChromeClientHello,
	}

	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 3000; i++ {
				raw, err := build("example.com", []string{"h2", "http/1.1"}, km)
				if err != nil {
					t.Fatalf("build %d: %v", i, err)
				}
				ch, err := parseClientHello(raw)
				if err != nil {
					t.Fatalf("parseClientHello %d: %v", i, err)
				}
				seen := make(map[uint16]bool, len(ch.extTypes))
				for _, e := range ch.extTypes {
					if seen[e] {
						t.Fatalf("build %d: extension 0x%04x appears twice", i, e)
					}
					seen[e] = true
				}
			}
		})
	}
}

// TestGreaseKeyShareMatchesGroup asserts that the GREASE group placed in
// key_share always equals the one placed in supported_groups. RFC 8446 §4.2.8
// requires every group in key_share to appear in supported_groups; using
// independent draws violated this on ~94% of connections.
func TestGreaseKeyShareMatchesGroup(t *testing.T) {
	for i := 0; i < 20000; i++ {
		gs := newGreaseSet()
		if gs.keyShare != gs.group {
			t.Fatalf("draw %d: keyShare=0x%04x != group=0x%04x; "+
				"RFC 8446 §4.2.8 requires key_share groups to be in supported_groups",
				i, gs.keyShare, gs.group)
		}
	}
}

// TestGreaseValuesAreValid keeps every drawn value inside the RFC 8701 set.
// A non-GREASE value in any of these slots would land in a real code point's
// namespace and could be interpreted rather than ignored.
func TestGreaseValuesAreValid(t *testing.T) {
	for i := 0; i < 5000; i++ {
		gs := newGreaseSet()
		for slot, v := range map[string]uint16{
			"cipher":   gs.cipher,
			"extFirst": gs.extFirst,
			"extLast":  gs.extLast,
			"keyShare": gs.keyShare,
			"group":    gs.group,
			"version":  gs.version,
		} {
			if !isGreaseValue(v) {
				t.Fatalf("%s = 0x%04x is not an RFC 8701 GREASE value", slot, v)
			}
		}
	}
}
