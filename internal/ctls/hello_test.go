package ctls

import (
	"bytes"
	"strings"
	"testing"
)

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

// TestGreaseKeyShareMatchesGreaseGroup covers the cause of
// "tls handshake: server alert: illegal_parameter (47)" against strict servers.
//
// RFC 8446 §4.2.8: "Clients MUST NOT offer any KeyShareEntry values for groups
// not listed in the client's 'supported_groups' extension. [...] Servers MAY
// check for violations of these rules and abort the handshake with an
// 'illegal_parameter' alert if one is violated."
//
// The GREASE entry in key_share is a group value, so it has to be the same
// group that supported_groups advertises. newGreaseSet used to draw the two
// independently out of the 16 GREASE values, so 15 connections in 16 offered a
// key share for a group the hello never claimed to support. Lenient servers
// ignore it; ones that enforce §4.2.8 kill the handshake.
//
// BoringSSL — what real Chrome ships — reads both slots from a single
// ssl_grease_group index, so a real browser hello can never disagree here.
func TestGreaseKeyShareMatchesGreaseGroup(t *testing.T) {
	for i := 0; i < 20000; i++ {
		gs := newGreaseSet()
		if gs.keyShare != gs.group {
			t.Fatalf("draw %d: key_share GREASE 0x%04x != supported_groups GREASE 0x%04x; "+
				"the hello offers a key share for a group it does not advertise and a "+
				"strict server answers illegal_parameter (47)", i, gs.keyShare, gs.group)
		}
	}
}

// TestKeyShareGroupsAreAdvertised asserts the same property on the bytes each
// builder emits, and additionally pins the ordering half of §4.2.8: "The
// KeyShareEntry values MUST appear in the same order as in the supported_groups
// extension." Both are checked here so a future edit that reintroduces the
// violation by some other route than newGreaseSet still fails.
func TestKeyShareGroupsAreAdvertised(t *testing.T) {
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
				if len(ch.keyShareGroups) == 0 {
					t.Fatalf("build %d: no key_share entries parsed", i)
				}

				// Every offered key share must name a group supported_groups
				// advertises, and the shares must follow that list's order.
				next := 0
				for _, ksGroup := range ch.keyShareGroups {
					at := -1
					for j := next; j < len(ch.groups); j++ {
						if ch.groups[j] == ksGroup {
							at = j
							break
						}
					}
					if at < 0 {
						// Distinguish the two failure modes: a group missing
						// entirely, versus one that is present but out of order.
						for _, g := range ch.groups {
							if g == ksGroup {
								t.Fatalf("build %d: key_share order %v does not follow "+
									"supported_groups order %v (group 0x%04x)",
									i, ch.keyShareGroups, ch.groups, ksGroup)
							}
						}
						t.Fatalf("build %d: key_share offers group 0x%04x, which is not in "+
							"supported_groups %v; a strict server answers illegal_parameter (47)",
							i, ksGroup, ch.groups)
					}
					next = at + 1
				}
			}
		})
	}
}

// TestSNIOmittedForAddressLiterals covers the other fatal-alert trigger on this
// path. RFC 6066 §3: "Literal IPv4 and IPv6 addresses are not permitted in
// 'HostName'." A server that enforces it rejects the hello outright, so an
// IP-form target has to go out with no server_name at all — which is what the
// emulated browsers do.
func TestSNIOmittedForAddressLiterals(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}

	cases := []struct {
		name    string
		want    bool // server_name present
		wantSNI string
	}{
		{"example.com", true, "example.com"},
		{"sub.example.co.uk", true, "sub.example.co.uk"},
		// A hostname that merely looks numeric is still a hostname.
		{"1.2.3.4.example.com", true, "1.2.3.4.example.com"},
		// A trailing root label is legal in a URL host and illegal in a
		// HostName, so it is stripped rather than passed through.
		{"example.com.", true, "example.com"},
		{"example.com...", true, "example.com"},
		// Browsers normalise the URL host before the TLS layer sees it.
		{"EXAMPLE.com", true, "example.com"},
		{"Sub.Example.COM.", true, "sub.example.com"},
		// net/http hands the dialer an A-label, which passes through unchanged.
		{"xn--kln-sna.example", true, "xn--kln-sna.example"},
		{"103.214.71.121", false, ""},
		{"::1", false, ""},
		{"[2606:4700:4700::1111]", false, ""},
		{"2606:4700:4700::1111", false, ""},
		// A scope zone has to come off before the address check, or the whole
		// thing fails to parse as an IP and goes out as a bogus HostName.
		{"fe80::1%eth0", false, ""},
		{"[fe80::1%eth0]", false, ""},
		{"", false, ""},
		{".", false, ""},
	}

	builders := map[string]func(string, []string, *keyMaterial) ([]byte, error){
		"safari": buildSafariClientHello,
		"chrome": buildChromeClientHello,
	}

	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			for _, tc := range cases {
				raw, err := build(tc.name, []string{"h2", "http/1.1"}, km)
				if err != nil {
					t.Fatalf("build(%q): %v", tc.name, err)
				}
				ch, err := parseClientHello(raw)
				if err != nil {
					t.Fatalf("parseClientHello(%q): %v", tc.name, err)
				}
				if ch.hasSNI != tc.want {
					t.Fatalf("build(%q): server_name present = %v, want %v", tc.name, ch.hasSNI, tc.want)
				}
				if !tc.want {
					continue
				}
				// Present: check it actually carries the requested name.
				data, ok := findExtension(raw, extServerName)
				if !ok {
					t.Fatalf("build(%q): server_name reported present but not found", tc.name)
				}
				if len(data) < 5 {
					t.Fatalf("build(%q): server_name payload too short: %d", tc.name, len(data))
				}
				if got := string(data[5:]); got != tc.wantSNI {
					t.Fatalf("build(%q): SNI host = %q, want %q", tc.name, got, tc.wantSNI)
				}
			}
		})
	}
}

// TestALPNEncoding pins the ProtocolNameList guards. RFC 7301 gives the list
// and each name a minimum length of one, and the 1-byte name prefix cannot
// describe anything longer than 255 — inputs that break either used to be
// encoded anyway, putting an extension on the wire whose framing disagreed with
// its contents.
func TestALPNEncoding(t *testing.T) {
	t.Run("well formed", func(t *testing.T) {
		got := buildALPN([]string{"h2", "http/1.1"})
		want := []byte{
			0x00, 0x0C, // list length: 12
			0x02, 'h', '2',
			0x08, 'h', 't', 't', 'p', '/', '1', '.', '1',
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("buildALPN = %x, want %x", got, want)
		}
	})

	t.Run("nothing encodable", func(t *testing.T) {
		for name, in := range map[string][]string{
			"nil":         nil,
			"empty slice": {},
			"empty name":  {""},
			"all dropped": {"", strings.Repeat("x", 256)},
		} {
			if got := buildALPN(in); got != nil {
				t.Fatalf("%s: buildALPN = %x, want nil so the caller omits the extension", name, got)
			}
		}
	})

	t.Run("drops unencodable names", func(t *testing.T) {
		got := buildALPN([]string{"h2", strings.Repeat("x", 256), "", "http/1.1"})
		want := []byte{
			0x00, 0x0C,
			0x02, 'h', '2',
			0x08, 'h', 't', 't', 'p', '/', '1', '.', '1',
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("buildALPN = %x, want %x", got, want)
		}
	})
}

// TestExtensionsAreSelfConsistent walks every extension of every hello both
// builders can produce and checks the declared lengths against the bytes that
// follow. A length that disagrees with its payload shifts the parse of every
// later extension, so one bad encoder turns the whole ClientHello into
// something the server rejects rather than something it merely ignores.
func TestExtensionsAreSelfConsistent(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}

	names := []string{
		"example.com", "example.com.", "EXAMPLE.com",
		"127.0.0.1", "::1", "fe80::1%eth0", "",
	}
	alpnLists := [][]string{
		{"h2", "http/1.1"},
		{"http/1.1"},
		{},
		nil,
		{""},
	}
	builders := map[string]func(string, []string, *keyMaterial) ([]byte, error){
		"safari": buildSafariClientHello,
		"chrome": buildChromeClientHello,
	}

	for bname, build := range builders {
		for _, host := range names {
			for _, alpn := range alpnLists {
				raw, err := build(host, alpn, km)
				if err != nil {
					t.Fatalf("%s build(%q, %v): %v", bname, host, alpn, err)
				}
				// parseClientHello validates the handshake header, the block
				// length and every extension length against the real bytes.
				ch, err := parseClientHello(raw)
				if err != nil {
					t.Fatalf("%s build(%q, %v): %v", bname, host, alpn, err)
				}
				// And the retry rewriter re-derives the same boundaries, so it
				// is a second, independent check on the framing.
				if _, err := clientHelloExtensionsStart(raw); err != nil {
					t.Fatalf("%s build(%q, %v): extension span: %v", bname, host, alpn, err)
				}
				if len(ch.extTypes) == 0 {
					t.Fatalf("%s build(%q, %v): no extensions", bname, host, alpn)
				}
			}
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
