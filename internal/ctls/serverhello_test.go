package ctls

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// newHandshakeStateWithHello builds a handshakeState holding a real ClientHello,
// which is what the ServerHello checks compare against.
func newHandshakeStateWithHello(t *testing.T, alpn []string) *handshakeState {
	t.Helper()
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	ch, err := buildChromeClientHello("example.com", alpn, km, nil)
	if err != nil {
		t.Fatalf("buildChromeClientHello: %v", err)
	}
	return &handshakeState{km: km, serverName: "example.com", alpn: alpn, clientHelloMsg: ch}
}

// ourSessionID returns the legacy_session_id the state's ClientHello carries.
func ourSessionID(t *testing.T, hs *handshakeState) []byte {
	t.Helper()
	id, err := clientHelloSessionID(hs.clientHelloMsg)
	if err != nil {
		t.Fatalf("clientHelloSessionID: %v", err)
	}
	if len(id) != 32 {
		t.Fatalf("session id is %d bytes, want the 32 both profiles send", len(id))
	}
	return id
}

// TestServerHelloSessionIDEchoIsChecked covers RFC 8446 §4.1.3: "A client which
// receives a legacy_session_id_echo field that does not match what it sent in
// the ClientHello MUST abort the handshake with an 'illegal_parameter' alert."
//
// Both profiles send a fresh 32-byte session id for middlebox compatibility, so
// this is a live check rather than a formality — a mismatch means the hello that
// reached the server is not the hello that left it.
func TestServerHelloSessionIDEchoIsChecked(t *testing.T) {
	hs := newHandshakeStateWithHello(t, []string{"h2"})
	sent := ourSessionID(t, hs)
	tls13 := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))
	random := make([]byte, 32)

	t.Run("matching echo accepted", func(t *testing.T) {
		sh, err := parseServerHelloShell(serverHelloBytes(random, sent, cipherTLS_AES_128_GCM_SHA256, tls13))
		if err != nil {
			t.Fatalf("parseServerHelloShell: %v", err)
		}
		if err := hs.checkServerHelloShell(sh); err != nil {
			t.Fatalf("a correctly echoed session id was rejected: %v", err)
		}
	})

	// An echo of the right length but the wrong bytes is the case a length-only
	// check would wave through.
	t.Run("wrong bytes rejected", func(t *testing.T) {
		altered := append([]byte(nil), sent...)
		altered[0] ^= 0xFF
		sh, err := parseServerHelloShell(serverHelloBytes(random, altered, cipherTLS_AES_128_GCM_SHA256, tls13))
		if err != nil {
			t.Fatalf("parseServerHelloShell: %v", err)
		}
		requireAlert(t, hs.checkServerHelloShell(sh), alertIllegalParameter)
	})

	t.Run("empty echo rejected", func(t *testing.T) {
		sh, err := parseServerHelloShell(serverHelloBytes(random, nil, cipherTLS_AES_128_GCM_SHA256, tls13))
		if err != nil {
			t.Fatalf("parseServerHelloShell: %v", err)
		}
		requireAlert(t, hs.checkServerHelloShell(sh), alertIllegalParameter)
	})
}

// TestServerHelloRejectsDowngradeSentinel covers the other half of §4.1.3: a
// TLS 1.3-capable server that negotiates 1.2 or below stamps a fixed value into
// the last 8 bytes of ServerHello.random, and a client that offered 1.3 and sees
// it "MUST abort the handshake with an 'illegal_parameter' alert" — the version
// list it sent was tampered with in flight.
func TestServerHelloRejectsDowngradeSentinel(t *testing.T) {
	hs := newHandshakeStateWithHello(t, []string{"h2"})
	sent := ourSessionID(t, hs)
	tls13 := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))

	for name, sentinel := range map[string][]byte{
		"tls 1.2": tls12DowngradeSentinel,
		"tls 1.1": tls11DowngradeSentinel,
	} {
		t.Run(name, func(t *testing.T) {
			random := make([]byte, 32)
			copy(random[24:], sentinel)
			sh, err := parseServerHelloShell(serverHelloBytes(random, sent, cipherTLS_AES_128_GCM_SHA256, tls13))
			if err != nil {
				t.Fatalf("parseServerHelloShell: %v", err)
			}
			requireAlert(t, hs.checkServerHelloShell(sh), alertIllegalParameter)
		})
	}

	// A HelloRetryRequest carries a fixed random of its own, which §4.1.3
	// exempts. Applying the check there would break every retried handshake.
	t.Run("hello retry request exempt", func(t *testing.T) {
		sh, err := parseServerHelloShell(
			serverHelloBytes(helloRetryRequestRandom, sent, cipherTLS_AES_128_GCM_SHA256, tls13))
		if err != nil {
			t.Fatalf("parseServerHelloShell: %v", err)
		}
		if !sh.isHRR {
			t.Fatal("HelloRetryRequest not recognised")
		}
		if err := hs.checkServerHelloShell(sh); err != nil {
			t.Fatalf("HelloRetryRequest rejected: %v", err)
		}
	})
}

// TestServerHelloRejectsNonNullCompression pins §4.1.3's
// legacy_compression_method rule. The byte was previously skipped unread; a
// non-zero value means the peer is not speaking TLS 1.3 whatever its
// supported_versions extension claims.
func TestServerHelloRejectsNonNullCompression(t *testing.T) {
	hs := newHandshakeStateWithHello(t, []string{"h2"})
	sent := ourSessionID(t, hs)
	tls13 := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))

	msg := serverHelloBytes(make([]byte, 32), sent, cipherTLS_AES_128_GCM_SHA256, tls13)
	// The compression byte sits directly after the cipher suite: header(4) +
	// version(2) + random(32) + id_len(1) + id + suite(2).
	idx := 4 + 2 + 32 + 1 + len(sent) + 2
	if msg[idx] != 0x00 {
		t.Fatalf("test built a hello whose compression byte is already %d", msg[idx])
	}
	msg[idx] = 0x01

	requireAlert(t, errFrom(parseServerHelloShell(msg)), alertIllegalParameter)
}

// TestServerHelloRejectsDuplicateExtensions covers RFC 8446 §4.2: "There MUST
// NOT be more than one extension of the same type in a given extension block."
//
// Without the check the second copy silently overwrote the first, so which
// key_share took effect came down to the order a hostile server chose — the
// classic shape of a parser-differential bug.
func TestServerHelloRejectsDuplicateExtensions(t *testing.T) {
	hs := newHandshakeStateWithHello(t, []string{"h2"})
	sent := ourSessionID(t, hs)

	tls13 := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))
	exts := append(append([]byte(nil), tls13...), tls13...)

	sh, err := parseServerHelloShell(serverHelloBytes(make([]byte, 32), sent, cipherTLS_AES_128_GCM_SHA256, exts))
	if err != nil {
		t.Fatalf("parseServerHelloShell: %v", err)
	}
	_, err = hs.parseServerHello(sh)
	requireAlert(t, err, alertIllegalParameter)
	if !strings.Contains(err.Error(), "twice") {
		t.Fatalf("error does not name the duplicate: %v", err)
	}
}

// TestServerHelloRejectsUnsolicitedPSK covers a server selecting a pre-shared
// key from the empty list this package offers.
//
// Ignoring it meant deriving the key schedule without the PSK the server had
// already mixed in, and the handshake died several messages later at "server
// finished MAC mismatch" — a decryption symptom for what is really a
// ServerHello contract violation.
func TestServerHelloRejectsUnsolicitedPSK(t *testing.T) {
	hs := newHandshakeStateWithHello(t, []string{"h2"})
	sent := ourSessionID(t, hs)

	exts := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))
	exts = append(exts, tlsExt(extPreSharedKey, []byte{0x00, 0x00})...)

	sh, err := parseServerHelloShell(serverHelloBytes(make([]byte, 32), sent, cipherTLS_AES_128_GCM_SHA256, exts))
	if err != nil {
		t.Fatalf("parseServerHelloShell: %v", err)
	}
	_, err = hs.parseServerHello(sh)
	requireAlert(t, err, alertIllegalParameter)
}

// TestServerHelloRejectsExtensionsMovedToEncryptedExtensions pins §4.2's table:
// TLS 1.3 allows only key_share, pre_shared_key and supported_versions in a
// ServerHello. ALPN in particular is not merely misplaced — honouring it there
// would let a cleartext, unauthenticated field pick the application protocol.
func TestServerHelloRejectsExtensionsMovedToEncryptedExtensions(t *testing.T) {
	hs := newHandshakeStateWithHello(t, []string{"h2", "http/1.1"})
	sent := ourSessionID(t, hs)

	for name, ext := range map[string][]byte{
		"alpn":           tlsExt(extALPN, []byte{0x00, 0x03, 0x02, 'h', '2'}),
		"server_name":    tlsExt(extServerName, nil),
		"session_ticket": tlsExt(extSessionTicket, nil),
		"sct":            tlsExt(extSCT, nil),
	} {
		t.Run(name, func(t *testing.T) {
			exts := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))
			exts = append(exts, ext...)
			sh, err := parseServerHelloShell(
				serverHelloBytes(make([]byte, 32), sent, cipherTLS_AES_128_GCM_SHA256, exts))
			if err != nil {
				t.Fatalf("parseServerHelloShell: %v", err)
			}
			_, err = hs.parseServerHello(sh)
			requireAlert(t, err, alertUnsupportedExtension)
		})
	}

	// GREASE only works if unrecognised types keep being ignored, so the
	// rejection has to stay limited to extensions we know are misplaced.
	t.Run("unknown type ignored", func(t *testing.T) {
		exts := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))
		exts = append(exts, tlsExt(0x8A8A, nil)...)
		exts = append(exts, tlsExt(extKeyShare, keyShareEntryForTest(t, hs))...)
		sh, err := parseServerHelloShell(
			serverHelloBytes(make([]byte, 32), sent, cipherTLS_AES_128_GCM_SHA256, exts))
		if err != nil {
			t.Fatalf("parseServerHelloShell: %v", err)
		}
		if _, err := hs.parseServerHello(sh); err != nil {
			t.Fatalf("an unknown extension was rejected: %v", err)
		}
	})
}

// keyShareEntryForTest builds a usable X25519 KeyShareEntry so a ServerHello can
// get all the way through parseServerHello.
func keyShareEntryForTest(t *testing.T, hs *handshakeState) []byte {
	t.Helper()
	pub := hs.km.x25519Priv.PublicKey().Bytes()
	out := binary.BigEndian.AppendUint16(nil, groupX25519)
	out = binary.BigEndian.AppendUint16(out, uint16(len(pub)))
	return append(out, pub...)
}

// TestServerHelloRejectsTrailingBytes checks that a message with padding after
// its extension block is rejected rather than parsed as far as it goes. Bytes
// the parser never looks at are bytes the two peers hash differently.
func TestServerHelloRejectsTrailingBytes(t *testing.T) {
	tls13 := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))
	msg := serverHelloBytes(make([]byte, 32), nil, cipherTLS_AES_128_GCM_SHA256, tls13)
	msg = append(msg, 0xDE, 0xAD)
	// Re-length the handshake header so the trailing bytes are inside the body.
	bodyLen := len(msg) - 4
	msg[1], msg[2], msg[3] = byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen)

	requireAlert(t, errFrom(parseServerHelloShell(msg)), alertDecodeError)
}

// TestNegotiatedALPNMustHaveBeenOffered covers RFC 7301 §3.2: the server picks
// from the client's list, it does not invent an entry.
//
// The consequence here is concrete rather than theoretical. dialTLSForH2 treats
// any protocol other than "h2" as an HTTP/1.1 server and caches that verdict for
// ten minutes, so a peer answering with a protocol nobody offered could force
// every later request to that host onto HTTP/1.1.
func TestNegotiatedALPNMustHaveBeenOffered(t *testing.T) {
	hs := newHandshakeStateWithHello(t, []string{"h2", "http/1.1"})

	for _, proto := range []string{"h2", "http/1.1"} {
		if err := hs.checkNegotiatedALPN(proto); err != nil {
			t.Fatalf("offered protocol %q rejected: %v", proto, err)
		}
	}
	for _, proto := range []string{"h3", "spdy/3.1", "http/1.0", ""} {
		requireAlert(t, hs.checkNegotiatedALPN(proto), alertNoApplicationProtocol)
	}
}

// TestEncryptedExtensionsALPNParsing pins that a malformed ALPN in
// EncryptedExtensions fails the handshake instead of reading as "no protocol
// selected".
//
// EncryptedExtensions is authenticated, so anything unparseable in it is a real
// protocol failure — and the silent "" it used to produce was the worst possible
// outcome downstream, because an empty ALPN makes dialTLSForH2 record the host
// as HTTP/1.1 for ten minutes.
func TestEncryptedExtensionsALPNParsing(t *testing.T) {
	encryptedExtensions := func(exts []byte) []byte {
		return append(binary.BigEndian.AppendUint16(nil, uint16(len(exts))), exts...)
	}

	t.Run("well formed", func(t *testing.T) {
		body := encryptedExtensions(tlsExt(extALPN, []byte{0x00, 0x03, 0x02, 'h', '2'}))
		proto, err := parseEncryptedExtensionsALPN(body)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if proto != "h2" {
			t.Fatalf("protocol = %q, want h2", proto)
		}
	})

	t.Run("absent is not an error", func(t *testing.T) {
		proto, err := parseEncryptedExtensionsALPN(encryptedExtensions(nil))
		if err != nil {
			t.Fatalf("an EncryptedExtensions without ALPN failed: %v", err)
		}
		if proto != "" {
			t.Fatalf("protocol = %q, want empty", proto)
		}
	})

	malformed := map[string][]byte{
		"truncated body":        {0x00},
		"exts overrun":          {0xFF, 0xFF},
		"alpn too short":        encryptedExtensions(tlsExt(extALPN, []byte{0x00})),
		"list length lies":      encryptedExtensions(tlsExt(extALPN, []byte{0x00, 0xFF, 0x02, 'h', '2'})),
		"protocol length lies":  encryptedExtensions(tlsExt(extALPN, []byte{0x00, 0x03, 0xFF, 'h', '2'})),
		"zero length protocol":  encryptedExtensions(tlsExt(extALPN, []byte{0x00, 0x01, 0x00})),
		"trailing second entry": encryptedExtensions(tlsExt(extALPN, []byte{0x00, 0x06, 0x02, 'h', '2', 0x01, 'x'})),
	}
	for name, body := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := parseEncryptedExtensionsALPN(body); err == nil {
				t.Fatal("malformed ALPN accepted")
			}
		})
	}
}

// TestParseCertificateRejectsMalformedEntries covers the list walk. Both cases
// used to end the loop quietly and hand back whatever had parsed so far, so a
// truncated or overrunning message produced a chain the server never sent.
func TestParseCertificateRejectsMalformedEntries(t *testing.T) {
	// context(1) + list length(3) + one entry: cert length(3) + cert + ext(2)
	entry := func(der []byte, extLen uint16, extra []byte) []byte {
		e := []byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}
		e = append(e, der...)
		e = binary.BigEndian.AppendUint16(e, extLen)
		return append(e, extra...)
	}
	message := func(entries []byte) []byte {
		out := []byte{0x00}
		out = append(out, byte(len(entries)>>16), byte(len(entries)>>8), byte(len(entries)))
		return append(out, entries...)
	}

	der := []byte{0x30, 0x03, 0x02, 0x01, 0x00} // not a certificate, but well framed

	t.Run("extension length overruns", func(t *testing.T) {
		if _, err := parseCertificate(message(entry(der, 0xFFFF, nil))); err == nil {
			t.Fatal("an entry whose extensions run past the list was accepted")
		}
	})

	t.Run("entry header truncated", func(t *testing.T) {
		entries := append(entry(der, 0, nil), 0x00, 0x00) // two stray bytes
		if _, err := parseCertificate(message(entries)); err == nil {
			t.Fatal("a truncated trailing entry was accepted")
		}
	})

	t.Run("missing extensions field", func(t *testing.T) {
		e := []byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}
		e = append(e, der...)
		if _, err := parseCertificate(message(e)); err == nil {
			t.Fatal("an entry with no extensions field was accepted")
		}
	})
}

// requireAlert asserts that err carries the expected alert description.
func requireAlert(t *testing.T, err error, want uint8) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a failure carrying %s, got nil", alertName(want))
	}
	if got := alertDescFor(err); got != want {
		t.Fatalf("alert = %s, want %s (error: %v)", alertName(got), alertName(want), err)
	}
}

// errFrom drops the value half of a (T, error) pair so it can be asserted on
// inline.
func errFrom[T any](_ T, err error) error { return err }

// TestClientHelloSessionIDReadBack checks the accessor the echo test depends on:
// it must return the same 32 bytes the builder put on the wire, for both
// profiles, and reject a message it cannot parse.
func TestClientHelloSessionIDReadBack(t *testing.T) {
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}

	for name, build := range map[string]func(string, []string, *keyMaterial) ([]byte, error){
		"chrome": func(sn string, alpn []string, km *keyMaterial) ([]byte, error) {
			return buildChromeClientHello(sn, alpn, km, nil)
		},
		"safari": buildSafariClientHello,
	} {
		t.Run(name, func(t *testing.T) {
			ch, err := build("example.com", []string{"h2"}, km)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			id, err := clientHelloSessionID(ch)
			if err != nil {
				t.Fatalf("clientHelloSessionID: %v", err)
			}
			if len(id) != 32 {
				t.Fatalf("session id is %d bytes, want 32", len(id))
			}
			// The bytes must be the ones at the documented offset, not a
			// coincidentally 32-byte slice from somewhere else.
			if !bytes.Equal(id, ch[4+2+32+1:4+2+32+1+32]) {
				t.Fatal("session id does not match the message layout")
			}
		})
	}

	for name, msg := range map[string][]byte{
		"empty":          nil,
		"wrong type":     {handshakeTypeServerHello, 0, 0, 0},
		"truncated":      {handshakeTypeClientHello, 0, 0, 4, 0x03, 0x03},
		"id runs past":   append([]byte{handshakeTypeClientHello, 0, 0, 35, 0x03, 0x03}, append(make([]byte, 32), 0xFF)...),
		"no id byte yet": append([]byte{handshakeTypeClientHello, 0, 0, 34, 0x03, 0x03}, make([]byte, 32)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := clientHelloSessionID(msg); err == nil {
				t.Fatal("malformed ClientHello accepted")
			}
		})
	}
}
