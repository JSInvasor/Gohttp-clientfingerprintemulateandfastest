package ctls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startCurveRestrictedServer runs a crypto/tls 1.3 server that will only do key
// exchange over curves. Because both profiles put key shares on the wire for
// X25519MLKEM768 and X25519 only, a server restricted to anything else has to
// answer with a HelloRetryRequest — which is exactly the flight under test.
func startCurveRestrictedServer(t *testing.T, cert *x509.Certificate, key crypto.PrivateKey, curves []tls.CurveID, reply string) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	cfg := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
		NextProtos:       []string{"h2", "http/1.1"},
	}

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc := tls.Server(raw, cfg)
				defer sc.Close()
				if err := sc.Handshake(); err != nil {
					return
				}
				sc.Write([]byte(reply))
			}()
		}
	}()
	return ln.Addr()
}

// TestHelloRetryRequestEndToEnd is the whole point of the retry path: a server
// that cannot use either key share we sent must still complete the handshake.
//
// Every case here failed outright before HelloRetryRequest was implemented,
// with "server sent HelloRetryRequest: no offered key share was acceptable".
func TestHelloRetryRequestEndToEnd(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "localhost", key)
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	cases := []struct {
		name    string
		curve   tls.CurveID
		browser BrowserType
	}{
		{"chrome/P-256", tls.CurveP256, BrowserChrome},
		{"chrome/P-384", tls.CurveP384, BrowserChrome},
		{"safari/P-256", tls.CurveP256, BrowserSafari},
		{"safari/P-384", tls.CurveP384, BrowserSafari},
		// P-521 is in Safari's supported_groups but not Chrome's, so only the
		// Safari profile can legally answer a retry that asks for it.
		{"safari/P-521", tls.CurveP521, BrowserSafari},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := startCurveRestrictedServer(t, cert, key, []tls.CurveID{tc.curve}, "retried")

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			raw, err := net.Dial("tcp", addr.String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			conn, err := WrapConn(ctx, raw, "localhost", []string{"h2", "http/1.1"}, false, roots, tc.browser)
			if err != nil {
				t.Fatalf("handshake through HelloRetryRequest failed: %v", err)
			}
			defer conn.Close()

			// A completed handshake is not enough on its own: if the transcript
			// had been assembled wrongly the Finished MAC would have failed, but
			// reading real application data proves the traffic keys agree too.
			got, err := io.ReadAll(conn)
			if err != nil && err != io.EOF {
				t.Fatalf("read: %v", err)
			}
			if string(got) != "retried" {
				t.Fatalf("payload = %q, want %q", got, "retried")
			}
			if conn.NegotiatedProtocol() != "h2" {
				t.Fatalf("ALPN = %q, want h2", conn.NegotiatedProtocol())
			}
		})
	}
}

// TestNoHelloRetryRequestWhenShareUsable is the control: against a server that
// accepts a group we preemptively keyed, no retry happens at all. Without this,
// a bug that made every handshake take the retry path would still look green.
func TestNoHelloRetryRequestWhenShareUsable(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "localhost", key)
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	addr := startCurveRestrictedServer(t, cert, key, []tls.CurveID{tls.X25519}, "direct")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	raw, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := WrapConn(ctx, raw, "localhost", []string{"h2"}, false, roots, BrowserChrome)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	got, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "direct" {
		t.Fatalf("payload = %q, want %q", got, "direct")
	}
}

// recordingConn captures the type and legacy_record_version of every record the
// client writes.
type recordingConn struct {
	net.Conn
	records []struct {
		typ     uint8
		version uint16
	}
}

func (r *recordingConn) Write(b []byte) (int, error) {
	// The client writes one whole record per Write, so no reassembly is needed.
	if len(b) >= recordHeaderLen {
		r.records = append(r.records, struct {
			typ     uint8
			version uint16
		}{b[0], binary.BigEndian.Uint16(b[1:])})
	}
	return r.Conn.Write(b)
}

// TestRetryRecordVersions pins RFC 8446 §5.1's legacy_record_version rule
// across a retried handshake.
//
// Only an initial ClientHello may carry 0x0301; everything else, the second
// ClientHello included, must be 0x0303. Writing 0x0301 on every handshake
// record looks harmless because the retry flight is the only place the two
// differ — and there it is fatal. Go's server answers such a second hello with
// "received record with version 301 when expecting version 303", which reaches
// the client as an opaque protocol_version alert.
func TestRetryRecordVersions(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := newTestCert(t, "localhost", key)
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	addr := startCurveRestrictedServer(t, cert, key, []tls.CurveID{tls.CurveP256}, "x")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	raw, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	rec := &recordingConn{Conn: raw}
	conn, err := WrapConn(ctx, rec, "localhost", []string{"h2"}, false, roots, BrowserChrome)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	var handshakeRecords []uint16
	var sawCCS int
	for _, r := range rec.records {
		switch r.typ {
		case recordTypeHandshake:
			handshakeRecords = append(handshakeRecords, r.version)
		case recordTypeChangeCipherSpec:
			sawCCS++
			if r.version != versionTLS12 {
				t.Fatalf("ChangeCipherSpec record version = 0x%04x, want 0x0303", r.version)
			}
		case recordTypeApplicationData:
			if r.version != versionTLS12 {
				t.Fatalf("encrypted record version = 0x%04x, want 0x0303", r.version)
			}
		}
	}

	if len(handshakeRecords) != 2 {
		t.Fatalf("wrote %d plaintext handshake records, want 2 (both ClientHellos)", len(handshakeRecords))
	}
	if handshakeRecords[0] != versionTLS10 {
		t.Fatalf("initial ClientHello record version = 0x%04x, want 0x0301", handshakeRecords[0])
	}
	if handshakeRecords[1] != versionTLS12 {
		t.Fatalf("second ClientHello record version = 0x%04x, want 0x0303", handshakeRecords[1])
	}

	// Appendix D.4 puts exactly one dummy ChangeCipherSpec in the flight, and a
	// retried handshake spends it before the second ClientHello rather than
	// before Finished.
	if sawCCS != 1 {
		t.Fatalf("sent %d ChangeCipherSpec records, want 1", sawCCS)
	}
}

// newRetryState builds a handshakeState holding a freshly built ClientHello,
// which is what the retry rewrite operates on.
func newRetryState(t *testing.T, browser BrowserType) *handshakeState {
	t.Helper()
	km, err := generateKeyMaterial()
	if err != nil {
		t.Fatalf("generateKeyMaterial: %v", err)
	}
	build := buildSafariClientHello
	if browser == BrowserChrome {
		build = buildChromeClientHello
	}
	ch, err := build("example.com", []string{"h2", "http/1.1"}, km)
	if err != nil {
		t.Fatalf("build client hello: %v", err)
	}
	return &handshakeState{km: km, serverName: "example.com", browser: browser, clientHelloMsg: ch}
}

// TestRetryClientHelloSubstitutesOnlyKeyShare pins RFC 8446 §4.1.2: the second
// ClientHello must be the first one unmodified except for the substitutions the
// spec lists. Rebuilding a hello from scratch would redraw GREASE and reshuffle
// Chrome's extension order, which a server comparing the two may reject — and
// would change the fingerprint mid-handshake.
func TestRetryClientHelloSubstitutesOnlyKeyShare(t *testing.T) {
	for _, browser := range []BrowserType{BrowserChrome, BrowserSafari} {
		hs := newRetryState(t, browser)
		ch1 := append([]byte(nil), hs.clientHelloMsg...)

		ch2, err := hs.buildRetryClientHello(&helloRetryRequest{
			suite:         cipherTLS_AES_128_GCM_SHA256,
			selectedGroup: groupP256,
			hasGroup:      true,
			isTLS13:       true,
		})
		if err != nil {
			t.Fatalf("buildRetryClientHello: %v", err)
		}

		// Everything before the extension block — version, random, session id,
		// cipher suites, compression — must be byte-identical.
		start1, err := clientHelloExtensionsStart(ch1)
		if err != nil {
			t.Fatalf("clientHelloExtensionsStart(ch1): %v", err)
		}
		start2, err := clientHelloExtensionsStart(ch2)
		if err != nil {
			t.Fatalf("clientHelloExtensionsStart(ch2): %v", err)
		}
		// The prefix minus the 2-byte extension-block length.
		if !bytes.Equal(ch1[4:start1-2], ch2[4:start2-2]) {
			t.Fatal("retry hello changed the ClientHello prefix")
		}

		p1, err := parseClientHello(ch1)
		if err != nil {
			t.Fatalf("parseClientHello(ch1): %v", err)
		}
		p2, err := parseClientHello(ch2)
		if err != nil {
			t.Fatalf("parseClientHello(ch2): %v", err)
		}

		// Extension types, in wire order, must be untouched.
		if len(p1.extTypes) != len(p2.extTypes) {
			t.Fatalf("extension count changed: %d -> %d", len(p1.extTypes), len(p2.extTypes))
		}
		for i := range p1.extTypes {
			if p1.extTypes[i] != p2.extTypes[i] {
				t.Fatalf("extension order changed at %d: 0x%04x -> 0x%04x",
					i, p1.extTypes[i], p2.extTypes[i])
			}
		}
		// supported_groups is not one of the permitted substitutions.
		if len(p1.groups) != len(p2.groups) {
			t.Fatalf("supported_groups changed: %v -> %v", p1.groups, p2.groups)
		}
		for i := range p1.groups {
			if p1.groups[i] != p2.groups[i] {
				t.Fatalf("supported_groups changed: %v -> %v", p1.groups, p2.groups)
			}
		}

		// key_share is the one thing that must change, to exactly one entry —
		// §4.2.8 says "containing only a new KeyShareEntry", so the GREASE entry
		// goes with the rest.
		if len(p2.keyShareGroups) != 1 || p2.keyShareGroups[0] != groupP256 {
			t.Fatalf("retry key_share = %v, want exactly [P-256]", p2.keyShareGroups)
		}
	}
}

// TestRetryClientHelloEchoesCookie covers RFC 8446 §4.2.2, which requires the
// cookie from the HelloRetryRequest to be copied verbatim into the new hello.
// Servers that keep no per-connection state put their entire retry context in
// there, so dropping it fails the handshake on exactly the stateless edges most
// likely to send a retry in the first place.
func TestRetryClientHelloEchoesCookie(t *testing.T) {
	hs := newRetryState(t, BrowserChrome)

	cookieBody := []byte("opaque-server-state")
	cookie := binary.BigEndian.AppendUint16(nil, uint16(len(cookieBody)))
	cookie = append(cookie, cookieBody...)

	ch2, err := hs.buildRetryClientHello(&helloRetryRequest{
		suite:         cipherTLS_AES_128_GCM_SHA256,
		selectedGroup: groupP256,
		hasGroup:      true,
		cookie:        cookie,
		isTLS13:       true,
	})
	if err != nil {
		t.Fatalf("buildRetryClientHello: %v", err)
	}

	got, ok := findExtension(ch2, extCookie)
	if !ok {
		t.Fatal("retry hello dropped the cookie")
	}
	if !bytes.Equal(got, cookie) {
		t.Fatalf("cookie = %x, want %x", got, cookie)
	}

	// pre_shared_key aside — which this package never sends — the trailing
	// GREASE extension is the profile's last one, and inserting the cookie must
	// not have displaced it.
	p, err := parseClientHello(ch2)
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	if last := p.extTypes[len(p.extTypes)-1]; !isGreaseValue(last) {
		t.Fatalf("last extension is 0x%04x, want the trailing GREASE", last)
	}
}

// TestRetryECHHasEmptyEnc covers the ECH spec's carve-out from §4.1.2's
// "resend the same hello": the second ClientHelloOuter repeats config_id,
// cipher suite and payload length but empties enc, because the first hello
// already established the HPKE context. Everything else about the extension has
// to survive untouched.
func TestRetryECHHasEmptyEnc(t *testing.T) {
	hs := newRetryState(t, BrowserChrome)

	ch1ECH, ok := findExtension(hs.clientHelloMsg, extECH)
	if !ok {
		t.Fatal("Chrome hello has no encrypted_client_hello to retry")
	}

	ch2, err := hs.buildRetryClientHello(&helloRetryRequest{
		suite:         cipherTLS_AES_128_GCM_SHA256,
		selectedGroup: groupP256,
		hasGroup:      true,
		isTLS13:       true,
	})
	if err != nil {
		t.Fatalf("buildRetryClientHello: %v", err)
	}
	ch2ECH, ok := findExtension(ch2, extECH)
	if !ok {
		t.Fatal("retry hello dropped encrypted_client_hello")
	}

	const headerLen = 1 + 2 + 2 + 1 // type, kdf_id, aead_id, config_id
	if !bytes.Equal(ch1ECH[:headerLen], ch2ECH[:headerLen]) {
		t.Fatalf("ECH header changed: %x -> %x", ch1ECH[:headerLen], ch2ECH[:headerLen])
	}
	if encLen := binary.BigEndian.Uint16(ch2ECH[headerLen:]); encLen != 0 {
		t.Fatalf("retry ECH enc is %d bytes, want empty", encLen)
	}

	// Payload length and bytes must both carry over.
	ch1EncLen := int(binary.BigEndian.Uint16(ch1ECH[headerLen:]))
	ch1Payload := ch1ECH[headerLen+2+ch1EncLen:]
	ch2Payload := ch2ECH[headerLen+2:]
	if !bytes.Equal(ch1Payload, ch2Payload) {
		t.Fatal("retry ECH payload changed")
	}
}

// TestEchGreaseForRetryRejectsMalformed keeps the rewrite from slicing out of
// range. It only ever parses an extension this package built, but that is one
// refactor away from being untrue.
func TestEchGreaseForRetryRejectsMalformed(t *testing.T) {
	good, err := buildECHGrease()
	if err != nil {
		t.Fatalf("buildECHGrease: %v", err)
	}

	cases := map[string][]byte{
		"empty":            {},
		"header only":      good[:6],
		"enc overruns":     append(append([]byte{}, good[:6]...), 0xFF, 0xFF),
		"payload overruns": func() []byte { b := append([]byte(nil), good...); b[40], b[41] = 0xFF, 0xFF; return b }(),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			if _, err := echGreaseForRetry(data); err == nil {
				t.Fatal("malformed encrypted_client_hello accepted")
			}
		})
	}
}

// TestRetryGroupValidation pins the two limits RFC 8446 §4.1.4 puts on the
// selected group. Both exist to stop a server steering the client into an
// endless retry loop or onto a curve it never agreed to.
func TestRetryGroupValidation(t *testing.T) {
	chrome := newRetryState(t, BrowserChrome)
	safari := newRetryState(t, BrowserSafari)

	cases := []struct {
		name    string
		hs      *handshakeState
		group   uint16
		wantErr string
	}{
		{"already offered x25519", chrome, groupX25519, "already sent"},
		{"already offered mlkem", chrome, groupX25519MLKEM768, "already sent"},
		// P-521 is Safari-only; Chrome never advertises it.
		{"not advertised by chrome", chrome, groupP521, "not offered"},
		{"unadvertised group", chrome, 0x1234, "not offered"},
		{"p256 is fine for chrome", chrome, groupP256, ""},
		{"p384 is fine for chrome", chrome, groupP384, ""},
		{"p521 is fine for safari", safari, groupP521, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.hs.checkRetryGroup(tc.group)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("group 0x%04x rejected: %v", tc.group, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("group 0x%04x accepted, want %q", tc.group, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestHelloRetryRequestRejectsNoChange covers the degenerate retry: a
// HelloRetryRequest carrying neither a new group nor a cookie asks the client to
// resend the identical hello, which can only loop.
func TestHelloRetryRequestRejectsNoChange(t *testing.T) {
	tls13 := tlsExt(extSupportedVersions, binary.BigEndian.AppendUint16(nil, versionTLS13))
	msg := serverHelloBytes(helloRetryRequestRandom, nil, cipherTLS_AES_128_GCM_SHA256, tls13)

	sh, err := parseServerHelloShell(msg)
	if err != nil {
		t.Fatalf("parseServerHelloShell: %v", err)
	}
	if _, err := parseHelloRetryRequest(sh); err == nil {
		t.Fatal("a HelloRetryRequest asking for no change was accepted")
	}
}

// TestHelloRetryRequestRequiresTLS13 rejects a retry that does not select
// TLS 1.3: this package speaks nothing else, and continuing would derive keys
// under a version the server never agreed to.
func TestHelloRetryRequestRequiresTLS13(t *testing.T) {
	keyShare := tlsExt(extKeyShare, []byte{0x00, 0x17})
	msg := serverHelloBytes(helloRetryRequestRandom, nil, cipherTLS_AES_128_GCM_SHA256, keyShare)

	sh, err := parseServerHelloShell(msg)
	if err != nil {
		t.Fatalf("parseServerHelloShell: %v", err)
	}
	if _, err := parseHelloRetryRequest(sh); err == nil {
		t.Fatal("a HelloRetryRequest without supported_versions was accepted")
	}
}

// TestMessageHashMessage pins the synthetic message RFC 8446 §4.4.1 substitutes
// for ClientHello1 once a retry has happened. Getting its framing wrong desyncs
// the transcript, which surfaces much later as a Finished MAC mismatch.
func TestMessageHashMessage(t *testing.T) {
	sum := bytes.Repeat([]byte{0xAB}, 32)
	msg := messageHashMessage(sum)

	if msg[0] != handshakeTypeMessageHash {
		t.Fatalf("type = %d, want 254", msg[0])
	}
	gotLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if gotLen != len(sum) {
		t.Fatalf("length = %d, want %d", gotLen, len(sum))
	}
	if !bytes.Equal(msg[4:], sum) {
		t.Fatal("digest not copied verbatim")
	}
}

// TestClientHelloExtensionsStartRejectsMalformed keeps the rewrite helper from
// slicing out of range on a hello it did not build. It only ever sees our own
// message today, but it is the parser a future caller would reach for.
func TestClientHelloExtensionsStartRejectsMalformed(t *testing.T) {
	hs := newRetryState(t, BrowserChrome)
	good := hs.clientHelloMsg

	cases := map[string][]byte{
		"empty":            {},
		"header only":      {handshakeTypeClientHello, 0, 0, 0},
		"wrong type":       append([]byte{handshakeTypeServerHello}, good[1:]...),
		"truncated":        good[:len(good)/2],
		"body len too big": func() []byte { b := append([]byte(nil), good...); b[1] = 0xFF; return b }(),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			if _, err := clientHelloExtensionsStart(data); err == nil {
				t.Fatal("malformed ClientHello accepted")
			}
		})
	}
}
