package ctls

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"time"
)

// Chrome ClientHello builder.
//
// Verified against a real Chrome 150 on Windows via tls.peet.ws:
//
//	JA4: t13d1516h2_8daaf6152771_806a8c22fdea
//
// chrome_hello_test.go pins that, along with the sorted extension list the
// device reports in ja4_r, which this builder reproduces exactly.
//
// There is deliberately no reference JA3 here. Chrome permutes its extension
// order on every connection (see buildChromeExtensions), and JA3 hashes the
// extension list in wire order, so a Chrome JA3 is a different value per
// connection by design. JA4 sorts before hashing and is therefore stable.
//
// A fresh connection emits 16 counted extensions; the device confirms 16.
// A resumed one carries pre_shared_key (0x0029) as a 17th and hashes to
// t13d1517h2_8daaf6152771_a87ad97598a9 — see TestResumedChromeHelloAddsOnlyPSK,
// which derives that value rather than assuming it.
//
// An earlier revision documented the resumed hash as
// t13d1517h2_8daaf6152771_b6f405a00624. That capture predates the ML-DSA
// signature algorithms: it is this same extension set resumed, hashed with the
// Chrome 146 sig-alg list, and it no longer describes this profile.
//
// Key differences from Safari on iPhone:
//   - 15 cipher suites, no 3DES and no ECDSA-CBC legacy suites, and the TLS 1.3
//     suites lead with AES-128-GCM where Apple leads with AES-256-GCM
//   - Extension order is shuffled per connection (see buildChromeExtensions)
//   - 4 supported groups incl. post-quantum, no P-521 (Safari offers P-521)
//   - 11 signature algorithms led by ML-DSA, no SHA1; Safari sends 10 with SHA1
//     last and a repeated rsa_pss_rsae_sha384
//   - Only brotli for compress_certificate vs Safari's zlib
//   - Has ALPS (17613), ECH GREASE (65037) and session_ticket (35); Safari has none
//   - Pseudo-header order: m,a,s,p
//
// Both profiles carry an X25519MLKEM768 + X25519 key_share and send no padding.

// buildChromeClientHello builds the Chrome ClientHello handshake message.
func buildChromeClientHello(serverName string, alpn []string, km *keyMaterial, sess *Session) ([]byte, error) {
	gs := newGreaseSet()

	exts, err := buildChromeExtensions(serverName, alpn, km, gs, sess)
	if err != nil {
		return nil, err
	}

	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}

	var sessionID [32]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, err
	}

	body := make([]byte, 0, 512+len(exts))

	// Legacy version: TLS 1.2
	body = appendUint16(body, versionTLS12)

	// Random
	body = append(body, random[:]...)

	// Session ID (32 bytes)
	body = append(body, 32)
	body = append(body, sessionID[:]...)

	// Cipher suites: GREASE + chromeCipherSuites
	cipherCount := 1 + len(chromeCipherSuites) // +1 for GREASE
	body = appendUint16(body, uint16(cipherCount*2))
	body = appendUint16(body, gs.cipher) // GREASE cipher
	for _, cs := range chromeCipherSuites {
		body = appendUint16(body, cs)
	}

	// Compression methods: null only
	body = append(body, 1, 0x00)

	// Extensions
	body = appendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	// Wrap in handshake header
	msg := make([]byte, 4+len(body))
	msg[0] = handshakeTypeClientHello
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)

	return msg, nil
}

// chromeExt is one extension entry pending serialization.
type chromeExt struct {
	typ  uint16
	data []byte
}

// buildChromeExtensions builds all TLS extensions for Chrome 146, with the
// middle block shuffled per ClientHello.
//
// Real Chrome (BoringSSL tls_extension_permutation_enabled, default-on since
// 110) randomizes extension order on every connection so each request emits a
// different JA3 hash. A fixed order produces zero JA3 entropy across
// connections, which Cloudflare/Akamai score as a strong bot signal. JA4 is
// unaffected — it sorts extensions before hashing.
func buildChromeExtensions(serverName string, alpn []string, km *keyMaterial, gs greaseSet, sess *Session) ([]byte, error) {
	keyShareData, err := buildChromeKeyShare(km, gs)
	if err != nil {
		return nil, err
	}
	echGrease, err := buildECHGrease()
	if err != nil {
		return nil, err
	}

	middle := []chromeExt{
		{extPSKKeyExchangeModes, []byte{1, pskModePSKDHE}},
		{extECPointFormats, []byte{1, 0x00}},
		{extKeyShare, keyShareData},
		{extCompressCertificate, []byte{0x02, 0x00, 0x02}}, // brotli only
		{extExtendedMasterSecret, nil},
		{extSupportedVersions, buildChromeSupportedVersions(gs)},
		{extSCT, nil},
		{extRenegotiationInfo, []byte{0x00}},
		{extALPN, buildALPN(alpn)},
		{extServerName, buildSNI(serverName)},
		{extSupportedGroups, buildChromeSupportedGroups(gs)},
		{extALPS, buildALPS(alpsProtocols)},
		{extSignatureAlgorithms, buildChromeSigAlgs()},
		{extECH, echGrease},
		{extStatusRequest, buildStatusRequest()},
		{extSessionTicket, nil},
	}
	if err := shuffleChromeExts(middle); err != nil {
		return nil, err
	}

	var out []byte
	// First GREASE: pinned at index 0.
	out = appendExt(out, gs.extFirst, []byte{0x00})
	for _, e := range middle {
		out = appendExt(out, e.typ, e.data)
	}
	// Last GREASE: pinned at the end — except on a resumed session, where
	// RFC 8446 §4.2.11 requires pre_shared_key to be the final extension and
	// it therefore follows the GREASE.
	out = appendExt(out, gs.extLast, []byte{0x00})

	if sess != nil {
		out = appendExt(out, extPreSharedKey, buildPSKExtension(sess, time.Now()))
	}

	return out, nil
}

// shuffleChromeExts shuffles s in place using crypto/rand (Fisher-Yates).
func shuffleChromeExts(s []chromeExt) error {
	for i := len(s) - 1; i > 0; i-- {
		bn, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := int(bn.Int64())
		s[i], s[j] = s[j], s[i]
	}
	return nil
}

// buildChromeKeyShare builds key_share with GREASE + X25519MLKEM768 + X25519.
func buildChromeKeyShare(km *keyMaterial, gs greaseSet) ([]byte, error) {
	x25519PubBytes := km.x25519Priv.PublicKey().Bytes()

	// X25519MLKEM768: mlkem768_pub (1184) + x25519_pub (32) = 1216 bytes
	mlkemShare := make([]byte, 0, len(km.mlkemPub)+32)
	mlkemShare = append(mlkemShare, km.mlkemPub...)
	mlkemShare = append(mlkemShare, x25519PubBytes...)

	// X25519: 32 bytes
	x25519Share := x25519PubBytes

	// GREASE key share: 1 byte of 0x00
	greaseShare := []byte{0x00}

	sharesLen := 2 + 2 + len(greaseShare) + // GREASE entry
		2 + 2 + len(mlkemShare) + // X25519MLKEM768 entry
		2 + 2 + len(x25519Share) // X25519 entry

	data := make([]byte, 2+sharesLen)
	binary.BigEndian.PutUint16(data[0:], uint16(sharesLen))

	offset := 2

	// GREASE key share entry
	binary.BigEndian.PutUint16(data[offset:], gs.keyShare)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(greaseShare)))
	offset += 2
	copy(data[offset:], greaseShare)
	offset += len(greaseShare)

	// X25519MLKEM768 entry
	binary.BigEndian.PutUint16(data[offset:], groupX25519MLKEM768)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(mlkemShare)))
	offset += 2
	copy(data[offset:], mlkemShare)
	offset += len(mlkemShare)

	// X25519 entry
	binary.BigEndian.PutUint16(data[offset:], groupX25519)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(x25519Share)))
	offset += 2
	copy(data[offset:], x25519Share)

	return data, nil
}

// buildChromeSupportedGroups: GREASE + X25519MLKEM768 + X25519 + P-256 + P-384
func buildChromeSupportedGroups(gs greaseSet) []byte {
	groups := []uint16{
		gs.group,
		groupX25519MLKEM768,
		groupX25519,
		groupP256,
		groupP384,
	}
	data := make([]byte, 2+len(groups)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(groups)*2))
	for i, g := range groups {
		binary.BigEndian.PutUint16(data[2+i*2:], g)
	}
	return data
}

// buildChromeSupportedVersions: GREASE + TLS 1.3 + TLS 1.2
func buildChromeSupportedVersions(gs greaseSet) []byte {
	return []byte{
		0x06,                                    // list length: 6 bytes (3 versions)
		byte(gs.version >> 8), byte(gs.version), // GREASE
		0x03, 0x04, // TLS 1.3
		0x03, 0x03, // TLS 1.2
	}
}

// buildChromeSigAlgs builds Chrome 146 signature algorithms.
func buildChromeSigAlgs() []byte {
	algs := chromeSigAlgs
	data := make([]byte, 2+len(algs)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(algs)*2))
	for i, a := range algs {
		binary.BigEndian.PutUint16(data[2+i*2:], a)
	}
	return data
}

// alpsProtocols is the protocol list Chrome advertises in application_settings.
//
// ALPS is only defined over HTTP/2, so Chrome lists h2 alone here even though
// its ALPN offers h2 and http/1.1. An earlier revision reused the full ALPN
// list, putting an http/1.1 entry on the wire that no real Chrome sends.
var alpsProtocols = []string{"h2"}

// buildALPS builds the application_settings (ALPS) extension.
func buildALPS(alpn []string) []byte {
	// ALPS format: protocol_list_length(2) + [ length(1) + protocol ... ]
	total := 0
	for _, proto := range alpn {
		total += 1 + len(proto)
	}
	data := make([]byte, 2+total)
	binary.BigEndian.PutUint16(data[0:], uint16(total))
	offset := 2
	for _, proto := range alpn {
		data[offset] = byte(len(proto))
		copy(data[offset+1:], proto)
		offset += 1 + len(proto)
	}
	return data
}
