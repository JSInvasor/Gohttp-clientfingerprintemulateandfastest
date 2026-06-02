package ctls

import (
	"crypto/rand"
	"encoding/binary"
)

// greaseSet holds the GREASE values used at the six positions Safari sprinkles
// them into a single ClientHello. A fresh set is drawn per connection.
type greaseSet struct {
	cipher   uint16 // GREASE in cipher suite list
	extFirst uint16 // GREASE as first extension
	extLast  uint16 // GREASE as second-to-last extension
	keyShare uint16 // GREASE in key_share
	group    uint16 // GREASE in supported_groups
	version  uint16 // GREASE in supported_versions
}

func randomGrease() uint16 {
	var b [1]byte
	rand.Read(b[:])
	return greaseValues[int(b[0])%len(greaseValues)]
}

func newGreaseSet() greaseSet {
	return greaseSet{
		cipher:   randomGrease(),
		extFirst: randomGrease(),
		extLast:  randomGrease(),
		keyShare: randomGrease(),
		group:    randomGrease(),
		version:  randomGrease(),
	}
}

// Safari iOS 18.7 ClientHello builder.
//
// NOTE: JA3/JA4 below are stale — they were captured before the sigalg-dedup
// and TLS-1.0/1.1 removal. The current ClientHello (9 unique sigalgs, only
// TLS 1.3/1.2) matches a real iOS 18 device and produces a different hash;
// re-capture on tls.peet.ws to refresh. JA3: 773906b0efdefa24a7f2b8eb6985bf37
// / JA4: t13d2014h2_a09f3c656075_7f0f34a4126d (PRE-FIX, do not trust).
//
// Key differences from Firefox 148 and Chrome 146:
//   - 21 cipher suites including 3DES and CBC legacy ciphers
//   - GREASE in ciphers, extensions, supported_groups, supported_versions, key_share
//   - Only zlib for compress_certificate (not brotli/zstd)
//   - Has extended_master_secret, renegotiation_info, ec_point_formats
//   - supported_versions: GREASE + TLS 1.3 + TLS 1.2 only
//     (Apple removed TLS 1.0/1.1 in iOS 13; iOS 18 does NOT advertise them)
//   - Only X25519 key share (no P-256, no post-quantum)
//   - 5 supported groups including P-521 (Chrome only has 4)
//   - 9 unique signature algorithms (incl. sha1 for legacy server compat)
//   - Has padding extension to reach 512-byte ClientHello
//   - No ALPS, no ECH, no delegated_credentials, no record_size_limit
//   - Pseudo-header order: m,s,a,p (unique to Safari)

// Safari-specific cipher suites (3DES legacy ciphers)
const (
	cipherTLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008
	cipherTLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA   = 0xC012
	cipherTLS_RSA_WITH_3DES_EDE_CBC_SHA          = 0x000A
)

// Safari iOS 18 cipher suite order (20 suites; a GREASE value is prepended at
// build time for 21 on the wire)
var safariIOS18CipherSuites = []uint16{
	cipherTLS_AES_128_GCM_SHA256,                     // 0x1301
	cipherTLS_AES_256_GCM_SHA384,                     // 0x1302
	cipherTLS_CHACHA20_POLY1305_SHA256,               // 0x1303
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,   // 0xC02C
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,   // 0xC02B
	cipherTLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,    // 0xCCA9
	cipherTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,     // 0xC030
	cipherTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,     // 0xC02F
	cipherTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,      // 0xCCA8
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,      // 0xC00A
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,      // 0xC009
	cipherTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,        // 0xC014
	cipherTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,        // 0xC013
	cipherTLS_RSA_WITH_AES_256_GCM_SHA384,           // 0x009D
	cipherTLS_RSA_WITH_AES_128_GCM_SHA256,           // 0x009C
	cipherTLS_RSA_WITH_AES_256_CBC_SHA,              // 0x0035
	cipherTLS_RSA_WITH_AES_128_CBC_SHA,              // 0x002F
	cipherTLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,    // 0xC008
	cipherTLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,      // 0xC012
	cipherTLS_RSA_WITH_3DES_EDE_CBC_SHA,             // 0x000A
}

// Safari iOS 18 signature algorithms (9 unique algos including SHA1 fallback).
// Real iOS 18 Safari sends each sigalg exactly once. An older version of this
// profile carried a duplicate 0x0805 (rsa_pss_rsae_sha384) based on a stale
// capture; tls.peet.ws verification against a real iPhone 18 showed 9 unique
// values, so the duplicate is removed. Keeping it produces a JA4_r/peetprint
// hash that doesn't match any real Safari and makes the fingerprint uniquely
// identifiable.
var safariIOS18SigAlgs = []uint16{
	0x0403, // ecdsa_secp256r1_sha256
	0x0804, // rsa_pss_rsae_sha256
	0x0401, // rsa_pkcs1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0805, // rsa_pss_rsae_sha384
	0x0501, // rsa_pkcs1_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0601, // rsa_pkcs1_sha512
	0x0201, // rsa_pkcs1_sha1
}

// buildSafariClientHello builds the Safari iOS 18 ClientHello handshake message.
func buildSafariClientHello(serverName string, alpn []string, km *keyMaterial) ([]byte, error) {
	gs := newGreaseSet()

	exts, err := buildSafariExtensions(serverName, alpn, km, gs)
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

	// Cipher suites: GREASE + safariIOS18CipherSuites
	cipherCount := 1 + len(safariIOS18CipherSuites) // +1 for GREASE
	body = appendUint16(body, uint16(cipherCount*2))
	body = appendUint16(body, gs.cipher) // GREASE cipher
	for _, cs := range safariIOS18CipherSuites {
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

// buildSafariExtensions builds all TLS extensions in exact Safari iOS 18 order.
// Order from tls.peet.ws capture:
//  1. GREASE (0xdada)
//  2. server_name (0)
//  3. extended_master_secret (23)
//  4. renegotiation_info (65281)
//  5. supported_groups (10)
//  6. ec_point_formats (11)
//  7. application_layer_protocol_negotiation (16)
//  8. status_request (5)
//  9. signature_algorithms (13)
// 10. signed_certificate_timestamp (18)
// 11. key_share (51)
// 12. psk_key_exchange_modes (45)
// 13. supported_versions (43)
// 14. compress_certificate (27)
// 15. GREASE (0x9a9a)
// 16. padding (21)
func buildSafariExtensions(serverName string, alpn []string, km *keyMaterial, gs greaseSet) ([]byte, error) {
	var out []byte

	// 1. GREASE extension (empty)
	out = appendExt(out, gs.extFirst, nil)

	// 2. server_name (0)
	out = appendExt(out, extServerName, buildSNI(serverName))

	// 3. extended_master_secret (23) - empty
	out = appendExt(out, extExtendedMasterSecret, nil)

	// 4. renegotiation_info (65281) - empty renegotiated_connection
	out = appendExt(out, extRenegotiationInfo, []byte{0x00})

	// 5. supported_groups (10) - GREASE + X25519 + P-256 + P-384 + P-521
	out = appendExt(out, extSupportedGroups, buildSafariSupportedGroups(gs))

	// 6. ec_point_formats (11) - uncompressed
	out = appendExt(out, extECPointFormats, []byte{1, 0x00})

	// 7. ALPN (16)
	out = appendExt(out, extALPN, buildALPN(alpn))

	// 8. status_request (5) - OCSP stapling
	out = appendExt(out, extStatusRequest, buildStatusRequest())

	// 9. signature_algorithms (13)
	out = appendExt(out, extSignatureAlgorithms, buildSafariSigAlgs())

	// 10. signed_certificate_timestamp (18) - empty
	out = appendExt(out, extSCT, nil)

	// 11. key_share (51) - GREASE + X25519 only
	keyShareData := buildSafariKeyShare(km, gs)
	out = appendExt(out, extKeyShare, keyShareData)

	// 12. psk_key_exchange_modes (45) - psk_dhe_ke
	out = appendExt(out, extPSKKeyExchangeModes, []byte{1, pskModePSKDHE})

	// 13. supported_versions (43) - GREASE + TLS 1.3 + 1.2
	out = appendExt(out, extSupportedVersions, buildSafariSupportedVersions(gs))

	// 14. compress_certificate (27) - zlib only (Safari uses zlib, not brotli!)
	out = appendExt(out, extCompressCertificate, []byte{
		0x02,       // list length: 2 bytes
		0x00, 0x01, // zlib
	})

	// 15. GREASE extension (empty)
	out = appendExt(out, gs.extLast, nil)

	// 16. padding (21) - pad to target size
	// Safari pads the ClientHello to a consistent size.
	// Calculate how much padding we need to reach 512 bytes total.
	out = appendSafariPadding(out)

	return out, nil
}

// buildSafariKeyShare builds key_share with GREASE + X25519 only.
// Safari does NOT send post-quantum (MLKEM768) or P-256 key shares.
func buildSafariKeyShare(km *keyMaterial, gs greaseSet) []byte {
	x25519PubBytes := km.x25519Priv.PublicKey().Bytes()

	// GREASE: 1 byte
	greaseShare := []byte{0x00}
	// X25519: 32 bytes
	x25519Share := x25519PubBytes

	sharesLen := 2 + 2 + len(greaseShare) + // GREASE entry
		2 + 2 + len(x25519Share) // X25519 entry

	data := make([]byte, 2+sharesLen)
	binary.BigEndian.PutUint16(data[0:], uint16(sharesLen))

	offset := 2

	// GREASE key share
	binary.BigEndian.PutUint16(data[offset:], gs.keyShare)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(greaseShare)))
	offset += 2
	copy(data[offset:], greaseShare)
	offset += len(greaseShare)

	// X25519 key share
	binary.BigEndian.PutUint16(data[offset:], groupX25519)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(x25519Share)))
	offset += 2
	copy(data[offset:], x25519Share)

	return data
}

// buildSafariSupportedGroups: GREASE + X25519 + P-256 + P-384 + P-521
func buildSafariSupportedGroups(gs greaseSet) []byte {
	groups := []uint16{
		gs.group,
		groupX25519,
		groupP256,
		groupP384,
		groupP521,
	}
	data := make([]byte, 2+len(groups)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(groups)*2))
	for i, g := range groups {
		binary.BigEndian.PutUint16(data[2+i*2:], g)
	}
	return data
}

// buildSafariSupportedVersions: GREASE + TLS 1.3 + TLS 1.2.
// Apple deprecated TLS 1.0/1.1 in iOS 13 (2019); real iOS 18 Safari only
// advertises TLS 1.3 and TLS 1.2 in supported_versions. Advertising 1.0/1.1
// is a strong "non-Apple synthetic client" signal for CF/Akamai bot scoring.
func buildSafariSupportedVersions(gs greaseSet) []byte {
	return []byte{
		0x06, // list length: 6 bytes (3 versions)
		byte(gs.version >> 8), byte(gs.version), // GREASE
		0x03, 0x04, // TLS 1.3
		0x03, 0x03, // TLS 1.2
	}
}

// buildSafariSigAlgs builds Safari iOS 18 signature algorithms.
// 9 unique algorithms — see safariIOS18SigAlgs for why the old duplicate
// rsa_pss_rsae_sha384 entry was removed. The list length is computed from the
// slice, so the on-wire bytes track the slice automatically.
func buildSafariSigAlgs() []byte {
	algs := safariIOS18SigAlgs
	data := make([]byte, 2+len(algs)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(algs)*2))
	for i, a := range algs {
		binary.BigEndian.PutUint16(data[2+i*2:], a)
	}
	return data
}

// appendSafariPadding adds the padding extension (21) to reach target ClientHello size.
// Safari uses padding to make the ClientHello a consistent size.
func appendSafariPadding(extensions []byte) []byte {
	// The padding extension format: type(2) + length(2) + zeros(N)
	// We want the total extensions to result in a ~512-byte ClientHello.
	// Current extensions length + padding header (4 bytes) + padding data = target
	//
	// From the capture: padding_data_length was 394.
	// But this varies based on SNI length. We calculate dynamically.
	//
	// Target total ClientHello (without record/handshake headers):
	// 2(version) + 32(random) + 1+32(sessionID) + 2+42(ciphers) + 2(compression)
	// + 2(extensions_length) + extensions = ~512 target
	// Fixed part = 2+32+33+44+2+2 = 115 bytes
	// So extensions target = 512 - 115 = 397 bytes... but actual target varies.
	//
	// Simpler approach: pad extensions to a multiple of 512 minus overhead.
	// Real Safari targets differ; we use the captured padding of ~394 bytes
	// adjusted for our actual extension size.

	currentLen := len(extensions)
	// Target extensions size: make total ClientHello body ~512 bytes
	targetExtLen := 397 // approximate from captures
	if currentLen >= targetExtLen {
		// Already big enough, add minimal padding
		return appendExt(extensions, extPadding, nil)
	}

	paddingNeeded := targetExtLen - currentLen - 4 // 4 = ext header (type + length)
	if paddingNeeded < 0 {
		paddingNeeded = 0
	}

	padding := make([]byte, paddingNeeded)
	return appendExt(extensions, extPadding, padding)
}

// Padding extension type
const extPadding = 0x0015
