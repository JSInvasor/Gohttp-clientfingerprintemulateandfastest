package ctls

import (
	"crypto/rand"
	"encoding/binary"
)

// Safari (iPhone) ClientHello builder.
//
// Verified against tls.peet.ws using a real iPhone 13 running iOS 26.5.2
// (Safari 26.5.2). Reference values that this builder reproduces:
//
//	JA3:            771,4866-4867-4865-49196-49195-52393-49200-49199-52392-
//	                49162-49161-49172-49171-157-156-53-47-49160-49170-10,
//	                0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0
//	JA3 hash:       ecdf4f49dd59effc439639da29186671
//	JA4:            t13d2013h2_a09f3c656075_7f0f34a4126d
//	peetprint hash: 62b834de729e78a9f0ebd1dd099314a7
//
// safari_hello_test.go pins these, so a change that shifts the fingerprint
// fails the build instead of silently making the client trackable.
//
// The same fingerprint is emitted by every browser on iOS — Chrome (CriOS) and
// the Google app (GSA) were captured byte-identical here, because iOS forces
// all of them onto Apple's networking stack. Only the User-Agent differs.
//
// Key differences from Chrome 146:
//   - 21 cipher suites including 3DES and CBC legacy ciphers, and the TLS 1.3
//     suites lead with AES-256-GCM (0x1302) rather than AES-128-GCM
//   - GREASE in ciphers, extensions, supported_groups, supported_versions, key_share
//   - Only zlib for compress_certificate (not brotli)
//   - Has extended_master_secret, renegotiation_info, ec_point_formats
//   - supported_versions: GREASE + TLS 1.3 + TLS 1.2 only
//     (Apple removed TLS 1.0/1.1 in iOS 13 and still does not advertise them)
//   - 5 supported groups including P-521, which Chrome does not offer
//   - key_share carries X25519MLKEM768 + X25519 (Apple ships post-quantum)
//   - 10 signature algorithms, with 0x0805 repeated, and sha1 last
//   - No padding extension (see the note at the bottom of this file)
//   - No ALPS, no ECH, no session_ticket, no delegated_credentials
//   - Pseudo-header order: m,s,a,p (unique to Safari)

// Safari-specific cipher suites (3DES legacy ciphers)
const (
	cipherTLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008
	cipherTLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA   = 0xC012
	cipherTLS_RSA_WITH_3DES_EDE_CBC_SHA         = 0x000A
)

// Safari iOS 18 cipher suite order (20 suites; a GREASE value is prepended at
// build time for 21 on the wire)
//
// The TLS 1.3 suites lead with AES-256-GCM, not AES-128-GCM. Apple orders them
// 0x1302, 0x1303, 0x1301 — verified against a real device. JA4 sorts the cipher
// list before hashing so it cannot catch this, but JA3 is order-sensitive: the
// old 0x1301, 0x1302, 0x1303 order produced a JA3 that matched no real Safari.
var safariIOS18CipherSuites = []uint16{
	cipherTLS_AES_256_GCM_SHA384,                  // 0x1302
	cipherTLS_CHACHA20_POLY1305_SHA256,            // 0x1303
	cipherTLS_AES_128_GCM_SHA256,                  // 0x1301
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // 0xC02C
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // 0xC02B
	cipherTLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,  // 0xCCA9
	cipherTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,   // 0xC030
	cipherTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // 0xC02F
	cipherTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,    // 0xCCA8
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,    // 0xC00A
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,    // 0xC009
	cipherTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,      // 0xC014
	cipherTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,      // 0xC013
	cipherTLS_RSA_WITH_AES_256_GCM_SHA384,         // 0x009D
	cipherTLS_RSA_WITH_AES_128_GCM_SHA256,         // 0x009C
	cipherTLS_RSA_WITH_AES_256_CBC_SHA,            // 0x0035
	cipherTLS_RSA_WITH_AES_128_CBC_SHA,            // 0x002F
	cipherTLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,   // 0xC008
	cipherTLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,     // 0xC012
	cipherTLS_RSA_WITH_3DES_EDE_CBC_SHA,           // 0x000A
}

// Safari iOS signature algorithms — 10 entries, and 0x0805 genuinely appears
// TWICE.
//
// This duplicate is not a capture artifact. A tls.peet.ws capture from a real
// iPhone 13 on iOS 26.5.2 reports it in both ja4_r and peetprint:
//
//	ja4_r     ..._0403,0804,0401,0503,0805,0805,0501,0806,0601,0201
//	peetprint ...|1027-2052-1025-1283-2053-2053-1281-2054-1537-513|...
//
// An earlier revision "deduplicated" it on the theory that a real device sends
// each sigalg once. That was wrong and it broke the fingerprint: dropping the
// second 0x0805 changes JA4_c from 7f0f34a4126d (real) to 604f15001eed, which
// matches no shipping Safari and is therefore uniquely trackable. Do not
// deduplicate this list.
var safariIOS18SigAlgs = []uint16{
	0x0403, // ecdsa_secp256r1_sha256
	0x0804, // rsa_pss_rsae_sha256
	0x0401, // rsa_pkcs1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0805, // rsa_pss_rsae_sha384
	0x0805, // rsa_pss_rsae_sha384 (repeated on the wire — intentional)
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

// buildSafariExtensions builds all TLS extensions in exact Safari order.
// 15 extensions on the wire; 13 counted by JA4 once the two GREASE entries are
// dropped. Order from the tls.peet.ws capture:
//  1. GREASE
//  2. server_name (0)
//  3. extended_master_secret (23)
//  4. renegotiation_info (65281)
//  5. supported_groups (10)
//  6. ec_point_formats (11)
//  7. application_layer_protocol_negotiation (16)
//  8. status_request (5)
//  9. signature_algorithms (13)
//
// 10. signed_certificate_timestamp (18)
// 11. key_share (51)
// 12. psk_key_exchange_modes (45)
// 13. supported_versions (43)
// 14. compress_certificate (27)
// 15. GREASE
//
// Unlike Chrome this order is fixed — Apple does not permute extensions.
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

	// 5. supported_groups (10) - GREASE + X25519MLKEM768 + X25519 + P-256 + P-384 + P-521
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

	// 11. key_share (51) - GREASE + X25519MLKEM768 + X25519
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

	// 15. GREASE extension (empty) — final extension, no padding follows.
	out = appendExt(out, gs.extLast, nil)

	return out, nil
}

// buildSafariKeyShare builds key_share with GREASE + X25519MLKEM768 + X25519.
//
// Apple shipped post-quantum key agreement, so the key_share carries a real
// X25519MLKEM768 entry (ML-KEM-768 public key || X25519 public key) ahead of
// the classical X25519 entry. handshake.go's processServerKeyShare already
// decapsulates whichever of the two the server selects.
func buildSafariKeyShare(km *keyMaterial, gs greaseSet) []byte {
	x25519PubBytes := km.x25519Priv.PublicKey().Bytes()

	// GREASE: 1 byte
	greaseShare := []byte{0x00}
	// X25519MLKEM768: mlkem768_pub (1184) + x25519_pub (32) = 1216 bytes
	mlkemShare := make([]byte, 0, len(km.mlkemPub)+len(x25519PubBytes))
	mlkemShare = append(mlkemShare, km.mlkemPub...)
	mlkemShare = append(mlkemShare, x25519PubBytes...)
	// X25519: 32 bytes
	x25519Share := x25519PubBytes

	sharesLen := 2 + 2 + len(greaseShare) + // GREASE entry
		2 + 2 + len(mlkemShare) + // X25519MLKEM768 entry
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

	// X25519MLKEM768 key share
	binary.BigEndian.PutUint16(data[offset:], groupX25519MLKEM768)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(mlkemShare)))
	offset += 2
	copy(data[offset:], mlkemShare)
	offset += len(mlkemShare)

	// X25519 key share
	binary.BigEndian.PutUint16(data[offset:], groupX25519)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(x25519Share)))
	offset += 2
	copy(data[offset:], x25519Share)

	return data
}

// buildSafariSupportedGroups: GREASE + X25519MLKEM768 + X25519 + P-256 + P-384 + P-521
func buildSafariSupportedGroups(gs greaseSet) []byte {
	groups := []uint16{
		gs.group,
		groupX25519MLKEM768,
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
		0x06,                                    // list length: 6 bytes (3 versions)
		byte(gs.version >> 8), byte(gs.version), // GREASE
		0x03, 0x04, // TLS 1.3
		0x03, 0x03, // TLS 1.2
	}
}

// buildSafariSigAlgs builds Safari's signature algorithms. 10 entries, with
// 0x0805 deliberately repeated — see safariIOS18SigAlgs. The list length is
// computed from the slice, so the on-wire bytes track the slice automatically.
func buildSafariSigAlgs() []byte {
	algs := safariIOS18SigAlgs
	data := make([]byte, 2+len(algs)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(algs)*2))
	for i, a := range algs {
		binary.BigEndian.PutUint16(data[2+i*2:], a)
	}
	return data
}

// NOTE: no padding extension (0x0015).
//
// BoringSSL only pads a ClientHello that would otherwise land in the 256-511
// byte range (a workaround for old F5 middleboxes). Once key_share carries the
// 1216-byte X25519MLKEM768 entry the hello is far past that window, so a real
// device emits no padding at all — confirmed by the iOS 26.5.2 capture, whose
// extension list ends at the trailing GREASE.
//
// An earlier revision padded unconditionally to ~512 bytes. That added a 14th
// counted extension, so JA4_a read t13d2014h2 where a real device reads
// t13d2013h2, and the extra 0x0015 also shifted JA3.
