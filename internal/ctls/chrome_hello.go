package ctls

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
)

// Chrome 146 ClientHello builder.
// Verified against real Chrome 146 via tls.peet.ws.
//
// JA3: 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,
//      45-11-51-27-23-43-18-65281-16-0-10-17613-13-65037-5-35-41,4588-29-23-24,0
// JA3 Hash: 9271bc66017f8920fe4549ad9e47e63b
// JA4: t13d1517h2_8daaf6152771_b6f405a00624
//
// Key differences from Firefox 148:
//   - GREASE values in cipher suites, extensions, supported_groups, supported_versions, key_share
//   - Different cipher suite order (AES128, AES256, CHACHA vs Firefox AES128, CHACHA, AES256)
//   - Only 2 key shares (X25519MLKEM768, X25519) vs Firefox's 3 (+ P-256)
//   - 4 supported groups (no P-521, no FFDHE) vs Firefox's 7
//   - 8 signature algorithms (no SHA1) vs Firefox's 11
//   - Only brotli for compress_certificate vs Firefox's zlib+brotli+zstd
//   - Has ALPS extension (17613) - Firefox doesn't
//   - No delegated_credentials, no record_size_limit
//   - Different extension order

// greaseSet holds pre-selected GREASE values for one ClientHello.
// Chrome uses different GREASE values at different positions.
type greaseSet struct {
	cipher     uint16 // GREASE in cipher suite list
	extFirst   uint16 // GREASE as first extension
	extLast    uint16 // GREASE as second-to-last extension
	keyShare   uint16 // GREASE in key_share
	group      uint16 // GREASE in supported_groups
	version    uint16 // GREASE in supported_versions
}

// randomGrease picks a random GREASE value.
func randomGrease() uint16 {
	var b [1]byte
	rand.Read(b[:])
	return greaseValues[int(b[0])%len(greaseValues)]
}

// newGreaseSet generates a set of GREASE values for Chrome ClientHello.
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

// buildChromeClientHello builds the Chrome 146 ClientHello handshake message.
func buildChromeClientHello(serverName string, alpn []string, km *keyMaterial) ([]byte, error) {
	gs := newGreaseSet()

	exts, err := buildChromeExtensions(serverName, alpn, km, gs)
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

	// Cipher suites: GREASE + chrome146CipherSuites
	cipherCount := 1 + len(chrome146CipherSuites) // +1 for GREASE
	body = appendUint16(body, uint16(cipherCount*2))
	body = appendUint16(body, gs.cipher) // GREASE cipher
	for _, cs := range chrome146CipherSuites {
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

// buildChromeExtensions builds all TLS extensions in exact Chrome 146 order.
// Order from tls.peet.ws capture:
//  1. GREASE
//  2. psk_key_exchange_modes (45)
//  3. ec_point_formats (11)
//  4. key_share (51)
//  5. compress_certificate (27)
//  6. extended_master_secret (23)
//  7. supported_versions (43)
//  8. signed_certificate_timestamp (18)
//  9. renegotiation_info (65281)
// 10. application_layer_protocol_negotiation (16)
// 11. server_name (0)
// 12. supported_groups (10)
// 13. application_settings (17613)
// 14. signature_algorithms (13)
// 15. encrypted_client_hello (65037)
// 16. status_request (5)
// 17. session_ticket (35)
// 18. GREASE
// chromeExt is one extension entry pending serialization.
type chromeExt struct {
	typ  uint16
	data []byte
}

func buildChromeExtensions(serverName string, alpn []string, km *keyMaterial, gs greaseSet) ([]byte, error) {
	keyShareData, err := buildChromeKeyShare(km, gs)
	if err != nil {
		return nil, err
	}
	echGrease, err := buildECHGrease()
	if err != nil {
		return nil, err
	}

	// Middle extensions - shuffled per ClientHello to match Chrome 110+ behavior.
	// Real Chrome (BoringSSL tls_extension_permutation_enabled, default-on since
	// 110) randomizes extension order on every connection so each request emits
	// a different JA3 hash. A fixed order produces zero JA3 entropy across
	// connections, which Cloudflare/Akamai score as a strong bot signal.
	// JA4 is unaffected (it sorts extensions before hashing).
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
		{extALPS, buildALPS(alpn)},
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
	// Last GREASE: pinned at the end. (pre_shared_key would have to come after
	// this on a resumed session per RFC 8446, but we don't send PSK on initial
	// connections, so the trailing GREASE is the final extension.)
	out = appendExt(out, gs.extLast, []byte{0x00})

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

	// Total key shares size
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
		0x06, // list length: 6 bytes (3 versions)
		byte(gs.version >> 8), byte(gs.version), // GREASE
		0x03, 0x04, // TLS 1.3
		0x03, 0x03, // TLS 1.2
	}
}

// buildChromeSigAlgs builds Chrome 146 signature algorithms.
func buildChromeSigAlgs() []byte {
	algs := chrome146SigAlgs
	data := make([]byte, 2+len(algs)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(algs)*2))
	for i, a := range algs {
		binary.BigEndian.PutUint16(data[2+i*2:], a)
	}
	return data
}

// buildALPS builds the application_settings (ALPS) extension.
// Chrome sends this with "h2" protocol.
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
