package ctls

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	// kyber768 has the same public key size (1184 bytes) and ciphertext size (1088 bytes)
	// as ML-KEM-768, making it a drop-in for TLS fingerprint purposes.
	// Most servers fall back to X25519 key exchange.
	kyber "github.com/cloudflare/circl/kem/kyber/kyber768"
)

// kyber768PubKeySize is the public key size for Kyber768 / ML-KEM-768.
// Both have identical sizes: 1184 bytes public key, 1088 bytes ciphertext.
const kyber768PubKeySize = 1184

// keyMaterial holds generated key pairs for the ClientHello key_share.
type keyMaterial struct {
	kyberPub   []byte           // Kyber768 / ML-KEM-768 compatible public key (1184 bytes)
	kyberPriv  kyber.PrivateKey // for potential decapsulation
	x25519Priv *ecdh.PrivateKey
}

// generateKeyMaterial generates key pairs for X25519MLKEM768 (using Kyber768) and X25519.
func generateKeyMaterial() (*keyMaterial, error) {
	// Generate Kyber768 key pair (same sizes as ML-KEM-768)
	pub, priv, err := kyber.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate kyber768 key: %w", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal kyber768 pub: %w", err)
	}

	// Generate X25519 key pair
	privX25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}

	return &keyMaterial{
		kyberPub:   pubBytes,
		kyberPriv:  *priv,
		x25519Priv: privX25519,
	}, nil
}

// buildClientHello builds the full Firefox 148 ClientHello handshake message.
// Returns the raw bytes of the handshake message (without the TLS record header).
func buildClientHello(serverName string, alpn []string, km *keyMaterial) ([]byte, error) {
	// --- Build extensions ---
	exts, err := buildExtensions(serverName, alpn, km)
	if err != nil {
		return nil, err
	}

	// --- Build ClientHello body ---
	// ClientHello = version(2) + random(32) + session_id(1+32) +
	//               cipher_suites(2+N*2) + compression_methods(1+1) +
	//               extensions(2+N)

	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("generate random: %w", err)
	}

	var sessionID [32]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}

	body := make([]byte, 0, 512+len(exts))

	// Legacy version: 0x0303 (TLS 1.2)
	body = appendUint16(body, versionTLS12)

	// Random: 32 bytes
	body = append(body, random[:]...)

	// Legacy session ID (32 bytes, non-empty for TLS 1.3 compat)
	body = append(body, 32) // length
	body = append(body, sessionID[:]...)

	// Cipher suites
	body = appendUint16(body, uint16(len(firefox148CipherSuites)*2))
	for _, cs := range firefox148CipherSuites {
		body = appendUint16(body, cs)
	}

	// Compression methods: null only
	body = append(body, 1, 0x00)

	// Extensions
	body = appendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	// --- Wrap in handshake header ---
	msg := make([]byte, 4+len(body))
	msg[0] = handshakeTypeClientHello
	// Length: 3-byte big-endian
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)

	return msg, nil
}

// buildExtensions builds all TLS extensions in exact Firefox 148 order.
func buildExtensions(serverName string, alpn []string, km *keyMaterial) ([]byte, error) {
	var out []byte

	// 0x0000 - server_name
	out = appendExt(out, extServerName, buildSNI(serverName))

	// 0x0017 - extended_master_secret (empty)
	out = appendExt(out, extExtendedMasterSecret, nil)

	// 0xFF01 - renegotiation_info (empty renegotiated_connection)
	out = appendExt(out, extRenegotiationInfo, []byte{0x00})

	// 0x000A - supported_groups
	out = appendExt(out, extSupportedGroups, buildSupportedGroups())

	// 0x000B - ec_point_formats
	out = appendExt(out, extECPointFormats, []byte{1, 0x00}) // uncompressed only

	// 0x0010 - ALPN
	out = appendExt(out, extALPN, buildALPN(alpn))

	// 0x0005 - status_request (OCSP stapling)
	out = appendExt(out, extStatusRequest, buildStatusRequest())

	// 0x0022 - delegated_credentials
	out = appendExt(out, extDelegatedCredentials, buildDelegatedCredentials())

	// 0x0012 - signed_certificate_timestamp (empty)
	out = appendExt(out, extSCT, nil)

	// 0x0033 - key_share: X25519MLKEM768 + X25519 (Firefox 148 order)
	keyShareData, err := buildKeyShare(km)
	if err != nil {
		return nil, err
	}
	out = appendExt(out, extKeyShare, keyShareData)

	// 0x002B - supported_versions: TLS 1.3, TLS 1.2
	out = appendExt(out, extSupportedVersions, buildSupportedVersions())

	// 0x000D - signature_algorithms
	out = appendExt(out, extSignatureAlgorithms, buildSigAlgs())

	// 0x002D - psk_key_exchange_modes: psk_dhe_ke
	out = appendExt(out, extPSKKeyExchangeModes, []byte{1, pskModePSKDHE})

	// 0x001C - record_size_limit: 16385 (0x4001)
	out = appendExt(out, extRecordSizeLimit, []byte{0x40, 0x01})

	// 0x001B - compress_certificate: zlib, brotli, zstd
	out = appendExt(out, extCompressCertificate, buildCompressCertificate())

	return out, nil
}

func buildSNI(serverName string) []byte {
	// server_name_list length (2) + type (1) + name_length (2) + name
	nameBytes := []byte(serverName)
	data := make([]byte, 2+1+2+len(nameBytes))
	// server_name_list length
	binary.BigEndian.PutUint16(data[0:], uint16(1+2+len(nameBytes)))
	data[2] = 0x00 // name_type: host_name
	binary.BigEndian.PutUint16(data[3:], uint16(len(nameBytes)))
	copy(data[5:], nameBytes)
	return data
}

func buildSupportedGroups() []byte {
	groups := []uint16{
		groupX25519MLKEM768,
		groupX25519,
		groupP256,
		groupP384,
		groupP521,
		groupFFDHE2048,
		groupFFDHE3072,
	}
	data := make([]byte, 2+len(groups)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(groups)*2))
	for i, g := range groups {
		binary.BigEndian.PutUint16(data[2+i*2:], g)
	}
	return data
}

func buildALPN(alpn []string) []byte {
	// First pass: calculate total size
	total := 0
	for _, proto := range alpn {
		total += 1 + len(proto) // length byte + proto bytes
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

func buildStatusRequest() []byte {
	// CertificateStatusRequest: status_type=ocsp(1), responder_id_list empty, request_extensions empty
	return []byte{
		0x01,       // status_type: ocsp
		0x00, 0x00, // responder_id_list length: 0
		0x00, 0x00, // request_extensions length: 0
	}
}

func buildDelegatedCredentials() []byte {
	// SignatureSchemeList
	algs := firefox148DCAlgs
	data := make([]byte, 2+len(algs)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(algs)*2))
	for i, a := range algs {
		binary.BigEndian.PutUint16(data[2+i*2:], a)
	}
	return data
}

func buildKeyShare(km *keyMaterial) ([]byte, error) {
	// key_share extension data:
	// client_shares length (2) + [ (group(2) + key_exchange_length(2) + key_exchange) ... ]

	// X25519MLKEM768 key share: kyber768_pub (1184 bytes) || x25519_pub (32 bytes) = 1216 bytes
	x25519PubBytes := km.x25519Priv.PublicKey().Bytes()
	mlkemShare := make([]byte, 0, len(km.kyberPub)+32)
	mlkemShare = append(mlkemShare, km.kyberPub...)
	mlkemShare = append(mlkemShare, x25519PubBytes...)

	// X25519 key share
	x25519Share := x25519PubBytes

	// Total key shares size
	sharesLen := 2 + 2 + len(mlkemShare) + // X25519MLKEM768 entry
		2 + 2 + len(x25519Share) // X25519 entry

	data := make([]byte, 2+sharesLen)
	binary.BigEndian.PutUint16(data[0:], uint16(sharesLen))

	offset := 2
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

func buildSupportedVersions() []byte {
	// versions_length (1) + [TLS 1.3 (2), TLS 1.2 (2)]
	return []byte{
		0x04,       // list length: 4 bytes
		0x03, 0x04, // TLS 1.3
		0x03, 0x03, // TLS 1.2
	}
}

func buildSigAlgs() []byte {
	algs := firefox148SigAlgs
	data := make([]byte, 2+len(algs)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(algs)*2))
	for i, a := range algs {
		binary.BigEndian.PutUint16(data[2+i*2:], a)
	}
	return data
}

func buildCompressCertificate() []byte {
	return []byte{
		0x06,       // list length: 6 bytes
		0x00, 0x01, // zlib
		0x00, 0x02, // brotli
		0x00, 0x03, // zstd
	}
}

// buildECHGrease builds a random ECH GREASE extension matching Firefox 148 format.
func buildECHGrease() ([]byte, error) {
	// ECH ClientHello outer structure (simplified GREASE format):
	// client_hello_type (1) = outer(0)
	// cipher_suite:
	//   kdf_id (2) = HKDF-SHA256 (0x0001)
	//   aead_id (2) = AES-128-GCM (0x0001)
	// config_id (1) = random
	// enc_len (2) + enc (random public key, 32 bytes for X25519 HPKE)
	// payload_len (2) + payload (random, 128 or 223 bytes)

	var configID [1]byte
	if _, err := rand.Read(configID[:]); err != nil {
		return nil, err
	}

	var enc [32]byte
	if _, err := rand.Read(enc[:]); err != nil {
		return nil, err
	}

	// Choose 128 or 223 payload length (Firefox alternates)
	payloadLen := 128
	var randByte [1]byte
	if _, err := rand.Read(randByte[:]); err != nil {
		return nil, err
	}
	if randByte[0]&1 == 1 {
		payloadLen = 223
	}

	payload := make([]byte, payloadLen)
	if _, err := rand.Read(payload); err != nil {
		return nil, err
	}

	// Build the ECH extension data
	var data []byte
	data = append(data, 0x00) // client_hello_type = outer
	data = appendUint16(data, 0x0001) // kdf_id = HKDF-SHA256
	data = appendUint16(data, 0x0001) // aead_id = AES-128-GCM
	data = append(data, configID[0])
	data = appendUint16(data, uint16(len(enc)))
	data = append(data, enc[:]...)
	data = appendUint16(data, uint16(payloadLen))
	data = append(data, payload...)

	return data, nil
}

// appendExt appends an extension (type + length + data) to buf.
func appendExt(buf []byte, extType uint16, data []byte) []byte {
	buf = appendUint16(buf, extType)
	buf = appendUint16(buf, uint16(len(data)))
	buf = append(buf, data...)
	return buf
}

// appendUint16 appends a big-endian uint16 to buf.
func appendUint16(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}
