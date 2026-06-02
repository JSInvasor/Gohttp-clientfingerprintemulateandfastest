package ctls

// TLS record content types
const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22
	recordTypeApplicationData  = 23
)

// TLS handshake message types
const (
	handshakeTypeClientHello             = 1
	handshakeTypeServerHello             = 2
	handshakeTypeEncryptedExtensions     = 8
	handshakeTypeCertificate             = 11
	handshakeTypeCertificateVerify       = 15
	handshakeTypeFinished                = 20
	handshakeTypeCompressedCertificate   = 25
)

// TLS versions
const (
	versionTLS10 = 0x0301
	versionTLS12 = 0x0303
	versionTLS13 = 0x0304
)

// TLS extension IDs
const (
	extServerName           = 0x0000
	extStatusRequest        = 0x0005
	extSupportedGroups      = 0x000A
	extECPointFormats       = 0x000B
	extSignatureAlgorithms  = 0x000D
	extALPN                 = 0x0010
	extSCT                  = 0x0012
	extExtendedMasterSecret = 0x0017
	extCompressCertificate  = 0x001B
	extSessionTicket        = 0x0023
	extKeyShare             = 0x0033
	extSupportedVersions    = 0x002B
	extPSKKeyExchangeModes  = 0x002D
	extRenegotiationInfo    = 0xFF01
)

// Named groups (curves)
const (
	groupX25519MLKEM768 = 0x11EC // Post-quantum hybrid (defensive: server may pick)
	groupX25519         = 0x001D
	groupP256           = 0x0017
	groupP384           = 0x0018
	groupP521           = 0x0019
)

// Cipher suites used by Safari iOS 18
const (
	cipherTLS_AES_128_GCM_SHA256                     = 0x1301
	cipherTLS_CHACHA20_POLY1305_SHA256               = 0x1303
	cipherTLS_AES_256_GCM_SHA384                     = 0x1302
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    = 0xC02B
	cipherTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256      = 0xC02F
	cipherTLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305     = 0xCCA9
	cipherTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305       = 0xCCA8
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    = 0xC02C
	cipherTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384      = 0xC030
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA       = 0xC00A
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA       = 0xC009
	cipherTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA         = 0xC013
	cipherTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA         = 0xC014
	cipherTLS_RSA_WITH_AES_128_GCM_SHA256            = 0x009C
	cipherTLS_RSA_WITH_AES_256_GCM_SHA384            = 0x009D
	cipherTLS_RSA_WITH_AES_128_CBC_SHA               = 0x002F
	cipherTLS_RSA_WITH_AES_256_CBC_SHA               = 0x0035
)

// Certificate compression algorithms
const (
	certCompressionZlib   = 1
	certCompressionBrotli = 2
	certCompressionZstd   = 3
)

// PSK key exchange modes
const (
	pskModePSK    = 0
	pskModePSKDHE = 1
)

// GREASE values (RFC 8701). Safari sprinkles them into the cipher list,
// extensions, supported_groups, supported_versions, and key_share.
var greaseValues = []uint16{
	0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
	0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

// Alert levels and descriptions
const (
	alertLevelWarning = 1
	alertLevelFatal   = 2

	alertCloseNotify    = 0
	alertUnexpectedMsg  = 10
	alertHandshakeFailure = 40
	alertDecryptError   = 51
)
