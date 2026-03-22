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
	handshakeTypeClientHello         = 1
	handshakeTypeServerHello         = 2
	handshakeTypeEncryptedExtensions = 8
	handshakeTypeCertificate         = 11
	handshakeTypeCertificateVerify   = 15
	handshakeTypeFinished            = 20
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
	extRecordSizeLimit      = 0x001C
	extDelegatedCredentials = 0x0022
	extSessionTicket        = 0x0023 // Sent empty by Firefox 148 on initial connections
	extKeyShare             = 0x0033
	extSupportedVersions    = 0x002B
	extPSKKeyExchangeModes  = 0x002D
	extRenegotiationInfo    = 0xFF01
	extECH                  = 0xFE0D // ECH GREASE
)

// Named groups (curves)
const (
	groupX25519MLKEM768 = 0x11EC // Post-quantum hybrid
	groupX25519         = 0x001D
	groupP256           = 0x0017
	groupP384           = 0x0018
	groupP521           = 0x0019
	groupFFDHE2048      = 0x0100
	groupFFDHE3072      = 0x0101
)

// Cipher suites (Firefox 148 order)
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

// Firefox 148 cipher suite order
var firefox148CipherSuites = []uint16{
	cipherTLS_AES_128_GCM_SHA256,
	cipherTLS_CHACHA20_POLY1305_SHA256,
	cipherTLS_AES_256_GCM_SHA384,
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	cipherTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	cipherTLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	cipherTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	cipherTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	cipherTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	cipherTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	cipherTLS_RSA_WITH_AES_128_GCM_SHA256,
	cipherTLS_RSA_WITH_AES_256_GCM_SHA384,
	cipherTLS_RSA_WITH_AES_128_CBC_SHA,
	cipherTLS_RSA_WITH_AES_256_CBC_SHA,
}

// Signature algorithms (Firefox 148 order)
var firefox148SigAlgs = []uint16{
	0x0403, // ecdsa_secp256r1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0603, // ecdsa_secp521r1_sha512
	0x0804, // rsa_pss_rsae_sha256
	0x0805, // rsa_pss_rsae_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0401, // rsa_pkcs1_sha256
	0x0501, // rsa_pkcs1_sha384
	0x0601, // rsa_pkcs1_sha512
	0x0203, // ecdsa_sha1
	0x0201, // rsa_pkcs1_sha1
}

// Delegated credentials signature algorithms
var firefox148DCAlgs = []uint16{
	0x0403, // ecdsa_secp256r1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0603, // ecdsa_secp521r1_sha512
	0x0203, // ecdsa_sha1
}

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

// Alert levels and descriptions
const (
	alertLevelWarning = 1
	alertLevelFatal   = 2

	alertCloseNotify    = 0
	alertUnexpectedMsg  = 10
	alertHandshakeFailure = 40
	alertDecryptError   = 51
)
