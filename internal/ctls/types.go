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

// BrowserType selects which TLS ClientHello to build.
type BrowserType int

const (
	BrowserFirefox148 BrowserType = iota
	BrowserChrome146
	BrowserSafariIOS18
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
	extSessionTicket        = 0x0023
	extKeyShare             = 0x0033
	extSupportedVersions    = 0x002B
	extPSKKeyExchangeModes  = 0x002D
	extALPS                 = 0x44CD // application_settings (Chrome-only)
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

// Chrome 146 cipher suite order (GREASE prefix added at build time)
var chrome146CipherSuites = []uint16{
	cipherTLS_AES_128_GCM_SHA256,
	cipherTLS_AES_256_GCM_SHA384,
	cipherTLS_CHACHA20_POLY1305_SHA256,
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	cipherTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	cipherTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	cipherTLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	cipherTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	cipherTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	cipherTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	cipherTLS_RSA_WITH_AES_128_GCM_SHA256,
	cipherTLS_RSA_WITH_AES_256_GCM_SHA384,
	cipherTLS_RSA_WITH_AES_128_CBC_SHA,
	cipherTLS_RSA_WITH_AES_256_CBC_SHA,
}

// Chrome 146 signature algorithms (8 algos, no SHA1)
var chrome146SigAlgs = []uint16{
	0x0403, // ecdsa_secp256r1_sha256
	0x0804, // rsa_pss_rsae_sha256
	0x0401, // rsa_pkcs1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0805, // rsa_pss_rsae_sha384
	0x0501, // rsa_pkcs1_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0601, // rsa_pkcs1_sha512
}

// GREASE values used by Chrome (RFC 8701)
var greaseValues = []uint16{
	0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
	0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

// Alert levels and descriptions live in alert.go.
