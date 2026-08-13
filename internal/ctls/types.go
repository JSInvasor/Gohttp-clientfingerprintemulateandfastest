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
	handshakeTypeClientHello           = 1
	handshakeTypeServerHello           = 2
	handshakeTypeNewSessionTicket      = 4
	handshakeTypeEncryptedExtensions   = 8
	handshakeTypeCertificate           = 11
	handshakeTypeCertificateRequest    = 13
	handshakeTypeCertificateVerify     = 15
	handshakeTypeFinished              = 20
	handshakeTypeKeyUpdate             = 24
	handshakeTypeCompressedCertificate = 25

	// handshakeTypeMessageHash is the synthetic message RFC 8446 §4.4.1
	// substitutes for ClientHello1 once a HelloRetryRequest has been exchanged.
	handshakeTypeMessageHash = 254
)

// KeyUpdate request_update values (RFC 8446 §4.6.3).
const (
	keyUpdateNotRequested = 0
	keyUpdateRequested    = 1
)

// helloRetryRequestRandom is the fixed ServerHello.random that marks a message
// as a HelloRetryRequest (RFC 8446 §4.1.3). It is SHA-256("HelloRetryRequest").
var helloRetryRequestRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// Signature schemes accepted in CertificateVerify (RFC 8446 §4.2.3).
//
// RSASSA-PKCS1-v1_5 code points are deliberately absent: §4.4.3 forbids them in
// signed handshake messages even though they stay legal inside certificates.
const (
	sigECDSAP256SHA256  = 0x0403
	sigECDSAP384SHA384  = 0x0503
	sigECDSAP521SHA512  = 0x0603
	sigRSAPSSRSAeSHA256 = 0x0804
	sigRSAPSSRSAeSHA384 = 0x0805
	sigRSAPSSRSAeSHA512 = 0x0806
	sigEd25519          = 0x0807
	sigRSAPSSPSSSHA256  = 0x0809
	sigRSAPSSPSSSHA384  = 0x080A
	sigRSAPSSPSSSHA512  = 0x080B
)

// TLS versions
const (
	versionTLS10 = 0x0301
	versionTLS12 = 0x0303
	versionTLS13 = 0x0304
)

// BrowserType selects which TLS ClientHello to build.
//
// The zero value is Safari so a caller that does not specify a profile
// keeps the Safari fingerprint this package shipped as its only profile.
type BrowserType int

const (
	BrowserSafari BrowserType = iota
	BrowserChrome
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
	extEarlyData            = 0x002a
	extKeyShare             = 0x0033
	extSupportedVersions    = 0x002B
	extCookie               = 0x002C
	extPSKKeyExchangeModes  = 0x002D
	extPreSharedKey         = 0x0029
	extALPS                 = 0x44CD // application_settings (Chrome-only)
	extECH                  = 0xFE0D // ECH GREASE (Chrome-only)
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

// Cipher suites used by the Safari iOS 18 and Chrome 146 profiles
const (
	cipherTLS_AES_128_GCM_SHA256                  = 0x1301
	cipherTLS_CHACHA20_POLY1305_SHA256            = 0x1303
	cipherTLS_AES_256_GCM_SHA384                  = 0x1302
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
	cipherTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   = 0xC02F
	cipherTLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305  = 0xCCA9
	cipherTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305    = 0xCCA8
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
	cipherTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   = 0xC030
	cipherTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    = 0xC00A
	cipherTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    = 0xC009
	cipherTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      = 0xC013
	cipherTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      = 0xC014
	cipherTLS_RSA_WITH_AES_128_GCM_SHA256         = 0x009C
	cipherTLS_RSA_WITH_AES_256_GCM_SHA384         = 0x009D
	cipherTLS_RSA_WITH_AES_128_CBC_SHA            = 0x002F
	cipherTLS_RSA_WITH_AES_256_CBC_SHA            = 0x0035
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

// Chrome cipher suite order (a GREASE value is prepended at build time).
// Unchanged between Chrome 146 and 150 — verified against real Chrome 150.
var chromeCipherSuites = []uint16{
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

// Chrome signature algorithms (11 algos, no SHA1). Verified against real
// Chrome 150 via tls.peet.ws.
//
// The three ML-DSA entries lead the list: Chrome advertises post-quantum
// certificate signatures ahead of the classical algorithms. They were absent
// from the Chrome 146 profile, which put JA4_c at d8a2da3f94cd instead of the
// real 806a8c22fdea.
var chromeSigAlgs = []uint16{
	0x0904, // mldsa44
	0x0905, // mldsa65
	0x0906, // mldsa87
	0x0403, // ecdsa_secp256r1_sha256
	0x0804, // rsa_pss_rsae_sha256
	0x0401, // rsa_pkcs1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0805, // rsa_pss_rsae_sha384
	0x0501, // rsa_pkcs1_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0601, // rsa_pkcs1_sha512
}

// GREASE values (RFC 8701). Both Safari and Chrome sprinkle them into the
// cipher list, extensions, supported_groups, supported_versions, and key_share.
var greaseValues = []uint16{
	0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
	0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

// Alert levels and descriptions live in alert.go, next to the code that reads
// and writes them.
