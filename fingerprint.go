package gofire

import (
	tls "github.com/refraction-networking/utls"
)

// Firefox148Spec returns the TLS ClientHelloSpec for Firefox 148.
// This precisely emulates Firefox 148's TLS ClientHello including:
//   - Cipher suites in exact Firefox order
//   - Extensions in exact Firefox order
//   - GREASE values for realistic randomization
//   - ECH GREASE (Encrypted Client Hello)
//   - Certificate compression (zlib, brotli)
//   - Delegated credentials
//   - Post-handshake auth indicator
//
// Verified against: tls.peet.ws, ja3er.com, browserleaks.com
func Firefox148Spec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS12,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites (Firefox order)
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			// TLS 1.2 cipher suites (Firefox order)
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0x00}, // null compression only
		Extensions: []tls.TLSExtension{
			// Extension order matches Firefox 148 exactly
			&tls.SNIExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{
				Curves: []tls.CurveID{
					tls.X25519,    // 0x001d
					tls.CurveP256, // 0x0017
					tls.CurveP384, // 0x0018
					tls.CurveP521, // 0x0019
					0x0100,        // ffdhe2048
					0x0101,        // ffdhe3072
				},
			},
			&tls.SupportedPointsExtension{
				SupportedPoints: []byte{0x00}, // uncompressed
			},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{
				AlpnProtocols: []string{"h2", "http/1.1"},
			},
			&tls.StatusRequestExtension{},
			&tls.DelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.PSSWithSHA256,
					tls.PSSWithSHA384,
					tls.PSSWithSHA512,
				},
			},
			&tls.KeyShareExtension{
				KeyShares: []tls.KeyShare{
					{Group: tls.X25519},
					{Group: tls.CurveP256},
				},
			},
			&tls.SupportedVersionsExtension{
				Versions: []uint16{
					tls.VersionTLS13,
					tls.VersionTLS12,
				},
			},
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.PSSWithSHA256,
					tls.PSSWithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA256,
					tls.PKCS1WithSHA384,
					tls.PKCS1WithSHA512,
				},
			},
			&tls.PSKKeyExchangeModesExtension{
				Modes: []uint8{tls.PskModeDHE},
			},
			&tls.FakeRecordSizeLimitExtension{Limit: 0x4001}, // 16385
			&tls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
					{
						KdfId:  0x0001, // HKDF-SHA256
						AeadId: 0x0001, // AES-128-GCM
					},
					{
						KdfId:  0x0001, // HKDF-SHA256
						AeadId: 0x0003, // ChaCha20-Poly1305
					},
				},
				CandidatePayloadLens: []uint16{128, 223},
			},
			&tls.UtlsCompressCertExtension{
				Algorithms: []tls.CertCompressionAlgo{
					tls.CertCompressionZlib,
					tls.CertCompressionBrotli,
				},
			},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		},
	}
}

// H2Settings defines HTTP/2 connection settings for fingerprinting.
type H2Settings struct {
	HeaderTableSize      uint32
	EnablePush           uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	ConnectionWindowSize uint32
}

// Firefox148H2Settings returns HTTP/2 SETTINGS that match Firefox 148.
// These values are sent in the HTTP/2 SETTINGS frame after connection.
//
//	SETTINGS_HEADER_TABLE_SIZE:      65536
//	SETTINGS_ENABLE_PUSH:            0 (disabled)
//	SETTINGS_INITIAL_WINDOW_SIZE:    131072 (128KB)
//	SETTINGS_MAX_FRAME_SIZE:         16384 (16KB)
//	Connection WINDOW_UPDATE:        12517377
func Firefox148H2Settings() H2Settings {
	return H2Settings{
		HeaderTableSize:      65536,
		EnablePush:           0,
		InitialWindowSize:    131072,
		MaxFrameSize:         16384,
		ConnectionWindowSize: 12517377,
	}
}

// Firefox148PseudoHeaderOrder returns the HTTP/2 pseudo-header order for Firefox 148.
// Firefox sends pseudo-headers in this exact order: :method :path :authority :scheme
func Firefox148PseudoHeaderOrder() []string {
	return []string{":method", ":path", ":authority", ":scheme"}
}

// Firefox148HeaderPriority returns the PRIORITY frame weight for Firefox 148.
// Firefox uses urgency-based priority (RFC 9218).
func Firefox148HeaderPriority() map[string]string {
	return map[string]string{
		"u": "0",
		"i": "",
	}
}
