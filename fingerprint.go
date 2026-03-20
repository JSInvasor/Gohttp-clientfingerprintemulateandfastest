package gofire

import (
	tls "github.com/refraction-networking/utls"
)

// X25519MLKEM768 is the post-quantum hybrid key exchange (ML-KEM-768 + X25519).
// Firefox 148 includes this as the first supported group.
// CurveID 0x11EC (4588) per RFC 9180 / draft-ietf-tls-mlkem.
const CurveX25519MLKEM768 tls.CurveID = 0x11EC

// Firefox148Spec returns the exact TLS ClientHelloSpec for Firefox 148.
//
// Verified against real Firefox 148 capture from tls.peet.ws:
//
//	JA3:      771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0
//	JA3 Hash: 0e76c7e9d06fa0e211b1827687dd8f43
//	JA4:      t13d1717h2_5b57614c22b0_e6dcd7ae0a9e
func Firefox148Spec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS12,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites
			tls.TLS_AES_128_GCM_SHA256,                       // 4865  0x1301
			tls.TLS_CHACHA20_POLY1305_SHA256,                  // 4867  0x1303
			tls.TLS_AES_256_GCM_SHA384,                        // 4866  0x1302
			// TLS 1.2 ECDHE cipher suites
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,      // 49195 0xC02B
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,        // 49199 0xC02F
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // 52393 0xCCA9
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,  // 52392 0xCCA8
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,      // 49196 0xC02C
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,        // 49200 0xC030
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,         // 49162 0xC00A
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,         // 49161 0xC009
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,           // 49171 0xC013
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,           // 49172 0xC014
			// TLS 1.2 RSA cipher suites
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,              // 156   0x009C
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,              // 157   0x009D
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,                 // 47    0x002F
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,                 // 53    0x0035
		},
		CompressionMethods: []uint8{0x00}, // null compression only
		Extensions: []tls.TLSExtension{
			// Extension order matches real Firefox 148 JA3:
			// 0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41

			// 0: server_name
			&tls.SNIExtension{},

			// 23: extended_master_secret
			&tls.ExtendedMasterSecretExtension{},

			// 65281: renegotiation_info
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},

			// 10: supported_groups
			&tls.SupportedCurvesExtension{
				Curves: []tls.CurveID{
					CurveX25519MLKEM768, // 4588 0x11EC - post-quantum hybrid (FIRST!)
					tls.X25519,          // 29   0x001D
					tls.CurveP256,       // 23   0x0017
					tls.CurveP384,       // 24   0x0018
					tls.CurveP521,       // 25   0x0019
					0x0100,              // 256  ffdhe2048
					0x0101,              // 257  ffdhe3072
				},
			},

			// 11: ec_point_formats
			&tls.SupportedPointsExtension{
				SupportedPoints: []byte{0x00}, // uncompressed
			},

			// 16: application_layer_protocol_negotiation
			// NOTE: NO session_ticket extension - Firefox 148 does NOT send it
			&tls.ALPNExtension{
				AlpnProtocols: []string{"h2", "http/1.1"},
			},

			// 5: status_request (OCSP stapling)
			&tls.StatusRequestExtension{},

			// 34: delegated_credentials
			&tls.DelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,        // 0x0403
					tls.ECDSAWithP384AndSHA384,        // 0x0503
					tls.ECDSAWithP521AndSHA512,        // 0x0603
					tls.SignatureScheme(0x0203),        // 0x0203 ecdsa_sha1
				},
			},

			// 18: signed_certificate_timestamp (SCT)
			&tls.GenericExtension{Id: 18},

			// 51: key_share
			&tls.KeyShareExtension{
				KeyShares: []tls.KeyShare{
					{Group: tls.X25519},
					{Group: tls.CurveP256},
				},
			},

			// 43: supported_versions
			&tls.SupportedVersionsExtension{
				Versions: []uint16{
					tls.VersionTLS13,
					tls.VersionTLS12,
				},
			},

			// 13: signature_algorithms (11 algorithms, exact Firefox 148 order)
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,        // 0x0403
					tls.ECDSAWithP384AndSHA384,        // 0x0503
					tls.ECDSAWithP521AndSHA512,        // 0x0603
					tls.PSSWithSHA256,                  // 0x0804
					tls.PSSWithSHA384,                  // 0x0805
					tls.PSSWithSHA512,                  // 0x0806
					tls.PKCS1WithSHA256,                // 0x0401
					tls.PKCS1WithSHA384,                // 0x0501
					tls.PKCS1WithSHA512,                // 0x0601
					tls.SignatureScheme(0x0203),        // 0x0203 ecdsa_sha1
					tls.SignatureScheme(0x0201),        // 0x0201 rsa_pkcs1_sha1
				},
			},

			// 45: psk_key_exchange_modes
			&tls.PSKKeyExchangeModesExtension{
				Modes: []uint8{tls.PskModeDHE},
			},

			// 28: record_size_limit
			&tls.FakeRecordSizeLimitExtension{Limit: 0x4001}, // 16385

			// 27: compress_certificate (zlib + brotli + zstd)
			&tls.UtlsCompressCertExtension{
				Algorithms: []tls.CertCompressionAlgo{
					tls.CertCompressionZlib,
					tls.CertCompressionBrotli,
					tls.CertCompressionAlgo(3), // zstd
				},
			},

			// 65037: encrypted_client_hello (ECH GREASE)
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

			// NOTE: extension 41 (pre_shared_key) is auto-added by TLS 1.3
			// on session resumption. Fresh connections won't have it, which
			// matches real browser behavior on first visit.

			// NOTE: NO padding extension - real Firefox 148 does NOT send it
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

// Firefox148H2Settings returns the exact HTTP/2 SETTINGS from Firefox 148.
//
// Akamai fingerprint: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
// Akamai hash: 6ea73faa8fc5aac76bded7bd238f6433
func Firefox148H2Settings() H2Settings {
	return H2Settings{
		HeaderTableSize:      65536,   // SETTINGS_HEADER_TABLE_SIZE
		EnablePush:           0,       // SETTINGS_ENABLE_PUSH (disabled)
		InitialWindowSize:    131072,  // SETTINGS_INITIAL_WINDOW_SIZE (128KB)
		MaxFrameSize:         16384,   // SETTINGS_MAX_FRAME_SIZE (16KB)
		ConnectionWindowSize: 12517377, // WINDOW_UPDATE increment
	}
}

// Firefox148PseudoHeaderOrder returns the HTTP/2 pseudo-header order.
// Akamai fingerprint suffix: m,p,a,s
func Firefox148PseudoHeaderOrder() []string {
	return []string{":method", ":path", ":authority", ":scheme"}
}

// Firefox148PriorityWeight returns the PRIORITY frame weight (0-indexed).
// Firefox 148 sends PRIORITY flag (0x20) with weight=42, depends_on=0, exclusive=0.
func Firefox148PriorityWeight() uint8 {
	return 42
}
