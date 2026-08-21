package quic

// The QUIC identity this client has to reproduce, read off a real device.
//
// Same rule as internal/ctls/reference.go: none of this is aspiration. Every
// value below was decoded from Chrome's own Initial datagrams, captured by
// tools/capture and committed under testdata, and initial_test.go decodes those
// same bytes on every `go test` — so a value that stops matching fails the
// build instead of quietly becoming a claim nobody checks.
//
// Three things are worth reading before trusting the layout of anything here.
//
// First, the extension order is not in this file, and its absence is a
// measurement. Chrome permutes its ClientHello extensions per connection on
// QUIC exactly as it does on TCP: three connections captured in one run
// produced three different orders and one identical JA4. A pinned QUIC
// extension order would fail every correct run, and a client that produced a
// stable one would be the anomaly.
//
// Second — and this one was a surprise — the transport parameters are shuffled
// too. The same three captures put the same set of parameters in three
// unrelated orders, and the GREASE version inside version_information moved
// with them. So TransportParams below is a set with values, deliberately a map
// rather than a slice: order here is noise, and an implementation that emits a
// fixed one is distinguishable from Chrome.
//
// Third, the GREASE moved. Chrome's TLS-over-TCP ClientHello carries a GREASE
// cipher, a GREASE extension at each end, a GREASE group and a GREASE key
// share. Its QUIC ClientHello carries none of those: three ciphers, eleven
// extensions, four groups, one TLS version, all real. The GREASE lives one
// layer down instead, as a reserved transport parameter with a random 62-bit id
// and as a reserved version inside version_information. Copying the TCP
// profile's GREASE placement into the QUIC hello would therefore be wrong in a
// way that no amount of care about cipher order would catch.
type Reference struct {
	// Device is what these values were captured from.
	Device string

	// Target is the host the capture was taken against. Named because the
	// ClientHello is per-connection: SNI and the ECH payload differ, and only
	// the fields below are shared.
	Target string

	// JA4 and JA4R are the QUIC-variant fingerprints. They differ from the
	// TCP profile's by more than the leading 'q': the extension set, the
	// absence of GREASE and the empty session id all move the hash.
	JA4  string
	JA4R string

	// Ciphers, Groups, KeyShares, SigAlgs and TLSVersions are in wire order.
	// Unlike the extension list these do not move between connections.
	Ciphers     []uint16
	Groups      []uint16
	KeyShares   []uint16
	SigAlgs     []uint16
	TLSVersions []uint16

	// ExtensionSet is every extension the hello carries, sorted. The order it
	// arrives in is not pinned; see the note above.
	ExtensionSet []uint16

	// SessionIDLen is 0. Worth stating rather than leaving implicit: the
	// TLS-over-TCP profile sends a 32-byte legacy session id for the benefit of
	// middleboxes that expect one, and QUIC drops it because there are no
	// middleboxes to fool inside an encrypted packet.
	SessionIDLen int

	// ALPN is what the hello offers. Exactly one entry on QUIC.
	ALPN []string

	// DCIDLen, SCIDLen and TokenLen describe the first Initial's header.
	// A zero-length SCID is not an omission — Chrome uses one, and says so
	// again in initial_source_connection_id, which is present and empty.
	DCIDLen  int
	SCIDLen  int
	TokenLen int

	// DatagramSize is what Chrome pads an Initial datagram to. RFC 9000
	// requires at least 1200; Chrome sends 1250, and that 50-byte difference is
	// as visible on the wire as anything in the ClientHello.
	DatagramSize int

	// TransportParams maps a parameter id to its value for every parameter
	// whose value is a varint. A map because the order is shuffled.
	TransportParams map[uint64]uint64

	// ConnectionOptions is Google's 0x3128 parameter, four ASCII bytes.
	ConnectionOptions string

	// ChosenVersion is the first field of version_information (0x11). The rest
	// of that parameter is the available-versions list, which holds QUIC v1 and
	// one reserved GREASE version in an order that moves per connection.
	ChosenVersion uint32
}

// Transport parameter ids this profile sends. Named so a diff reads as a
// parameter rather than as a number.
const (
	TPMaxIdleTimeout                 = 0x01
	TPMaxUDPPayloadSize              = 0x03
	TPInitialMaxData                 = 0x04
	TPInitialMaxStreamDataBidiLocal  = 0x05
	TPInitialMaxStreamDataBidiRemote = 0x06
	TPInitialMaxStreamDataUni        = 0x07
	TPInitialMaxStreamsBidi          = 0x08
	TPInitialMaxStreamsUni           = 0x09
	TPInitialSourceConnectionID      = 0x0f
	TPVersionInformation             = 0x11
	TPMaxDatagramFrameSize           = 0x20

	// TPGoogleConnectionOptions is Google's own parameter. Its value here is
	// the four ASCII bytes "ORIG".
	TPGoogleConnectionOptions = 0x3128
)

// Chrome151QUIC is Chrome 151.0.7922.77 on Windows 10, speaking HTTP/3 to
// cloudflare-quic.com.
//
// Confirmed against two further connections captured in the same run — to
// hosts fronted by Cloudflare and by Google Cloud, from a different
// application on the same machine — which reproduced this JA4, JA4R, cipher
// list, group list, signature algorithms and transport parameter values
// exactly, differing only in the shuffled orders described above and in the
// per-origin ECH payload.
var Chrome151QUIC = Reference{
	Device: "Chrome 151.0.7922.77, Windows 10 (19045), AMD64",
	Target: "cloudflare-quic.com",

	JA4: "q13d0311h3_55b375c5d22e_653d80c3fe9d",
	JA4R: "q13d0311h3_" +
		"1301,1302,1303_" +
		"000a,000d,001b,002b,002d,0033,0039,44cd,fe0d_" +
		"0403,0804,0401,0503,0805,0501,0806,0601,0201",

	// TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.
	Ciphers: []uint16{0x1301, 0x1302, 0x1303},

	// X25519MLKEM768, X25519, secp256r1, secp384r1. The post-quantum group
	// leads, as it does on the TCP profile.
	Groups: []uint16{0x11ec, 0x001d, 0x0017, 0x0018},

	// Shares are offered for the first two only; the other two are advertised
	// and would cost a HelloRetryRequest.
	KeyShares: []uint16{0x11ec, 0x001d},

	SigAlgs: []uint16{
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
		0x0501, 0x0806, 0x0601, 0x0201,
	},

	// TLS 1.3 alone, with no GREASE version beside it.
	TLSVersions: []uint16{0x0304},

	// server_name, supported_groups, signature_algorithms, alpn,
	// compress_certificate, supported_versions, psk_key_exchange_modes,
	// key_share, quic_transport_parameters, application_settings,
	// encrypted_client_hello.
	ExtensionSet: []uint16{
		0x0000, 0x000a, 0x000d, 0x0010, 0x001b,
		0x002b, 0x002d, 0x0033, 0x0039, 0x44cd, 0xfe0d,
	},

	SessionIDLen: 0,
	ALPN:         []string{"h3"},

	DCIDLen:      8,
	SCIDLen:      0,
	TokenLen:     0,
	DatagramSize: 1250,

	TransportParams: map[uint64]uint64{
		TPMaxIdleTimeout:                 30000,
		TPMaxUDPPayloadSize:              1472,
		TPInitialMaxData:                 15728640,
		TPInitialMaxStreamDataBidiLocal:  6291456,
		TPInitialMaxStreamDataBidiRemote: 6291456,
		TPInitialMaxStreamDataUni:        6291456,
		TPInitialMaxStreamsBidi:          100,
		TPInitialMaxStreamsUni:           103,
		TPMaxDatagramFrameSize:           65536,
	},

	ConnectionOptions: "ORIG",
	ChosenVersion:     Version1,
}
