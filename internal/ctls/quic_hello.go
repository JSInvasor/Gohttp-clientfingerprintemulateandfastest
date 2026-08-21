package ctls

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// Chrome's QUIC ClientHello.
//
// This is not the TCP hello with one extension added, and treating it that way
// is the mistake the file exists to prevent. Read off a real Chrome 151 on
// Windows (see internal/quic/reference.go and the captures under its testdata),
// the two differ in six ways, every one of which is visible on the first
// packet:
//
//   - No GREASE anywhere in the hello. The TCP profile carries a GREASE cipher,
//     a GREASE extension at each end, a GREASE group and a GREASE key share;
//     the QUIC one carries none of them. Chrome's GREASE moved down a layer,
//     into a reserved transport parameter and a reserved version — see
//     internal/quic/transportparams.go — and up one, into the HTTP/3 SETTINGS
//     frame.
//   - The legacy session id is empty. The TCP hello sends 32 random bytes for
//     the benefit of middleboxes that expect a session to resume; inside an
//     encrypted QUIC packet there is no middlebox to reassure.
//   - Three cipher suites, not sixteen. TLS 1.3 is the only version offered, so
//     the TLS 1.2 suites that fill out the TCP list have nothing to negotiate.
//   - supported_versions offers TLS 1.3 alone — no GREASE, and no TLS 1.2.
//   - Six extensions are gone: ec_point_formats, extended_master_secret,
//     signed_certificate_timestamp, renegotiation_info, status_request and
//     session_ticket. All six exist for TLS-over-TCP's history, and QUIC
//     inherits none of it.
//   - The signature algorithms differ in both directions: the three ML-DSA
//     entries the TCP profile leads with are absent, and rsa_pkcs1_sha1 is
//     present at the end where TCP has none.
//
// What carries over unchanged: the extension permutation, the
// X25519MLKEM768 + X25519 key share, the four supported groups, and brotli
// certificate compression.
//
// The fresh hello is eleven extensions and hashes to
// q13d0311h3_55b375c5d22e_653d80c3fe9d. A resumed one adds pre_shared_key and
// early_data for thirteen, and hashes to q13d0313h3_55b375c5d22e_226f3f127bbe.
// Both are pinned in internal/quic/reference.go against device captures, and
// internal/quic's tests build this hello and check it against them.

// extQUICTransportParameters is RFC 9001 section 8.2. It carries the QUIC
// transport parameters, which this package treats as an opaque blob: encoding
// them is internal/quic's job, and pushing that knowledge down here would put
// a QUIC layout inside the TLS layer for no gain.
const extQUICTransportParameters = 0x0039

// quicCipherSuites is the whole cipher list: the three TLS 1.3 suites, no
// GREASE, in the order Chrome sends them.
var quicCipherSuites = []uint16{
	cipherTLS_AES_128_GCM_SHA256,
	cipherTLS_AES_256_GCM_SHA384,
	cipherTLS_CHACHA20_POLY1305_SHA256,
}

// quicSigAlgs is Chrome's signature_algorithms over QUIC.
//
// Nine entries, and neither a subset nor a superset of the TCP profile's
// eleven: the ML-DSA algorithms are absent and rsa_pkcs1_sha1 closes the list.
var quicSigAlgs = []uint16{
	0x0403, // ecdsa_secp256r1_sha256
	0x0804, // rsa_pss_rsae_sha256
	0x0401, // rsa_pkcs1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0805, // rsa_pss_rsae_sha384
	0x0501, // rsa_pkcs1_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0601, // rsa_pkcs1_sha512
	0x0201, // rsa_pkcs1_sha1
}

// quicALPSProtocols is what application_settings advertises. ALPS names the
// protocol it applies to, so over QUIC it is h3 where the TCP profile says h2.
var quicALPSProtocols = []string{"h3"}

// QUICHelloConfig is what a caller supplies to build the hello.
type QUICHelloConfig struct {
	// ServerName goes into SNI. An address-form target omits the extension, the
	// same way the TCP builders do.
	ServerName string

	// ALPN is the protocol list. One entry, "h3", for this profile.
	ALPN []string

	// TransportParams is the encoded body of extension 0x0039, built by
	// internal/quic. Required: a QUIC ClientHello without it is not one.
	TransportParams []byte
}

// QUICClientHello is a built hello together with the private state needed to
// finish the handshake it opens.
//
// Bytes is what goes into a CRYPTO frame. The key material stays unexported
// because nothing outside this package has any business holding it; the QUIC
// handshake driver that will consume it lives here too.
type QUICClientHello struct {
	Bytes []byte

	km *keyMaterial
}

// BuildChromeQUICClientHello builds Chrome's fresh QUIC ClientHello.
//
// Resumption is deliberately not offered through this signature yet. The
// resumed shape is known and pinned — thirteen extensions, pre_shared_key last
// and early_data beside it, hashing to q13d0313h3_… — and the builder below
// produces it when handed an offer. What does not exist yet is anything that
// can hold a QUIC session ticket to make the offer from, and inventing an
// exported type to pass a ticket that nothing issues would be an API shaped
// around a test rather than around a use.
func BuildChromeQUICClientHello(cfg QUICHelloConfig) (*QUICClientHello, error) {
	if len(cfg.TransportParams) == 0 {
		return nil, errors.New("ctls: QUIC ClientHello needs transport parameters")
	}
	km, err := generateKeyMaterial()
	if err != nil {
		return nil, err
	}
	msg, err := buildChromeQUICClientHelloWith(cfg, km, nil)
	if err != nil {
		return nil, err
	}
	return &QUICClientHello{Bytes: msg, km: km}, nil
}

// buildChromeQUICClientHelloWith is the builder proper, split out so tests can
// drive it with key material they already hold.
func buildChromeQUICClientHelloWith(cfg QUICHelloConfig, km *keyMaterial, psk *pskOffer) ([]byte, error) {
	exts, err := buildChromeQUICExtensions(cfg, km, psk)
	if err != nil {
		return nil, err
	}

	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}

	body := make([]byte, 0, 64+len(exts))
	body = appendUint16(body, versionTLS12) // legacy_version
	body = append(body, random[:]...)
	body = append(body, 0) // legacy_session_id: empty

	body = appendUint16(body, uint16(len(quicCipherSuites)*2))
	for _, cs := range quicCipherSuites {
		body = appendUint16(body, cs)
	}

	body = append(body, 1, 0x00) // compression methods: null only

	body = appendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	msg := make([]byte, 4+len(body))
	msg[0] = handshakeTypeClientHello
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)

	// The binder is an HMAC over this message truncated just before the binder
	// itself, so it can only be filled in once everything else is assembled.
	if psk != nil {
		finishBinder(msg, hashForCipher(psk.ticket.suite), psk.ticket.psk)
	}
	return msg, nil
}

// buildChromeQUICExtensions assembles the extension block.
//
// Every extension goes through the shuffle. The TCP builder pins a GREASE
// extension at each end and permutes only what is between them; here there are
// no GREASE extensions to pin, so nothing is anchored except pre_shared_key,
// which RFC 8446 section 4.2.11 requires to be last.
func buildChromeQUICExtensions(cfg QUICHelloConfig, km *keyMaterial, psk *pskOffer) ([]byte, error) {
	keyShareData, err := buildQUICKeyShare(km)
	if err != nil {
		return nil, err
	}
	echGrease, err := buildECHGrease()
	if err != nil {
		return nil, err
	}

	exts := []chromeExt{
		{extSupportedVersions, buildQUICSupportedVersions()},
		{extSupportedGroups, buildQUICSupportedGroups()},
		{extSignatureAlgorithms, buildQUICSigAlgs()},
		{extKeyShare, keyShareData},
		{extPSKKeyExchangeModes, []byte{1, pskModePSKDHE}},
		{extCompressCertificate, []byte{0x02, 0x00, 0x02}}, // brotli only
		{extALPS, buildALPS(quicALPSProtocols)},
		{extECH, echGrease},
		{extQUICTransportParameters, cfg.TransportParams},
	}
	if host, ok := sniHostName(cfg.ServerName); ok {
		exts = append(exts, chromeExt{extServerName, buildSNI(host)})
	}
	if alpnData := buildALPN(cfg.ALPN); alpnData != nil {
		exts = append(exts, chromeExt{extALPN, alpnData})
	}
	// Chrome offers 0-RTT on every resumption the capture shows, so early_data
	// travels with the PSK rather than being a separate choice.
	if psk != nil {
		exts = append(exts, chromeExt{extEarlyData, nil})
	}

	if err := shuffleChromeExts(exts); err != nil {
		return nil, err
	}

	var out []byte
	for _, e := range exts {
		out = appendExt(out, e.typ, e.data)
	}
	if psk != nil {
		out = appendExt(out, extPreSharedKey,
			buildPSKExtension(psk.ticket.identity, psk.age, hashForCipher(psk.ticket.suite)().Size()))
	}
	return out, nil
}

// buildQUICKeyShare offers X25519MLKEM768 and X25519, with no GREASE entry
// ahead of them.
func buildQUICKeyShare(km *keyMaterial) ([]byte, error) {
	x25519Pub := km.x25519Priv.PublicKey().Bytes()

	mlkemShare := make([]byte, 0, len(km.mlkemPub)+len(x25519Pub))
	mlkemShare = append(mlkemShare, km.mlkemPub...)
	mlkemShare = append(mlkemShare, x25519Pub...)

	sharesLen := 2 + 2 + len(mlkemShare) + 2 + 2 + len(x25519Pub)
	data := make([]byte, 2, 2+sharesLen)
	binary.BigEndian.PutUint16(data[0:], uint16(sharesLen))

	data = appendUint16(data, groupX25519MLKEM768)
	data = appendUint16(data, uint16(len(mlkemShare)))
	data = append(data, mlkemShare...)

	data = appendUint16(data, groupX25519)
	data = appendUint16(data, uint16(len(x25519Pub)))
	data = append(data, x25519Pub...)

	return data, nil
}

// buildQUICSupportedGroups: X25519MLKEM768, X25519, P-256, P-384. No GREASE.
func buildQUICSupportedGroups() []byte {
	groups := []uint16{groupX25519MLKEM768, groupX25519, groupP256, groupP384}
	data := make([]byte, 2, 2+len(groups)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(groups)*2))
	for _, g := range groups {
		data = appendUint16(data, g)
	}
	return data
}

// buildQUICSupportedVersions offers TLS 1.3 and nothing else — no GREASE, and
// no TLS 1.2 fallback, since QUIC has no version below 1.3 to fall back to.
func buildQUICSupportedVersions() []byte {
	return []byte{0x02, 0x03, 0x04}
}

func buildQUICSigAlgs() []byte {
	data := make([]byte, 2, 2+len(quicSigAlgs)*2)
	binary.BigEndian.PutUint16(data[0:], uint16(len(quicSigAlgs)*2))
	for _, a := range quicSigAlgs {
		data = appendUint16(data, a)
	}
	return data
}
