package ctls

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	mlkem "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// mlkem768PubKeySize is the public key size for ML-KEM-768 (FIPS 203).
const mlkem768PubKeySize = 1184

// keyMaterial holds generated key pairs.
//
// Both profiles advertise X25519MLKEM768 and X25519 key shares. The P-256 key
// is generated anyway so handshake.go's processServerKeyShare can service a
// server that picks that group (defensive — not reachable from the shares we
// actually offer, but kept so a future profile tweak cannot turn an unexpected
// selection into a failed handshake).
type keyMaterial struct {
	mlkemPub   []byte
	mlkemPriv  *mlkem.PrivateKey
	x25519Priv *ecdh.PrivateKey
	p256Priv   *ecdh.PrivateKey

	// retryGroup/retryPriv hold the key generated to answer a
	// HelloRetryRequest, for the case where the group the server picked is not
	// one of the two we keep ready. P-384 and P-521 keygen is expensive enough
	// that doing it on every handshake to serve a path almost nothing takes
	// would be a real cost, so it happens on demand.
	retryGroup uint16
	retryPriv  *ecdh.PrivateKey
}

// ecdhCurveForGroup maps a TLS NamedGroup to its curve, or nil for a group that
// is not a plain ECDH curve (X25519MLKEM768, GREASE, anything unknown).
func ecdhCurveForGroup(group uint16) ecdh.Curve {
	switch group {
	case groupX25519:
		return ecdh.X25519()
	case groupP256:
		return ecdh.P256()
	case groupP384:
		return ecdh.P384()
	case groupP521:
		return ecdh.P521()
	default:
		return nil
	}
}

// privateKeyFor returns the ECDH private key held for group, or nil.
func (km *keyMaterial) privateKeyFor(group uint16) *ecdh.PrivateKey {
	switch group {
	case groupX25519:
		return km.x25519Priv
	case groupP256:
		return km.p256Priv
	}
	if km.retryPriv != nil && km.retryGroup == group {
		return km.retryPriv
	}
	return nil
}

// generateRetryKey makes a key for group available to privateKeyFor, and
// returns the public key to put in the second ClientHello's key_share.
func (km *keyMaterial) generateRetryKey(group uint16) ([]byte, error) {
	if priv := km.privateKeyFor(group); priv != nil {
		return priv.PublicKey().Bytes(), nil
	}
	curve := ecdhCurveForGroup(group)
	if curve == nil {
		return nil, fmt.Errorf("no key exchange for group 0x%04x", group)
	}
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key for group 0x%04x: %w", group, err)
	}
	km.retryGroup = group
	km.retryPriv = priv
	return priv.PublicKey().Bytes(), nil
}

// generateKeyMaterial generates key pairs for X25519MLKEM768, X25519, and P-256.
func generateKeyMaterial() (*keyMaterial, error) {
	pub, priv, err := mlkem.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate mlkem768 key: %w", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal mlkem768 pub: %w", err)
	}

	privX25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}

	privP256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate p256 key: %w", err)
	}

	return &keyMaterial{
		mlkemPub:   pubBytes,
		mlkemPriv:  priv,
		x25519Priv: privX25519,
		p256Priv:   privP256,
	}, nil
}

// greaseSet holds the GREASE values used at the six positions Safari and Chrome
// sprinkle them into a single ClientHello. A fresh set is drawn per connection.
type greaseSet struct {
	cipher   uint16 // GREASE in cipher suite list
	extFirst uint16 // GREASE as first extension
	extLast  uint16 // GREASE as second-to-last extension
	keyShare uint16 // GREASE in key_share — always equal to group, see newGreaseSet
	group    uint16 // GREASE in supported_groups
	version  uint16 // GREASE in supported_versions
}

func randomGrease() uint16 {
	var b [1]byte
	rand.Read(b[:])
	return greaseValues[int(b[0])%len(greaseValues)]
}

// randomGreaseExcept returns a GREASE value that is not excl.
func randomGreaseExcept(excl uint16) uint16 {
	for {
		if v := randomGrease(); v != excl {
			return v
		}
	}
}

func newGreaseSet() greaseSet {
	// extFirst and extLast must differ. They become the types of two real
	// extensions in the same ClientHello, and RFC 8446 §4.2 forbids sending
	// two extensions of the same type — a strict server answers a duplicate
	// with a decode_error alert rather than a ServerHello.
	//
	// Drawing both independently collided 1 in 16 times, so roughly 6% of all
	// connections emitted a malformed ClientHello. Go's crypto/tls server
	// rejects those outright, which is what made TestALPNFallbackToHTTP1 fail
	// intermittently; lenient servers accept them but no real browser ever
	// sends one, so it also stands out as a non-browser signal. Both captures
	// on record show two distinct values (Safari 0x6a6a/0x5a5a, Chrome
	// 0xfafa/0xeaea).
	//
	// The other positions may legitimately coincide with each other — they
	// live in separate namespaces (a cipher, a named group, a version), so a
	// repeat there is not a protocol violation.
	extFirst := randomGrease()

	// key_share and supported_groups share ONE draw, and must keep doing so.
	//
	// The GREASE entry in key_share is a NamedGroup, so it lands in the same
	// namespace as the GREASE entry in supported_groups. RFC 8446 §4.2.8:
	//
	//	Clients MUST NOT offer any KeyShareEntry values for groups not listed
	//	in the client's "supported_groups" extension. [...] Servers MAY check
	//	for violations of these rules and abort the handshake with an
	//	"illegal_parameter" alert if one is violated.
	//
	// Drawing them independently made 15 connections in 16 offer a key share
	// for a group the hello never advertised. Most servers ignore it, which is
	// why this only ever showed up on "some sites" — but the ones that do
	// enforce §4.2.8 answer with a fatal illegal_parameter, surfacing as
	// "tls handshake: server alert: 47" with no way to retry.
	//
	// Matching them is also what the emulated browsers do. BoringSSL fills both
	// slots from a single ssl_grease_group index (there is no separate key_share
	// index), so a real Chrome hello always repeats the same value in the two
	// places, and so does Apple's stack. A mismatch is therefore a bot signal on
	// top of being a protocol violation.
	group := randomGrease()

	return greaseSet{
		cipher:   randomGrease(),
		extFirst: extFirst,
		extLast:  randomGreaseExcept(extFirst),
		keyShare: group,
		group:    group,
		version:  randomGrease(),
	}
}

// sniHostName normalises serverName into the HostName a server_name extension
// may carry, and reports whether the extension should be sent at all.
//
// Every rule here is one RFC 6066 §3 states and that a strict server enforces
// with a fatal alert — the same class of unrecoverable handshake failure as an
// illegal ClientHello field:
//
//   - Address literals are not permitted in HostName, so an IP target gets no
//     server_name at all. That is also what browsers do, and the only way to
//     reach a host serving on an IP with no matching SNI vhost. IPv6 brackets
//     and a scope-zone suffix are stripped before the check, or "fe80::1%eth0"
//     would not parse as an address and would go out as if it were a hostname.
//   - HostName is the DNS name and carries no root label, so a trailing dot is
//     stripped. "example.com." is a perfectly ordinary URL host that net/http
//     passes through untouched, and it is not a legal HostName.
//   - An empty name is dropped rather than encoded: a zero-length HostName is a
//     malformed ServerNameList, not an absent one.
//
// The result is lower-cased. DNS and SNI comparison are both case-insensitive,
// but browsers normalise the URL host before it ever reaches the TLS layer, so
// a mixed-case HostName on the wire is a difference no real client produces.
//
// IDN needs no handling here: net/http converts the host to its A-label in
// canonicalAddr before the dialer sees it, so this only ever receives ASCII.
func sniHostName(serverName string) (string, bool) {
	host := serverName
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return "", false
	}
	for len(host) > 0 && host[len(host)-1] == '.' {
		host = host[:len(host)-1]
	}
	if host == "" {
		return "", false
	}
	return strings.ToLower(host), true
}

func buildSNI(serverName string) []byte {
	nameBytes := []byte(serverName)
	data := make([]byte, 2+1+2+len(nameBytes))
	binary.BigEndian.PutUint16(data[0:], uint16(1+2+len(nameBytes)))
	data[2] = 0x00 // name_type: host_name
	binary.BigEndian.PutUint16(data[3:], uint16(len(nameBytes)))
	copy(data[5:], nameBytes)
	return data
}

// buildALPN encodes a ProtocolNameList, returning nil when there is nothing
// legal to encode.
//
// RFC 7301 gives both the list and each name a minimum length of one, so an
// empty list or a zero-length name is a malformed extension that a strict
// server rejects outright. A name over 255 bytes cannot be length-prefixed at
// all and used to wrap silently through byte(), producing an extension whose
// framing disagreed with its contents — which desynchronises the whole
// extension block, not just this one entry. Callers pass constants today; this
// keeps a future caller from turning bad input into a dead connection.
func buildALPN(alpn []string) []byte {
	usable := make([]string, 0, len(alpn))
	total := 0
	for _, proto := range alpn {
		if len(proto) == 0 || len(proto) > 255 {
			continue
		}
		usable = append(usable, proto)
		total += 1 + len(proto)
	}
	if len(usable) == 0 || total > 0xFFFF {
		return nil
	}

	data := make([]byte, 2+total)
	binary.BigEndian.PutUint16(data[0:], uint16(total))
	offset := 2
	for _, proto := range usable {
		data[offset] = byte(len(proto))
		copy(data[offset+1:], proto)
		offset += 1 + len(proto)
	}
	return data
}

func buildStatusRequest() []byte {
	return []byte{
		0x01,       // status_type: ocsp
		0x00, 0x00, // responder_id_list length: 0
		0x00, 0x00, // request_extensions length: 0
	}
}

// buildECHGrease builds a random ECH GREASE extension. Chrome always sends
// encrypted_client_hello; omitting it is a strong "not really Chrome" signal,
// and because we have no real ECHConfig for the target we send the GREASE form
// that a Chrome client emits when the server publishes no HTTPS RR.
func buildECHGrease() ([]byte, error) {
	// ECH ClientHello outer structure (GREASE form):
	// client_hello_type (1) = outer(0)
	// cipher_suite: kdf_id (2) = HKDF-SHA256, aead_id (2) = AES-128-GCM
	// config_id (1) = random
	// enc_len (2) + enc (random X25519 HPKE public key, 32 bytes)
	// payload_len (2) + payload (random)
	var configID [1]byte
	if _, err := rand.Read(configID[:]); err != nil {
		return nil, err
	}

	var enc [32]byte
	if _, err := rand.Read(enc[:]); err != nil {
		return nil, err
	}

	// Chrome derives this length from the padded ClientHelloInner, so it is not
	// a constant across all sites — but it is deterministic for a given target,
	// not a coin flip.
	//
	// 208 is measured: a real Chrome 151 against tls.peet.ws (an 11-character
	// hostname) sends payload_len = 0x00d0. The shape is consistent with the ECH
	// padding rule — pad the inner hello to a multiple of 32, then add the
	// 16-byte AEAD tag — since 208 = 6*32 + 16.
	//
	// An earlier revision used 144 (= 4*32 + 16) on the same claim of being
	// captured. The device says otherwise, so it was either misread or from a
	// release that has since moved.
	//
	// This is still a single data point at one hostname length. Modelling the
	// hostname dependency needs captures against several, and until then a
	// constant is the honest choice: JA3 and JA4 hash extension IDs only and
	// cannot see this, so the exposure is limited to a byte-level check on the
	// raw ClientHello.
	const payloadLen = 208

	payload := make([]byte, payloadLen)
	if _, err := rand.Read(payload); err != nil {
		return nil, err
	}

	var data []byte
	data = append(data, 0x00)         // client_hello_type = outer
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
