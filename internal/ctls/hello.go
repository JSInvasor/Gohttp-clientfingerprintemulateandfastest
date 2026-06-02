package ctls

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	mlkem "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// mlkem768PubKeySize is the public key size for ML-KEM-768 (FIPS 203).
const mlkem768PubKeySize = 1184

// keyMaterial holds generated key pairs.
//
// Safari iOS 18 only advertises an X25519 key share, but we still generate
// ML-KEM-768 and P-256 keys so handshake.go's processServerKeyShare can
// service a server that chooses one of those groups (defensive — never
// reached when the ClientHello only lists X25519, but kept so a future
// profile tweak doesn't crash the handshake decoder).
type keyMaterial struct {
	mlkemPub   []byte
	mlkemPriv  *mlkem.PrivateKey
	x25519Priv *ecdh.PrivateKey
	p256Priv   *ecdh.PrivateKey
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

func buildSNI(serverName string) []byte {
	nameBytes := []byte(serverName)
	data := make([]byte, 2+1+2+len(nameBytes))
	binary.BigEndian.PutUint16(data[0:], uint16(1+2+len(nameBytes)))
	data[2] = 0x00 // name_type: host_name
	binary.BigEndian.PutUint16(data[3:], uint16(len(nameBytes)))
	copy(data[5:], nameBytes)
	return data
}

func buildALPN(alpn []string) []byte {
	total := 0
	for _, proto := range alpn {
		total += 1 + len(proto)
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
	return []byte{
		0x01,       // status_type: ocsp
		0x00, 0x00, // responder_id_list length: 0
		0x00, 0x00, // request_extensions length: 0
	}
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
