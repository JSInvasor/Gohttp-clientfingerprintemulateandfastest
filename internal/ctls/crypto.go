package ctls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// hashForCipher returns the hash function for the given cipher suite.
func hashForCipher(suite uint16) func() hash.Hash {
	switch suite {
	case cipherTLS_AES_256_GCM_SHA384:
		return sha512.New384
	default:
		// AES-128-GCM-SHA256 and CHACHA20-POLY1305-SHA256
		return sha256.New
	}
}

// hashLen returns the hash output length for the given cipher suite.
func hashLen(suite uint16) int {
	if suite == cipherTLS_AES_256_GCM_SHA384 {
		return 48
	}
	return 32
}

// aeadForCipher creates an AEAD cipher for the given cipher suite and key.
func aeadForCipher(suite uint16, key []byte) (cipher.AEAD, error) {
	switch suite {
	case cipherTLS_AES_128_GCM_SHA256:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)

	case cipherTLS_AES_256_GCM_SHA384:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)

	case cipherTLS_CHACHA20_POLY1305_SHA256:
		return chacha20poly1305.New(key)

	default:
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", suite)
	}
}

// keyLenForCipher returns the key length for the given cipher suite.
func keyLenForCipher(suite uint16) int {
	switch suite {
	case cipherTLS_AES_128_GCM_SHA256:
		return 16
	case cipherTLS_AES_256_GCM_SHA384:
		return 32
	case cipherTLS_CHACHA20_POLY1305_SHA256:
		return 32
	default:
		return 16
	}
}

// hkdfExtract computes HKDF-Extract(salt, ikm).
func hkdfExtract(h func() hash.Hash, salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, h().Size())
	}
	mac := hmac.New(h, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpandLabel computes HKDF-Expand-Label(secret, label, context, length) as per RFC 8446.
func hkdfExpandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	// HkdfLabel = length(2) || "tls13 " + label (with length prefix) || context (with length prefix)
	tlsLabel := "tls13 " + label

	hkdfLabel := make([]byte, 0, 2+1+len(tlsLabel)+1+len(context))
	hkdfLabel = binary.BigEndian.AppendUint16(hkdfLabel, uint16(length))
	hkdfLabel = append(hkdfLabel, byte(len(tlsLabel)))
	hkdfLabel = append(hkdfLabel, tlsLabel...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	out := make([]byte, length)
	r := hkdf.Expand(h, secret, hkdfLabel)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(fmt.Sprintf("hkdf expand: %v", err))
	}
	return out
}

// deriveSecret computes Derive-Secret(secret, label, messages) as per RFC 8446.
// messages is the transcript hash context.
func deriveSecret(h func() hash.Hash, secret []byte, label string, transcriptHash []byte) []byte {
	return hkdfExpandLabel(h, secret, label, transcriptHash, h().Size())
}

// tlsKeySchedule holds the TLS 1.3 key schedule state.
type tlsKeySchedule struct {
	suite           uint16
	h               func() hash.Hash
	earlySecret     []byte
	handshakeSecret []byte
	masterSecret    []byte

	clientHSTraffic  []byte
	serverHSTraffic  []byte
	clientAppTraffic []byte
	serverAppTraffic []byte
}

// newKeySchedule initializes the TLS 1.3 key schedule with no PSK.
func newKeySchedule(suite uint16) *tlsKeySchedule {
	h := hashForCipher(suite)
	hl := h().Size()

	// Early secret = HKDF-Extract(0..0, 0..0)
	earlySecret := hkdfExtract(h, make([]byte, hl), make([]byte, hl))

	return &tlsKeySchedule{
		suite:       suite,
		h:           h,
		earlySecret: earlySecret,
	}
}

// deriveHandshakeSecrets derives handshake traffic secrets from DHE result.
// transcriptHash is the hash of ClientHello + ServerHello.
func (ks *tlsKeySchedule) deriveHandshakeSecrets(dhe []byte, transcriptHash []byte) {
	hl := ks.h().Size()

	// derived = Derive-Secret(early_secret, "derived", empty_hash)
	emptyHash := ks.h()
	derived := deriveSecret(ks.h, ks.earlySecret, "derived", emptyHash.Sum(nil))

	// handshake_secret = HKDF-Extract(derived, DHE)
	if dhe == nil {
		dhe = make([]byte, hl)
	}
	ks.handshakeSecret = hkdfExtract(ks.h, derived, dhe)

	// Client/server handshake traffic secrets
	ks.clientHSTraffic = deriveSecret(ks.h, ks.handshakeSecret, "c hs traffic", transcriptHash)
	ks.serverHSTraffic = deriveSecret(ks.h, ks.handshakeSecret, "s hs traffic", transcriptHash)
}

// deriveMasterSecrets derives application traffic secrets.
// transcriptHash is the hash of all handshake messages up to and including Finished.
func (ks *tlsKeySchedule) deriveMasterSecrets(transcriptHash []byte) {
	hl := ks.h().Size()

	// derived = Derive-Secret(handshake_secret, "derived", empty_hash)
	emptyHash := ks.h()
	derived := deriveSecret(ks.h, ks.handshakeSecret, "derived", emptyHash.Sum(nil))

	// master_secret = HKDF-Extract(derived, 0)
	ks.masterSecret = hkdfExtract(ks.h, derived, make([]byte, hl))

	// Application traffic secrets
	ks.clientAppTraffic = deriveSecret(ks.h, ks.masterSecret, "c ap traffic", transcriptHash)
	ks.serverAppTraffic = deriveSecret(ks.h, ks.masterSecret, "s ap traffic", transcriptHash)
}

// makeTrafficKeys creates AEAD + IV from a traffic secret.
func (ks *tlsKeySchedule) makeTrafficKeys(trafficSecret []byte) (cipher.AEAD, []byte, error) {
	keyLen := keyLenForCipher(ks.suite)
	key := hkdfExpandLabel(ks.h, trafficSecret, "key", nil, keyLen)
	iv := hkdfExpandLabel(ks.h, trafficSecret, "iv", nil, 12)

	aead, err := aeadForCipher(ks.suite, key)
	if err != nil {
		return nil, nil, err
	}
	return aead, iv, nil
}

// finishedKey computes the HMAC key for the Finished message.
func (ks *tlsKeySchedule) finishedKey(trafficSecret []byte) []byte {
	return hkdfExpandLabel(ks.h, trafficSecret, "finished", nil, ks.h().Size())
}

// computeFinishedMAC computes HMAC(finishedKey, transcriptHash).
func computeFinishedMAC(h func() hash.Hash, finishedKey, transcriptHash []byte) []byte {
	mac := hmac.New(h, finishedKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil)
}
