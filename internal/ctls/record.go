package ctls

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

// tlsRecord represents a TLS record layer message.
type tlsRecord struct {
	typ  uint8
	data []byte
}

// writeRawRecord writes a TLS record to the connection.
// Per RFC 8446: ClientHello uses 0x0301, all other records use 0x0303.
func writeRawRecord(conn net.Conn, typ uint8, data []byte) error {
	buf := make([]byte, 5+len(data))
	buf[0] = typ
	// ClientHello (handshake, first record) uses 0x0301 for compat.
	// All other records (CCS, encrypted) MUST use 0x0303 per RFC 8446 §5.1.
	if typ == recordTypeHandshake {
		binary.BigEndian.PutUint16(buf[1:], versionTLS10) // 0x0301
	} else {
		binary.BigEndian.PutUint16(buf[1:], versionTLS12) // 0x0303
	}
	binary.BigEndian.PutUint16(buf[3:], uint16(len(data)))
	copy(buf[5:], data)
	_, err := conn.Write(buf)
	return err
}

// readRawRecord reads a single TLS record from the connection.
func readRawRecord(r io.Reader) (*tlsRecord, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read record header: %w", err)
	}

	typ := header[0]
	vers := binary.BigEndian.Uint16(header[1:3])
	length := binary.BigEndian.Uint16(header[3:])

	// Reject anything that is not a TLS record before trusting the length
	// field. A cleartext reply on the socket (a proxy answering CONNECT with
	// "HTTP/1.1 407 ...", a captive portal) otherwise reads its own ASCII as a
	// length and reports a nonsense "record too large" instead of the bytes.
	if typ < recordTypeChangeCipherSpec || typ > recordTypeApplicationData || vers>>8 != 0x03 {
		return nil, fmt.Errorf("not a TLS record: header %s (%q)", hexBytes(header), printableBytes(header))
	}

	if length > 16384+256 {
		return nil, fmt.Errorf("record too large: %d bytes", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read record body: %w", err)
	}

	return &tlsRecord{typ: typ, data: data}, nil
}

// hexBytes renders bytes as space-separated lowercase hex for error messages.
func hexBytes(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}

// printableBytes renders bytes as text with non-printables as '.', so a
// cleartext reply is recognizable at a glance.
func printableBytes(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			out[i] = '.'
			continue
		}
		out[i] = c
	}
	return string(out)
}

// encryptedRecord handles AEAD encryption/decryption of TLS 1.3 records.
// In TLS 1.3, all records after ServerHello are encrypted as ApplicationData (type 23).
type encryptedRecord struct {
	aead cipher.AEAD
	iv   [12]byte
	seq  uint64
}

// newEncryptedRecord creates an encrypted record handler.
func newEncryptedRecord(aead cipher.AEAD, iv []byte) *encryptedRecord {
	er := &encryptedRecord{aead: aead}
	copy(er.iv[:], iv)
	return er
}

// nonce derives the per-record nonce by XOR-ing the base IV with the sequence number.
func (er *encryptedRecord) nonce() []byte {
	nonce := make([]byte, 12)
	copy(nonce, er.iv[:])
	// XOR last 8 bytes with big-endian sequence number
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, er.seq)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}
	er.seq++
	return nonce
}

// encrypt encrypts a TLS 1.3 record.
// additional_data = type(1) || version(2) || length(2) of ciphertext
func (er *encryptedRecord) encrypt(plaintext []byte, innerType uint8) ([]byte, error) {
	// Inner content = plaintext || content_type byte (TLS 1.3 inner type)
	inner := make([]byte, len(plaintext)+1)
	copy(inner, plaintext)
	inner[len(plaintext)] = innerType

	// Ciphertext length = inner_length + tag_length
	cipherLen := len(inner) + er.aead.Overhead()

	// Additional data: TLSCiphertext header
	// type=23 (Application Data), version=0x0303, length=cipherLen
	additional := make([]byte, 5)
	additional[0] = recordTypeApplicationData
	binary.BigEndian.PutUint16(additional[1:], versionTLS12)
	binary.BigEndian.PutUint16(additional[3:], uint16(cipherLen))

	nonce := er.nonce()
	ciphertext := er.aead.Seal(nil, nonce, inner, additional)
	return ciphertext, nil
}

// decrypt decrypts a TLS 1.3 record and returns (plaintext, innerType, error).
func (er *encryptedRecord) decrypt(ciphertext []byte) ([]byte, uint8, error) {
	if len(ciphertext) < er.aead.Overhead()+1 {
		return nil, 0, fmt.Errorf("ciphertext too short")
	}

	// Reconstruct additional data
	additional := make([]byte, 5)
	additional[0] = recordTypeApplicationData
	binary.BigEndian.PutUint16(additional[1:], versionTLS12)
	binary.BigEndian.PutUint16(additional[3:], uint16(len(ciphertext)))

	nonce := er.nonce()
	inner, err := er.aead.Open(nil, nonce, ciphertext, additional)
	if err != nil {
		return nil, 0, fmt.Errorf("aead decrypt: %w", err)
	}

	// Strip padding zeros and find inner content type
	i := len(inner) - 1
	for i >= 0 && inner[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, 0, fmt.Errorf("no content type byte in inner plaintext")
	}

	innerType := inner[i]
	return inner[:i], innerType, nil
}
