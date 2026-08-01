package ctls

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	// recordHeaderLen is the TLS record header: type(1) + version(2) + length(2).
	recordHeaderLen = 5

	// maxPlaintextRecord is the largest plaintext we put in one record.
	maxPlaintextRecord = 16384

	// maxCiphertextRecord is the largest record body RFC 8446 §5.2 allows a
	// peer to send us: the plaintext limit plus 256 bytes of expansion.
	maxCiphertextRecord = maxPlaintextRecord + 256

	// recordReadBuf sizes the buffered reader. It holds a full-size record
	// header plus body, so an ordinary record costs one syscall rather than
	// one for the 5-byte header and another for the body.
	recordReadBuf = recordHeaderLen + maxCiphertextRecord
)

// newRecordReader wraps conn so record reads are buffered.
//
// The same reader has to be used for the handshake and for the connection that
// comes out of it: buffering can pull the first application-data bytes off the
// socket while reading the last handshake record, and those bytes are only
// recoverable from the reader that holds them.
func newRecordReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReaderSize(conn, recordReadBuf)
}

// tlsRecord represents a TLS record layer message.
type tlsRecord struct {
	typ  uint8
	data []byte
}

// writeRawRecord writes a TLS record to the connection.
// Per RFC 8446: ClientHello uses 0x0301, all other records use 0x0303.
func writeRawRecord(conn net.Conn, typ uint8, data []byte) error {
	buf := make([]byte, recordHeaderLen+len(data))
	buf[0] = typ
	// ClientHello (handshake, first record) uses 0x0301 for compat.
	// All other records (CCS, encrypted) MUST use 0x0303 per RFC 8446 §5.1.
	if typ == recordTypeHandshake {
		binary.BigEndian.PutUint16(buf[1:], versionTLS10) // 0x0301
	} else {
		binary.BigEndian.PutUint16(buf[1:], versionTLS12) // 0x0303
	}
	binary.BigEndian.PutUint16(buf[3:], uint16(len(data)))
	copy(buf[recordHeaderLen:], data)
	_, err := conn.Write(buf)
	return err
}

// readRawRecord reads a single TLS record from the connection.
func readRawRecord(r io.Reader) (*tlsRecord, error) {
	var header [recordHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read record header: %w", err)
	}

	typ := header[0]
	length := binary.BigEndian.Uint16(header[3:])

	if length > maxCiphertextRecord {
		return nil, fmt.Errorf("record too large: %d bytes", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read record body: %w", err)
	}

	return &tlsRecord{typ: typ, data: data}, nil
}

// encryptedRecord handles AEAD encryption/decryption of TLS 1.3 records.
// In TLS 1.3, all records after ServerHello are encrypted as ApplicationData (type 23).
//
// It is not safe for concurrent use: the sequence number must advance exactly
// once per record, and reusing a nonce voids the cipher's security. Conn
// serialises the write side with a mutex; the read side is single-goroutine.
type encryptedRecord struct {
	aead cipher.AEAD
	iv   [12]byte
	seq  uint64

	// nonceBuf and adBuf are scratch for the per-record nonce and additional
	// data. Both are fields rather than locals because they are passed to an
	// interface method, which makes the compiler heap-allocate a local array
	// on every single record.
	nonceBuf [12]byte
	adBuf    [recordHeaderLen]byte
}

// newEncryptedRecord creates an encrypted record handler.
func newEncryptedRecord(aead cipher.AEAD, iv []byte) *encryptedRecord {
	er := &encryptedRecord{aead: aead}
	copy(er.iv[:], iv)
	return er
}

// nonce derives the per-record nonce by XOR-ing the base IV with the sequence
// number, then advances the sequence. The returned slice is scratch owned by
// er and is valid only until the next call.
func (er *encryptedRecord) nonce() []byte {
	er.nonceBuf = er.iv
	seq := er.seq
	// XOR the trailing 8 bytes with the big-endian sequence number.
	for i := 11; i >= 4; i-- {
		er.nonceBuf[i] ^= byte(seq)
		seq >>= 8
	}
	er.seq++
	return er.nonceBuf[:]
}

// sealRecord encrypts plaintext into a complete TLS record — header included —
// using buf as storage, and returns the filled slice. Pass the previous return
// value back in to reuse the allocation.
//
// additional_data = type(1) || version(2) || length(2) of ciphertext
func (er *encryptedRecord) sealRecord(buf []byte, plaintext []byte, innerType uint8) ([]byte, error) {
	// Inner content = plaintext || content_type byte (TLS 1.3 inner type)
	innerLen := len(plaintext) + 1
	cipherLen := innerLen + er.aead.Overhead()
	total := recordHeaderLen + cipherLen

	if cap(buf) < total {
		buf = make([]byte, total)
	}
	buf = buf[:total]

	// TLSCiphertext header, which doubles as the additional data.
	buf[0] = recordTypeApplicationData
	binary.BigEndian.PutUint16(buf[1:], versionTLS12)
	binary.BigEndian.PutUint16(buf[3:], uint16(cipherLen))

	inner := buf[recordHeaderLen : recordHeaderLen+innerLen]
	copy(inner, plaintext)
	inner[len(plaintext)] = innerType

	// Sealing into inner[:0] is the documented in-place form, so the
	// ciphertext lands straight after the header with no second buffer.
	sealed := er.aead.Seal(inner[:0], er.nonce(), inner, buf[:recordHeaderLen])
	return buf[:recordHeaderLen+len(sealed)], nil
}

// encrypt encrypts a TLS 1.3 record body, without the record header.
func (er *encryptedRecord) encrypt(plaintext []byte, innerType uint8) ([]byte, error) {
	record, err := er.sealRecord(nil, plaintext, innerType)
	if err != nil {
		return nil, err
	}
	return record[recordHeaderLen:], nil
}

// decrypt decrypts a TLS 1.3 record and returns (plaintext, innerType, error).
// The plaintext aliases ciphertext, which is decrypted in place.
func (er *encryptedRecord) decrypt(ciphertext []byte) ([]byte, uint8, error) {
	if len(ciphertext) < er.aead.Overhead()+1 {
		return nil, 0, fmt.Errorf("ciphertext too short")
	}

	// Reconstruct additional data
	er.adBuf[0] = recordTypeApplicationData
	binary.BigEndian.PutUint16(er.adBuf[1:], versionTLS12)
	binary.BigEndian.PutUint16(er.adBuf[3:], uint16(len(ciphertext)))

	inner, err := er.aead.Open(ciphertext[:0], er.nonce(), ciphertext, er.adBuf[:])
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
