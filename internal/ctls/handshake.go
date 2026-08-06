package ctls

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"time"

	"github.com/andybalholm/brotli"
	mlkem "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// maxHandshakeMessage bounds a single reassembled handshake message and the
// amount of unconsumed handshake data we are willing to buffer. The length
// field allows 16 MiB; the largest thing a server legitimately sends is its
// certificate chain, so this uses the same 256 KiB ceiling as crypto/tls.
// Without a bound a hostile server could pin 16 MiB per connection.
const maxHandshakeMessage = 256 * 1024

// maxNoProgressRecords bounds how many consecutive records a server may send
// that carry no handshake bytes — warning alerts, ChangeCipherSpec, or empty
// payloads. Each is skipped with a `continue`, so without a ceiling a peer can
// hold the handshake loop open indefinitely by never sending anything real.
// The context deadline already bounds the wall clock; this bounds the work.
const maxNoProgressRecords = 64

// handshakeState manages the TLS 1.3 handshake.
type handshakeState struct {
	conn       net.Conn
	br         *bufio.Reader
	serverName string
	alpn       []string
	skipVerify bool
	rootCAs    *x509.CertPool
	browser    BrowserType

	km             *keyMaterial
	suite          uint16
	ks             *tlsKeySchedule
	transcript     hash.Hash
	negotiatedALPN string

	clientHelloMsg []byte
}

// handshake performs the full TLS 1.3 handshake and returns a *Conn.
func handshake(conn net.Conn, serverName string, alpn []string, skipVerify bool, rootCAs *x509.CertPool, browser BrowserType) (*Conn, error) {
	km, err := generateKeyMaterial()
	if err != nil {
		return nil, fmt.Errorf("generate keys: %w", err)
	}

	hs := &handshakeState{
		conn:       conn,
		br:         newRecordReader(conn),
		serverName: serverName,
		alpn:       alpn,
		skipVerify: skipVerify,
		rootCAs:    rootCAs,
		browser:    browser,
		km:         km,
	}

	return hs.run()
}

// handshakeReader reassembles handshake messages out of a stream of record
// payloads. RFC 8446 §5.1 lets one handshake message span several records and
// lets several messages share one record, so neither boundary can be assumed.
// Certificate chains routinely exceed the 16 KiB record limit, which is exactly
// where one-message-per-record reading breaks.
type handshakeReader struct {
	buf []byte
}

// add appends record payload bytes to the reassembly buffer.
func (hr *handshakeReader) add(data []byte) error {
	if len(hr.buf)+len(data) > maxHandshakeMessage {
		return fmt.Errorf("handshake data exceeds %d bytes", maxHandshakeMessage)
	}
	hr.buf = append(hr.buf, data...)
	return nil
}

// next returns the next complete handshake message including its 4-byte header,
// or nil when more record data is needed. The returned slice stays valid until
// the message after it is consumed.
func (hr *handshakeReader) next() ([]byte, error) {
	if len(hr.buf) < 4 {
		return nil, nil
	}
	msgLen := int(hr.buf[1])<<16 | int(hr.buf[2])<<8 | int(hr.buf[3])
	if msgLen > maxHandshakeMessage-4 {
		return nil, fmt.Errorf("handshake message length %d exceeds limit", msgLen)
	}
	if len(hr.buf) < 4+msgLen {
		return nil, nil
	}
	msg := hr.buf[:4+msgLen]
	hr.buf = hr.buf[4+msgLen:]
	return msg, nil
}

// alertError turns an alert record body into an error. Warning-level alerts
// other than close_notify carry no failure, so they return nil and the caller
// keeps reading — but the caller must also record them via warningAlert,
// because a server that warns and then hangs up otherwise leaves nothing
// behind but an unexplained EOF.
func alertError(body []byte) error {
	if len(body) < 2 {
		return fmt.Errorf("malformed alert record")
	}
	level, desc := body[0], body[1]
	if level == alertLevelFatal {
		return fmt.Errorf("server alert: %s", describeAlert(desc))
	}
	if desc == alertCloseNotify {
		return fmt.Errorf("server closed connection during handshake")
	}
	return nil
}

// warningAlert describes a non-fatal, non-close_notify alert, or returns ""
// for anything alertError already turns into a failure.
func warningAlert(body []byte) string {
	if len(body) < 2 || body[0] != alertLevelWarning || body[1] == alertCloseNotify {
		return ""
	}
	return describeAlert(body[1])
}

// readError wraps a record-read failure, naming the last warning alert the
// server sent if there was one.
//
// Warning alerts are skipped so the handshake can continue, which is correct,
// but servers routinely warn (unrecognized_name, say) and then drop the
// connection instead of alerting fatally. Without this the caller sees only
// "read record header: EOF", which reads as a dropped connection and invites
// the caller to blame the network for a rejection the server explained.
func readError(stage string, err error, lastWarning string) error {
	if lastWarning != "" {
		return fmt.Errorf("%s: %w (server had sent warning alert %s)", stage, err, lastWarning)
	}
	return fmt.Errorf("%s: %w", stage, err)
}

func (hs *handshakeState) run() (*Conn, error) {
	var chMsg []byte
	var err error
	switch hs.browser {
	case BrowserChrome:
		chMsg, err = buildChromeClientHello(hs.serverName, hs.alpn, hs.km)
	default:
		chMsg, err = buildSafariClientHello(hs.serverName, hs.alpn, hs.km)
	}
	if err != nil {
		return nil, fmt.Errorf("build client hello: %w", err)
	}
	hs.clientHelloMsg = chMsg

	if err := writeRawRecord(hs.conn, recordTypeHandshake, chMsg); err != nil {
		return nil, fmt.Errorf("send client hello: %w", err)
	}

	// Read ServerHello, reassembling across records rather than assuming a
	// single record carries the whole message.
	var shReader handshakeReader
	var serverHelloMsg []byte
	idleRecords := 0
	lastWarning := ""
	for serverHelloMsg == nil {
		rec, err := readRawRecord(hs.br)
		if err != nil {
			return nil, readError("read server hello record", err, lastWarning)
		}
		if rec.typ == recordTypeAlert || rec.typ == recordTypeChangeCipherSpec {
			if idleRecords++; idleRecords > maxNoProgressRecords {
				return nil, fmt.Errorf("server sent %d records without a server hello", idleRecords)
			}
		}
		if rec.typ == recordTypeAlert {
			if err := alertError(rec.data); err != nil {
				return nil, err
			}
			if w := warningAlert(rec.data); w != "" {
				lastWarning = w
			}
			continue
		}
		if rec.typ == recordTypeChangeCipherSpec {
			continue
		}
		if rec.typ != recordTypeHandshake {
			return nil, fmt.Errorf("expected handshake record, got %s", describeRecordType(rec.typ))
		}
		// RFC 8446 §5.1 forbids zero-length handshake fragments. Accepting them
		// also punched a hole through maxNoProgressRecords: the budget is only
		// charged for alerts and ChangeCipherSpec, so an empty handshake record
		// advanced nothing yet cost nothing, and a peer could hold this loop
		// open indefinitely. WrapConn only installs a deadline when the caller's
		// context carries one, so on a context.Background() dial that is a
		// permanent hang, not a slow failure.
		if len(rec.data) == 0 {
			return nil, fmt.Errorf("server sent a zero-length handshake fragment")
		}
		if err := shReader.add(rec.data); err != nil {
			return nil, fmt.Errorf("read server hello: %w", err)
		}
		msg, err := shReader.next()
		if err != nil {
			return nil, fmt.Errorf("read server hello: %w", err)
		}
		serverHelloMsg = msg
	}

	suite, dhe, negotiatedALPN, err := hs.parseServerHello(serverHelloMsg)
	if err != nil {
		return nil, fmt.Errorf("parse server hello: %w", err)
	}
	hs.negotiatedALPN = negotiatedALPN

	hs.suite = suite
	hs.ks = newKeySchedule(suite)

	// Initialize transcript with SHA-256 or SHA-384
	hs.transcript = hs.ks.h()
	hs.transcript.Write(chMsg)
	hs.transcript.Write(serverHelloMsg)

	// Derive handshake secrets
	transcriptHash := hs.transcript.Sum(nil)
	hs.ks.deriveHandshakeSecrets(dhe, transcriptHash)

	// Set up server handshake AEAD
	serverHSAEAD, serverHSIV, err := hs.ks.makeTrafficKeys(hs.ks.serverHSTraffic)
	if err != nil {
		return nil, fmt.Errorf("server hs keys (suite=0x%04x): %w", suite, err)
	}
	serverHSER := newEncryptedRecord(serverHSAEAD, serverHSIV)

	// Read encrypted handshake messages: EncryptedExtensions, Certificate,
	// CertificateVerify, Finished.
	var serverCerts []*x509.Certificate
	var sawCertVerify bool
	var finished bool
	var hr handshakeReader

	idleRecords = 0
	lastWarning = ""
	for !finished {
		rec, err := readRawRecord(hs.br)
		if err != nil {
			return nil, readError("read handshake", err, lastWarning)
		}

		if rec.typ != recordTypeApplicationData {
			if idleRecords++; idleRecords > maxNoProgressRecords {
				return nil, fmt.Errorf("server sent %d records carrying no handshake data", idleRecords)
			}
		}

		// Skip ChangeCipherSpec records (middlebox compat)
		if rec.typ == recordTypeChangeCipherSpec {
			continue
		}

		if rec.typ == recordTypeAlert {
			if err := alertError(rec.data); err != nil {
				return nil, err
			}
			if w := warningAlert(rec.data); w != "" {
				lastWarning = w
			}
			continue
		}

		if rec.typ != recordTypeApplicationData {
			return nil, fmt.Errorf("expected encrypted record, got %s", describeRecordType(rec.typ))
		}

		plaintext, innerType, err := serverHSER.decrypt(rec.data)
		if err != nil {
			return nil, fmt.Errorf("decrypt hs record (suite=0x%04x dheLen=%d recLen=%d): %w", hs.suite, len(dhe), len(rec.data), err)
		}

		if innerType == recordTypeAlert {
			if err := alertError(plaintext); err != nil {
				return nil, err
			}
			if w := warningAlert(plaintext); w != "" {
				lastWarning = w
			}
			// A warning alert decrypts fine but advances nothing, so it counts
			// against the same budget as a plaintext one.
			if idleRecords++; idleRecords > maxNoProgressRecords {
				return nil, fmt.Errorf("server sent %d records carrying no handshake data", idleRecords)
			}
			continue
		}

		if innerType != recordTypeHandshake {
			return nil, fmt.Errorf("expected handshake inner type, got %s", describeRecordType(innerType))
		}

		// Same rule as the plaintext loop above: an encrypted record whose
		// inner content is an empty handshake fragment is illegal, and it is
		// not charged against the no-progress budget because it arrives as
		// application data.
		if len(plaintext) == 0 {
			return nil, fmt.Errorf("server sent a zero-length handshake fragment")
		}

		if err := hr.add(plaintext); err != nil {
			return nil, err
		}

		for !finished {
			msg, err := hr.next()
			if err != nil {
				return nil, err
			}
			if msg == nil {
				break
			}
			body := msg[4:]

			switch msg[0] {
			case handshakeTypeEncryptedExtensions:
				// In TLS 1.3 ALPN is delivered here, not in ServerHello.
				// parseServerHello leaves negotiatedALPN empty for 1.3, so
				// extracting it now is what lets the caller route h1-only
				// servers to the HTTP/1.1 transport instead of pumping the
				// h2 preface into them.
				if alpn := parseEncryptedExtensionsALPN(body); alpn != "" {
					hs.negotiatedALPN = alpn
				}
				hs.transcript.Write(msg)

			case handshakeTypeCertificate:
				hs.transcript.Write(msg)
				certs, err := parseCertificate(body)
				if err != nil {
					return nil, fmt.Errorf("parse certificate: %w", err)
				}
				serverCerts = certs
				if err := hs.verifyChain(serverCerts); err != nil {
					return nil, err
				}

			case handshakeTypeCompressedCertificate:
				// RFC 8879: CompressedCertificate replaces Certificate in transcript
				hs.transcript.Write(msg)
				certs, err := parseCompressedCertificate(body)
				if err != nil {
					return nil, fmt.Errorf("parse compressed certificate: %w", err)
				}
				serverCerts = certs
				if err := hs.verifyChain(serverCerts); err != nil {
					return nil, err
				}

			case handshakeTypeCertificateVerify:
				// RFC 8446 §4.4.3: the signature covers the transcript up to
				// and including Certificate, so the hash must be taken before
				// this message is folded in.
				if !hs.skipVerify {
					if len(serverCerts) == 0 {
						return nil, fmt.Errorf("certificate_verify before certificate")
					}
					if err := verifyCertificateVerify(body, serverCerts[0], hs.transcript.Sum(nil)); err != nil {
						return nil, fmt.Errorf("certificate_verify: %w", err)
					}
				}
				hs.transcript.Write(msg)
				sawCertVerify = true

			case handshakeTypeFinished:
				// DO NOT update transcript yet - verify first
				finishedKey := hs.ks.finishedKey(hs.ks.serverHSTraffic)
				expectedMAC := computeFinishedMAC(hs.ks.h, finishedKey, hs.transcript.Sum(nil))
				if !hmac.Equal(expectedMAC, body) {
					return nil, fmt.Errorf("server finished MAC mismatch")
				}
				// Now update transcript
				hs.transcript.Write(msg)
				finished = true

			default:
				// Unknown or unhandled messages still belong in the transcript.
				// Dropping one would desynchronise the Finished MAC and turn a
				// benign extension into a handshake failure.
				hs.transcript.Write(msg)
			}
		}
	}

	// A chain that never arrived, or one that arrived without a matching
	// CertificateVerify, means the peer never proved it holds the private key.
	// Neither may be treated as "nothing to check".
	if !hs.skipVerify {
		if len(serverCerts) == 0 {
			return nil, fmt.Errorf("server sent no certificate")
		}
		if !sawCertVerify {
			return nil, fmt.Errorf("server sent no certificate_verify")
		}
	}

	// Derive master secrets (transcript up to server Finished)
	transcriptAfterSF := hs.transcript.Sum(nil)
	hs.ks.deriveMasterSecrets(transcriptAfterSF)

	// Build and send client Finished
	clientFinishedKey := hs.ks.finishedKey(hs.ks.clientHSTraffic)
	clientFinishedMAC := computeFinishedMAC(hs.ks.h, clientFinishedKey, transcriptAfterSF)

	finishedMsg := make([]byte, 4+len(clientFinishedMAC))
	finishedMsg[0] = handshakeTypeFinished
	finishedMsg[1] = byte(len(clientFinishedMAC) >> 16)
	finishedMsg[2] = byte(len(clientFinishedMAC) >> 8)
	finishedMsg[3] = byte(len(clientFinishedMAC))
	copy(finishedMsg[4:], clientFinishedMAC)

	// Send ChangeCipherSpec for TLS 1.3 middlebox compatibility.
	// Firefox sends CCS after ClientHello when session_id is non-empty (compat mode).
	// Not sending CCS is a fingerprint leak detectable by anti-bot services.
	if err := writeRawRecord(hs.conn, recordTypeChangeCipherSpec, []byte{0x01}); err != nil {
		return nil, fmt.Errorf("send ccs: %w", err)
	}

	clientHSAEAD, clientHSIV, err := hs.ks.makeTrafficKeys(hs.ks.clientHSTraffic)
	if err != nil {
		return nil, fmt.Errorf("client hs keys: %w", err)
	}
	clientHSER := newEncryptedRecord(clientHSAEAD, clientHSIV)

	encFinished, err := clientHSER.encrypt(finishedMsg, recordTypeHandshake)
	if err != nil {
		return nil, fmt.Errorf("encrypt finished: %w", err)
	}

	if err := writeRawRecord(hs.conn, recordTypeApplicationData, encFinished); err != nil {
		return nil, fmt.Errorf("send finished: %w", err)
	}

	// Derive application traffic keys
	serverAppAEAD, serverAppIV, err := hs.ks.makeTrafficKeys(hs.ks.serverAppTraffic)
	if err != nil {
		return nil, fmt.Errorf("server app keys: %w", err)
	}

	clientAppAEAD, clientAppIV, err := hs.ks.makeTrafficKeys(hs.ks.clientAppTraffic)
	if err != nil {
		return nil, fmt.Errorf("client app keys: %w", err)
	}

	return &Conn{
		Conn:            hs.conn,
		br:              hs.br,
		serverName:      hs.serverName,
		negotiatedALPN:  hs.negotiatedALPN,
		suite:           hs.suite,
		peerCerts:       serverCerts,
		ks:              hs.ks,
		serverAppSecret: hs.ks.serverAppTraffic,
		clientAppSecret: hs.ks.clientAppTraffic,
		serverReader:    newEncryptedRecord(serverAppAEAD, serverAppIV),
		clientWriter:    newEncryptedRecord(clientAppAEAD, clientAppIV),
	}, nil
}

// verifyChain validates the presented chain against the configured roots and
// the requested server name.
func (hs *handshakeState) verifyChain(certs []*x509.Certificate) error {
	if hs.skipVerify {
		return nil
	}
	if err := verifyCertificate(certs, hs.serverName, hs.rootCAs); err != nil {
		return fmt.Errorf("certificate verify: %w", err)
	}
	return nil
}

// forEachExtension walks a TLS extension block, calling fn for each entry.
// Every length in the block is attacker-controlled, so an overrun returns an
// error instead of slicing past the end.
func forEachExtension(exts []byte, fn func(extType uint16, extData []byte) error) error {
	for len(exts) > 0 {
		if len(exts) < 4 {
			return fmt.Errorf("trailing %d bytes in extension block", len(exts))
		}
		extType := binary.BigEndian.Uint16(exts[0:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if extLen > len(exts) {
			return fmt.Errorf("extension 0x%04x claims %d bytes, %d remain", extType, extLen, len(exts))
		}
		if err := fn(extType, exts[:extLen]); err != nil {
			return err
		}
		exts = exts[extLen:]
	}
	return nil
}

// parseServerHello parses a ServerHello message and returns the cipher suite,
// the DHE shared secret (X25519, P-256 or X25519MLKEM768) and the negotiated
// ALPN. data must be one complete handshake message including its header.
func (hs *handshakeState) parseServerHello(data []byte) (suite uint16, dhe []byte, alpn string, err error) {
	fail := func(format string, args ...any) (uint16, []byte, string, error) {
		return 0, nil, "", fmt.Errorf(format, args...)
	}

	if len(data) < 4 {
		return fail("server hello too short")
	}

	msgType := data[0]
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])

	if msgType != handshakeTypeServerHello {
		return fail("expected ServerHello (2), got %d", msgType)
	}
	if 4+msgLen > len(data) {
		return fail("server hello claims %d bytes, %d available", msgLen, len(data)-4)
	}

	body := data[4 : 4+msgLen]

	if len(body) < 2+32+1 {
		return fail("server hello body too short")
	}

	// A HelloRetryRequest is a ServerHello carrying this fixed random. Its
	// key_share holds a bare 2-byte group id instead of a key, so parsing it as
	// an ordinary ServerHello reads past the end of the message. We do not
	// retry: both profiles offer the key shares the browsers they emulate
	// offer, so a retry request means the server wants a group we deliberately
	// do not advertise, and answering it would change the fingerprint anyway.
	if bytes.Equal(body[2:34], helloRetryRequestRandom) {
		return fail("server sent HelloRetryRequest: no offered key share was acceptable")
	}

	// Skip legacy version (2) + random (32)
	offset := 2 + 32

	// Session ID length + session ID
	sessionIDLen := int(body[offset])
	offset += 1 + sessionIDLen

	// Cipher suite (2) + compression method (1)
	if offset+3 > len(body) {
		return fail("truncated server hello")
	}
	suite = binary.BigEndian.Uint16(body[offset:])
	offset += 2
	offset++

	switch suite {
	case cipherTLS_AES_128_GCM_SHA256, cipherTLS_AES_256_GCM_SHA384, cipherTLS_CHACHA20_POLY1305_SHA256:
	default:
		return fail("server selected unsupported cipher suite 0x%04x", suite)
	}

	// Extensions. TLS 1.3 is signalled by supported_versions, so a ServerHello
	// without extensions is by definition not a 1.3 handshake.
	if offset+2 > len(body) {
		return fail("server hello has no extensions (not TLS 1.3)")
	}
	extsLen := int(binary.BigEndian.Uint16(body[offset:]))
	offset += 2
	if offset+extsLen > len(body) {
		return fail("server hello extensions claim %d bytes, %d remain", extsLen, len(body)-offset)
	}
	exts := body[offset : offset+extsLen]

	var (
		isTLS13      bool
		keyShareData []byte
	)
	if err := forEachExtension(exts, func(extType uint16, extData []byte) error {
		switch extType {
		case extSupportedVersions:
			if len(extData) == 2 && binary.BigEndian.Uint16(extData) == versionTLS13 {
				isTLS13 = true
			}
		case extKeyShare:
			keyShareData = extData
		case extALPN:
			// protocol_name_list length (2) + protocol_length (1) + protocol
			if len(extData) >= 3 {
				protoLen := int(extData[2])
				if 3+protoLen <= len(extData) {
					alpn = string(extData[3 : 3+protoLen])
				}
			}
		}
		return nil
	}); err != nil {
		return fail("server hello extensions: %w", err)
	}

	if !isTLS13 {
		return fail("server did not negotiate TLS 1.3 (falling back not supported)")
	}
	if keyShareData == nil {
		return fail("no key_share in ServerHello")
	}

	dhe, err = hs.processServerKeyShare(keyShareData)
	if err != nil {
		return fail("key share: %w", err)
	}

	return suite, dhe, alpn, nil
}

// processServerKeyShare computes DHE shared secret from server's key share.
func (hs *handshakeState) processServerKeyShare(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("key_share too short")
	}

	group := binary.BigEndian.Uint16(data[0:])
	keyLen := int(binary.BigEndian.Uint16(data[2:]))
	if 4+keyLen > len(data) {
		return nil, fmt.Errorf("key_share claims %d bytes, %d remain", keyLen, len(data)-4)
	}
	keyData := data[4 : 4+keyLen]

	switch group {
	case groupX25519:
		// X25519 key exchange
		serverPub, err := ecdh.X25519().NewPublicKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse server x25519 key: %w", err)
		}
		shared, err := hs.km.x25519Priv.ECDH(serverPub)
		if err != nil {
			return nil, fmt.Errorf("x25519 ecdh: %w", err)
		}
		return shared, nil

	case groupX25519MLKEM768:
		// X25519MLKEM768: server sends ML-KEM-768 ciphertext (1088 bytes) || X25519 public key (32 bytes)
		const mlkemCTSize = mlkem.CiphertextSize // 1088 bytes
		// Exact, not minimum: DecapsulateTo panics on a wrong-sized ciphertext.
		if len(keyData) != mlkemCTSize+32 {
			return nil, fmt.Errorf("x25519mlkem768 key share is %d bytes, want %d", len(keyData), mlkemCTSize+32)
		}

		mlkemCT := keyData[:mlkemCTSize]
		serverX25519Bytes := keyData[mlkemCTSize:]

		// ML-KEM-768 decapsulation (FIPS 203)
		mlkemShared := make([]byte, mlkem.SharedKeySize)
		hs.km.mlkemPriv.DecapsulateTo(mlkemShared, mlkemCT)

		// X25519 ECDH
		serverX25519Pub, err := ecdh.X25519().NewPublicKey(serverX25519Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse server x25519 (mlkem combo): %w", err)
		}
		x25519Shared, err := hs.km.x25519Priv.ECDH(serverX25519Pub)
		if err != nil {
			return nil, fmt.Errorf("x25519 ecdh (mlkem combo): %w", err)
		}

		// Combine: mlkem_shared || x25519_shared (per draft-ietf-tls-hybrid-design)
		combined := append(mlkemShared, x25519Shared...)
		return combined, nil

	case groupP256:
		// P-256 ECDH key exchange
		serverPub, err := ecdh.P256().NewPublicKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse server p256 key: %w", err)
		}
		shared, err := hs.km.p256Priv.ECDH(serverPub)
		if err != nil {
			return nil, fmt.Errorf("p256 ecdh: %w", err)
		}
		return shared, nil

	default:
		return nil, fmt.Errorf("unsupported server key share group: 0x%04x", group)
	}
}

// serverSignatureContext is the context string RFC 8446 §4.4.3 mixes into the
// CertificateVerify signature so a server signature can never be replayed as a
// client one.
const serverSignatureContext = "TLS 1.3, server CertificateVerify"

// certificateVerifyPayload builds the octet string the server signed: 64 space
// characters, the context string, a zero separator, then the transcript hash.
func certificateVerifyPayload(transcriptHash []byte) []byte {
	payload := make([]byte, 0, 64+len(serverSignatureContext)+1+len(transcriptHash))
	for i := 0; i < 64; i++ {
		payload = append(payload, 0x20)
	}
	payload = append(payload, serverSignatureContext...)
	payload = append(payload, 0x00)
	payload = append(payload, transcriptHash...)
	return payload
}

// verifyCertificateVerify checks that the peer holds the private key for the
// certificate it presented (RFC 8446 §4.4.3). transcriptHash must cover every
// handshake message up to and including Certificate.
//
// Skipping this check makes the rest of the chain of trust decorative. A
// server's certificate chain is public information, so an attacker in path can
// replay a valid chain for the requested name, run its own ECDHE, and derive
// Finished keys that match — chain validation and hostname matching both still
// pass. This signature is the only step in the handshake that cannot be
// produced without the private key.
func verifyCertificateVerify(body []byte, cert *x509.Certificate, transcriptHash []byte) error {
	if len(body) < 4 {
		return fmt.Errorf("message too short")
	}
	sigAlg := binary.BigEndian.Uint16(body[0:2])
	sigLen := int(binary.BigEndian.Uint16(body[2:4]))
	if 4+sigLen > len(body) {
		return fmt.Errorf("signature claims %d bytes, %d remain", sigLen, len(body)-4)
	}
	sig := body[4 : 4+sigLen]
	payload := certificateVerifyPayload(transcriptHash)

	switch sigAlg {
	case sigEd25519:
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("ed25519 scheme with %T certificate key", cert.PublicKey)
		}
		// Ed25519 signs the payload directly; there is no pre-hash.
		if !ed25519.Verify(pub, payload, sig) {
			return fmt.Errorf("ed25519 signature mismatch")
		}
		return nil

	case sigECDSAP256SHA256, sigECDSAP384SHA384, sigECDSAP521SHA512:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ecdsa scheme with %T certificate key", cert.PublicKey)
		}
		curve, h := ecdsaSchemeParams(sigAlg)
		// RFC 8446 §4.2.3 binds each ECDSA scheme to exactly one curve.
		// Accepting a mismatch would let a P-256 key be verified under the
		// P-384 code point.
		if pub.Curve != curve {
			return fmt.Errorf("ecdsa key on %s used with scheme 0x%04x", pub.Curve.Params().Name, sigAlg)
		}
		if !ecdsa.VerifyASN1(pub, hashPayload(h, payload), sig) {
			return fmt.Errorf("ecdsa signature mismatch")
		}
		return nil

	case sigRSAPSSRSAeSHA256, sigRSAPSSRSAeSHA384, sigRSAPSSRSAeSHA512,
		sigRSAPSSPSSSHA256, sigRSAPSSPSSSHA384, sigRSAPSSPSSSHA512:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("rsa-pss scheme with %T certificate key", cert.PublicKey)
		}
		h := rsaPSSSchemeHash(sigAlg)
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
		if err := rsa.VerifyPSS(pub, h, hashPayload(h, payload), sig, opts); err != nil {
			return fmt.Errorf("rsa-pss signature mismatch: %w", err)
		}
		return nil

	default:
		// Fail closed. RSASSA-PKCS1-v1_5 is excluded on purpose (§4.4.3
		// forbids it here), and the ML-DSA code points the Chrome profile
		// advertises have no verifier available, so a server picking one gets
		// a rejected handshake rather than an unchecked signature.
		return fmt.Errorf("unsupported signature algorithm 0x%04x", sigAlg)
	}
}

func ecdsaSchemeParams(sigAlg uint16) (elliptic.Curve, crypto.Hash) {
	switch sigAlg {
	case sigECDSAP384SHA384:
		return elliptic.P384(), crypto.SHA384
	case sigECDSAP521SHA512:
		return elliptic.P521(), crypto.SHA512
	default:
		return elliptic.P256(), crypto.SHA256
	}
}

func rsaPSSSchemeHash(sigAlg uint16) crypto.Hash {
	switch sigAlg {
	case sigRSAPSSRSAeSHA384, sigRSAPSSPSSSHA384:
		return crypto.SHA384
	case sigRSAPSSRSAeSHA512, sigRSAPSSPSSSHA512:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// hashPayload digests payload with h. Every hash reached here is registered by
// the crypto/sha256 and crypto/sha512 imports in crypto.go.
func hashPayload(h crypto.Hash, payload []byte) []byte {
	hh := h.New()
	hh.Write(payload)
	return hh.Sum(nil)
}

// parseCertificate parses a TLS Certificate message body (after the handshake header).
func parseCertificate(data []byte) ([]*x509.Certificate, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("certificate message too short")
	}

	// TLS 1.3 Certificate: context (1) + cert_list length (3) + entries
	contextLen := int(data[0])
	offset := 1 + contextLen

	if offset+3 > len(data) {
		return nil, fmt.Errorf("certificate list truncated")
	}

	certListLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
	offset += 3

	end := offset + certListLen
	if end > len(data) {
		return nil, fmt.Errorf("certificate list overflow")
	}

	var certs []*x509.Certificate
	for offset < end {
		if offset+3 > end {
			break
		}
		certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if offset+certLen > end {
			return nil, fmt.Errorf("certificate data overflow")
		}

		cert, err := x509.ParseCertificate(data[offset : offset+certLen])
		if err != nil {
			return nil, fmt.Errorf("parse cert: %w", err)
		}
		certs = append(certs, cert)
		offset += certLen

		// Skip extensions
		if offset+2 <= end {
			extLen := int(binary.BigEndian.Uint16(data[offset:]))
			offset += 2 + extLen
		}
	}

	return certs, nil
}

// verifyCertificate verifies the server certificate chain.
func verifyCertificate(certs []*x509.Certificate, serverName string, rootCAs *x509.CertPool) error {
	if len(certs) == 0 {
		return fmt.Errorf("no certificates received")
	}

	leaf := certs[0]
	opts := x509.VerifyOptions{
		DNSName:     serverName,
		Roots:       rootCAs,
		CurrentTime: time.Now(),
	}

	if len(certs) > 1 {
		opts.Intermediates = x509.NewCertPool()
		for _, c := range certs[1:] {
			opts.Intermediates.AddCert(c)
		}
	}

	_, err := leaf.Verify(opts)
	return err
}

// parseCompressedCertificate decompresses and parses a CompressedCertificate message (RFC 8879).
// Format: algorithm(2) + uncompressed_length(3) + compressed_data_length(3) + compressed_data
func parseCompressedCertificate(data []byte) ([]*x509.Certificate, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("compressed certificate too short")
	}

	algorithm := binary.BigEndian.Uint16(data[0:2])
	uncompressedLen := int(data[2])<<16 | int(data[3])<<8 | int(data[4])
	compressedLen := int(data[5])<<16 | int(data[6])<<8 | int(data[7])

	if 8+compressedLen > len(data) {
		return nil, fmt.Errorf("compressed data truncated")
	}
	// The declared size is attacker-controlled and drives the decompression
	// bound, so cap it before allocating anything against it.
	if uncompressedLen > maxHandshakeMessage {
		return nil, fmt.Errorf("declared certificate size %d exceeds %d", uncompressedLen, maxHandshakeMessage)
	}

	compressed := data[8 : 8+compressedLen]

	var decompressed []byte
	var err error

	switch algorithm {
	case certCompressionZlib:
		decompressed, err = decompressZlib(compressed, uncompressedLen)
	case certCompressionBrotli:
		decompressed, err = decompressBrotli(compressed, uncompressedLen)
	case certCompressionZstd:
		return nil, fmt.Errorf("zstd certificate decompression not supported")
	default:
		return nil, fmt.Errorf("unknown compression algorithm: %d", algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("decompress (algo=%d): %w", algorithm, err)
	}
	// RFC 8879 §4: the decompressed length must equal the declared one.
	if len(decompressed) != uncompressedLen {
		return nil, fmt.Errorf("decompressed to %d bytes, header declared %d", len(decompressed), uncompressedLen)
	}

	return parseCertificate(decompressed)
}

func decompressZlib(data []byte, maxLen int) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, int64(maxLen)+1))
}

func decompressBrotli(data []byte, maxLen int) ([]byte, error) {
	r := brotli.NewReader(bytes.NewReader(data))
	return io.ReadAll(io.LimitReader(r, int64(maxLen)+1))
}

// parseEncryptedExtensionsALPN walks the EncryptedExtensions body and returns
// the negotiated ALPN protocol, or "" if absent. Body layout:
//
//	extensions_length(2) + [ ext_type(2) + ext_length(2) + ext_data ]*
//
// For ALPN the data is protocol_name_list_length(2) + length(1) + name.
// Returns "" on any parse error rather than failing the handshake — ALPN is
// optional, and a missing/garbled value just means the dispatcher will treat
// the conn as h2 (the default for our DialTLSContext path).
func parseEncryptedExtensionsALPN(body []byte) string {
	if len(body) < 2 {
		return ""
	}
	extsLen := int(binary.BigEndian.Uint16(body[0:2]))
	exts := body[2:]
	if extsLen > len(exts) {
		return ""
	}
	exts = exts[:extsLen]

	var alpn string
	_ = forEachExtension(exts, func(extType uint16, extData []byte) error {
		if extType == extALPN && alpn == "" && len(extData) >= 3 {
			protoLen := int(extData[2])
			if 3+protoLen <= len(extData) {
				alpn = string(extData[3 : 3+protoLen])
			}
		}
		return nil
	})
	return alpn
}
