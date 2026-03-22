package ctls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"hash"
	"net"
	"time"

	kyber "github.com/cloudflare/circl/kem/kyber/kyber768"
)

// handshakeState manages the TLS 1.3 handshake.
type handshakeState struct {
	conn       net.Conn
	serverName string
	alpn       []string
	skipVerify bool
	rootCAs    *x509.CertPool

	km             *keyMaterial
	suite          uint16
	ks             *tlsKeySchedule
	transcript     hash.Hash
	negotiatedALPN string

	clientHelloMsg []byte
}

// handshake performs the full TLS 1.3 handshake and returns a *Conn.
func handshake(conn net.Conn, serverName string, alpn []string, skipVerify bool, rootCAs *x509.CertPool) (*Conn, error) {
	km, err := generateKeyMaterial()
	if err != nil {
		return nil, fmt.Errorf("generate keys: %w", err)
	}

	hs := &handshakeState{
		conn:       conn,
		serverName: serverName,
		alpn:       alpn,
		skipVerify: skipVerify,
		rootCAs:    rootCAs,
		km:         km,
	}

	return hs.run()
}

func (hs *handshakeState) run() (*Conn, error) {
	// Send ClientHello
	chMsg, err := buildClientHello(hs.serverName, hs.alpn, hs.km)
	if err != nil {
		return nil, fmt.Errorf("build client hello: %w", err)
	}
	hs.clientHelloMsg = chMsg

	if err := writeRawRecord(hs.conn, recordTypeHandshake, chMsg); err != nil {
		return nil, fmt.Errorf("send client hello: %w", err)
	}

	// Read ServerHello
	rec, err := readRawRecord(hs.conn)
	if err != nil {
		return nil, fmt.Errorf("read server hello record: %w", err)
	}
	if rec.typ != recordTypeHandshake {
		return nil, fmt.Errorf("expected handshake record, got %d", rec.typ)
	}

	suite, dhe, serverHelloMsg, negotiatedALPN, err := hs.parseServerHello(rec.data)
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
		return nil, fmt.Errorf("server hs keys: %w", err)
	}
	serverHSER := newEncryptedRecord(serverHSAEAD, serverHSIV)

	// Read encrypted handshake messages: EncryptedExtensions, Certificate, CertVerify, Finished
	var serverCerts []*x509.Certificate
	var serverFinishedMAC []byte

	// Drain ChangeCipherSpec if present (TLS 1.3 middlebox compat)
	for {
		rec, err = readRawRecord(hs.conn)
		if err != nil {
			return nil, fmt.Errorf("read handshake: %w", err)
		}

		// Skip ChangeCipherSpec records (middlebox compat)
		if rec.typ == recordTypeChangeCipherSpec {
			continue
		}

		if rec.typ != recordTypeApplicationData {
			return nil, fmt.Errorf("expected encrypted record, got type %d", rec.typ)
		}

		// Decrypt
		plaintext, innerType, err := serverHSER.decrypt(rec.data)
		if err != nil {
			return nil, fmt.Errorf("decrypt hs record: %w", err)
		}

		if innerType == recordTypeAlert {
			if len(plaintext) >= 2 && plaintext[0] == alertLevelFatal {
				return nil, fmt.Errorf("server alert: %d", plaintext[1])
			}
			continue
		}

		if innerType != recordTypeHandshake {
			return nil, fmt.Errorf("expected handshake inner type, got %d", innerType)
		}

		// Process handshake messages - may contain multiple messages
		remaining := plaintext
		for len(remaining) >= 4 {
			msgType := remaining[0]
			msgLen := int(remaining[1])<<16 | int(remaining[2])<<8 | int(remaining[3])
			if 4+msgLen > len(remaining) {
				return nil, fmt.Errorf("truncated handshake message type %d", msgType)
			}
			msg := remaining[:4+msgLen]
			remaining = remaining[4+msgLen:]

			switch msgType {
			case handshakeTypeEncryptedExtensions:
				// Update transcript
				hs.transcript.Write(msg)

			case handshakeTypeCertificate:
				// Update transcript before parsing
				hs.transcript.Write(msg)
				certs, err := parseCertificate(msg[4:msgLen+4])
				if err != nil {
					return nil, fmt.Errorf("parse certificate: %w", err)
				}
				serverCerts = certs

			case handshakeTypeCertificateVerify:
				// Update transcript with this message
				hs.transcript.Write(msg)

			case handshakeTypeFinished:
				// DO NOT update transcript yet - verify first
				finishedKey := hs.ks.finishedKey(hs.ks.serverHSTraffic)
				expectedMAC := computeFinishedMAC(hs.ks.h, finishedKey, hs.transcript.Sum(nil))
				receivedMAC := msg[4 : 4+msgLen]
				if !bytes.Equal(expectedMAC, receivedMAC) {
					return nil, fmt.Errorf("server finished MAC mismatch")
				}
				serverFinishedMAC = receivedMAC
				_ = serverFinishedMAC
				// Now update transcript
				hs.transcript.Write(msg)
			}
		}

		// Check if we received Finished
		if serverFinishedMAC != nil {
			break
		}
	}

	// Verify server certificate
	if !hs.skipVerify && len(serverCerts) > 0 {
		if err := verifyCertificate(serverCerts, hs.serverName, hs.rootCAs); err != nil {
			return nil, fmt.Errorf("certificate verify: %w", err)
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
		Conn:           hs.conn,
		serverName:     hs.serverName,
		negotiatedALPN: hs.negotiatedALPN,
		serverReader:   newEncryptedRecord(serverAppAEAD, serverAppIV),
		clientWriter:   newEncryptedRecord(clientAppAEAD, clientAppIV),
	}, nil
}

// parseServerHello parses a ServerHello message and returns the cipher suite,
// DHE shared secret (X25519 or X25519MLKEM768), the raw message bytes, and negotiated ALPN.
func (hs *handshakeState) parseServerHello(data []byte) (suite uint16, dhe []byte, rawMsg []byte, alpn string, err error) {
	if len(data) < 4 {
		return 0, nil, nil, "", fmt.Errorf("server hello too short")
	}

	msgType := data[0]
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])

	if msgType != handshakeTypeServerHello {
		return 0, nil, nil, "", fmt.Errorf("expected ServerHello (2), got %d", msgType)
	}

	rawMsg = data[:4+msgLen]
	body := data[4 : 4+msgLen]

	if len(body) < 2+32+1 {
		return 0, nil, nil, "", fmt.Errorf("server hello body too short")
	}

	// Skip legacy version (2) + random (32)
	offset := 2 + 32

	// Session ID length + session ID
	sessionIDLen := int(body[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(body) {
		return 0, nil, nil, "", fmt.Errorf("truncated server hello")
	}

	// Cipher suite
	suite = binary.BigEndian.Uint16(body[offset:])
	offset += 2

	// Compression method (skip)
	offset += 1

	// Extensions
	if offset+2 > len(body) {
		return suite, nil, rawMsg, "", nil
	}
	extsLen := int(binary.BigEndian.Uint16(body[offset:]))
	offset += 2
	exts := body[offset : offset+extsLen]

	// Check if TLS 1.3 via supported_versions extension
	isTLS13 := false
	eOffset := 0
	for eOffset+4 <= len(exts) {
		extType := binary.BigEndian.Uint16(exts[eOffset:])
		extLen := int(binary.BigEndian.Uint16(exts[eOffset+2:]))
		eOffset += 4
		extData := exts[eOffset : eOffset+extLen]
		eOffset += extLen

		switch extType {
		case extSupportedVersions:
			if len(extData) == 2 {
				ver := binary.BigEndian.Uint16(extData)
				if ver == versionTLS13 {
					isTLS13 = true
				}
			}

		case extKeyShare:
			if !isTLS13 {
				// Parse after we confirm TLS 1.3, re-parse below
				break
			}
			// Falls through if already TLS 1.3
		}
	}

	if !isTLS13 {
		return 0, nil, nil, "", fmt.Errorf("server did not negotiate TLS 1.3 (falling back not supported)")
	}

	// Re-parse extensions to get key_share
	eOffset = 0
	for eOffset+4 <= len(exts) {
		extType := binary.BigEndian.Uint16(exts[eOffset:])
		extLen := int(binary.BigEndian.Uint16(exts[eOffset+2:]))
		eOffset += 4
		extData := exts[eOffset : eOffset+extLen]
		eOffset += extLen

		switch extType {
		case extKeyShare:
			dhe, err = hs.processServerKeyShare(extData)
			if err != nil {
				return 0, nil, nil, "", fmt.Errorf("key share: %w", err)
			}

		case extALPN:
			if len(extData) >= 4 {
				// protocol_name_list length (2) + protocol_length (1) + protocol
				protoLen := int(extData[2])
				if 3+protoLen <= len(extData) {
					alpn = string(extData[3 : 3+protoLen])
				}
			}
		}
	}

	if dhe == nil {
		return 0, nil, nil, "", fmt.Errorf("no key_share in ServerHello")
	}

	return suite, dhe, rawMsg, alpn, nil
}

// processServerKeyShare computes DHE shared secret from server's key share.
func (hs *handshakeState) processServerKeyShare(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("key_share too short")
	}

	group := binary.BigEndian.Uint16(data[0:])
	keyLen := int(binary.BigEndian.Uint16(data[2:]))
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
		// X25519MLKEM768: server sends Kyber768 ciphertext (1088 bytes) || X25519 public key (32 bytes)
		// Kyber768 ciphertext size matches ML-KEM-768 ciphertext size.
		const kyberCTSize = 1088
		if len(keyData) < kyberCTSize+32 {
			return nil, fmt.Errorf("x25519mlkem768 key data too short: %d", len(keyData))
		}

		kyberCT := keyData[:kyberCTSize]
		serverX25519Bytes := keyData[kyberCTSize:]

		// Kyber768 decapsulation
		kyberShared := make([]byte, 32)
		hs.km.kyberPriv.DecapsulateTo(kyberShared, kyberCT)
		_ = kyber.Scheme() // ensure import is used

		// X25519 ECDH
		serverX25519Pub, err := ecdh.X25519().NewPublicKey(serverX25519Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse server x25519 (kyber combo): %w", err)
		}
		x25519Shared, err := hs.km.x25519Priv.ECDH(serverX25519Pub)
		if err != nil {
			return nil, fmt.Errorf("x25519 ecdh (kyber combo): %w", err)
		}

		// Combine: kyber_shared || x25519_shared
		combined := append(kyberShared, x25519Shared...)
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
		DNSName:   serverName,
		Roots:     rootCAs,
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

