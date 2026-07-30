package ctls

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
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

// handshakeState manages the TLS 1.3 handshake.
type handshakeState struct {
	conn       net.Conn
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

	// Resumption state. offered is the ticket we put in the ClientHello;
	// pskAccepted records whether the ServerHello actually selected it.
	sessions    *SessionCache
	sessionKey  string
	offered     *Session
	pskAccepted bool

	clientHelloMsg []byte
}

// handshake performs the full TLS 1.3 handshake and returns a *Conn.
func handshake(conn net.Conn, cfg *Config) (*Conn, error) {
	km, err := generateKeyMaterial()
	if err != nil {
		return nil, fmt.Errorf("generate keys: %w", err)
	}

	hs := &handshakeState{
		conn:       conn,
		serverName: cfg.ServerName,
		alpn:       cfg.ALPN,
		skipVerify: cfg.SkipVerify,
		rootCAs:    cfg.RootCAs,
		browser:    cfg.Browser,
		km:         km,
		sessions:   cfg.Sessions,
		sessionKey: cfg.SessionKey,
	}

	return hs.run()
}

func (hs *handshakeState) run() (*Conn, error) {
	// A cached ticket turns this into a resumption attempt. If the server
	// declines it the handshake simply proceeds in full, so this is safe to
	// try whenever one is available.
	hs.offered = hs.sessions.Get(hs.sessionKey)

	var chMsg []byte
	var err error
	switch hs.browser {
	case BrowserChrome:
		chMsg, err = buildChromeClientHello(hs.serverName, hs.alpn, hs.km, hs.offered)
	default:
		chMsg, err = buildSafariClientHello(hs.serverName, hs.alpn, hs.km, hs.offered)
	}
	if err != nil {
		return nil, fmt.Errorf("build client hello: %w", err)
	}
	// The binder is an HMAC over the ClientHello up to the binder itself, so it
	// can only be filled in once the message is fully assembled.
	if hs.offered != nil {
		if err := finalizePSKBinder(chMsg, hs.offered); err != nil {
			return nil, fmt.Errorf("psk binder: %w", err)
		}
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
	resumed := false
	if hs.pskAccepted && hs.offered != nil {
		// The PSK is bound to the hash of the suite it was issued under; a
		// server that selects a suite with a different hash cannot be talking
		// about our ticket.
		if hashLen(suite) != hashLen(hs.offered.suite) {
			return nil, fmt.Errorf("server accepted psk under suite 0x%04x whose hash differs from the ticket's", suite)
		}
		hs.ks = newKeyScheduleWithPSK(suite, hs.offered.psk)
		resumed = true
	} else {
		hs.ks = newKeySchedule(suite)
	}

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

	// Read encrypted handshake messages: EncryptedExtensions, Certificate, CertVerify, Finished
	var serverCerts []*x509.Certificate
	var serverFinishedMAC []byte
	var sawCertVerify bool

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
			return nil, fmt.Errorf("decrypt hs record (suite=0x%04x dheLen=%d recLen=%d): %w", hs.suite, len(dhe), len(rec.data), err)
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
				// In TLS 1.3 ALPN is delivered here, not in ServerHello.
				// parseServerHello leaves negotiatedALPN empty for 1.3, so
				// extracting it now is what lets the caller route h1-only
				// servers to the HTTP/1.1 transport instead of pumping the
				// h2 preface into them.
				if alpn := parseEncryptedExtensionsALPN(msg[4 : 4+msgLen]); alpn != "" {
					hs.negotiatedALPN = alpn
				}
				hs.transcript.Write(msg)

			case handshakeTypeCertificate:
				// Update transcript before parsing
				hs.transcript.Write(msg)
				certs, err := parseCertificate(msg[4 : 4+msgLen])
				if err != nil {
					return nil, fmt.Errorf("parse certificate: %w", err)
				}
				serverCerts = certs

			case handshakeTypeCompressedCertificate:
				// RFC 8879: CompressedCertificate replaces Certificate in transcript
				hs.transcript.Write(msg)
				certs, err := parseCompressedCertificate(msg[4 : 4+msgLen])
				if err != nil {
					return nil, fmt.Errorf("parse compressed certificate: %w", err)
				}
				serverCerts = certs

			case handshakeTypeCertificateVerify:
				// RFC 8446 §4.4.3: the signature covers the transcript up to
				// and including Certificate, so snapshot the hash before
				// folding this message in.
				cvTranscript := hs.transcript.Sum(nil)
				hs.transcript.Write(msg)
				sawCertVerify = true

				if !hs.skipVerify {
					cvBody := msg[4 : 4+msgLen]
					if len(cvBody) < 4 {
						return nil, fmt.Errorf("certificate verify message too short")
					}
					sigAlg := binary.BigEndian.Uint16(cvBody[0:2])
					sigLen := int(binary.BigEndian.Uint16(cvBody[2:4]))
					if 4+sigLen > len(cvBody) {
						return nil, fmt.Errorf("certificate verify signature truncated")
					}
					if len(serverCerts) == 0 {
						return nil, fmt.Errorf("certificate verify arrived before any certificate")
					}
					if err := verifyCertVerifySignature(serverCerts[0], sigAlg, cvBody[4:4+sigLen], cvTranscript); err != nil {
						return nil, fmt.Errorf("certificate verify: %w", err)
					}
				}

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

	// Verify server certificate. Both the chain and the CertificateVerify
	// signature are mandatory: the previous `len(serverCerts) > 0` guard meant a
	// server that simply omitted its Certificate message skipped validation
	// entirely, and a missing CertificateVerify would leave the peer
	// unauthenticated. Absence of either is a failure, not a reason to skip.
	//
	// A resumed handshake is the documented exception: the server sends no
	// Certificate at all, and proves its identity by producing a Finished MAC
	// over a transcript keyed by the PSK — which only the server that
	// authenticated on the original connection can do.
	if !hs.skipVerify && !resumed {
		if len(serverCerts) == 0 {
			return nil, fmt.Errorf("server sent no certificate")
		}
		if !sawCertVerify {
			return nil, fmt.Errorf("server sent no CertificateVerify message")
		}
		if err := verifyCertificate(serverCerts, hs.serverName, hs.rootCAs); err != nil {
			return nil, fmt.Errorf("certificate chain verify: %w", err)
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

	// resumption_master_secret covers the transcript through the *client's*
	// Finished, so that message has to join the transcript before it is
	// derived. Post-handshake tickets hang off this secret.
	hs.transcript.Write(finishedMsg)
	resMaster := hs.ks.resumptionMasterSecret(hs.transcript.Sum(nil))

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
		didResume:      resumed,
		suite:          hs.suite,
		resMaster:      resMaster,
		sessions:       hs.sessions,
		sessionKey:     hs.sessionKey,
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

	if 4+msgLen > len(data) {
		return 0, nil, nil, "", fmt.Errorf("server hello truncated: declares %d bytes, record holds %d", msgLen, len(data)-4)
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
	// Length fields here are attacker-controlled: this parser runs on every
	// dial, against whatever bytes the peer sends, so an unchecked slice would
	// be a remotely triggerable panic that takes down the calling process.
	if offset+extsLen > len(body) {
		return 0, nil, nil, "", fmt.Errorf("server hello extensions overrun message: %d > %d", extsLen, len(body)-offset)
	}
	exts := body[offset : offset+extsLen]

	// Check if TLS 1.3 via supported_versions extension
	isTLS13 := false
	eOffset := 0
	for eOffset+4 <= len(exts) {
		extType := binary.BigEndian.Uint16(exts[eOffset:])
		extLen := int(binary.BigEndian.Uint16(exts[eOffset+2:]))
		eOffset += 4
		if eOffset+extLen > len(exts) {
			return 0, nil, nil, "", fmt.Errorf("server hello extension 0x%04x overruns block", extType)
		}
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
		if eOffset+extLen > len(exts) {
			return 0, nil, nil, "", fmt.Errorf("server hello extension 0x%04x overruns block", extType)
		}
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

		case extPreSharedKey:
			// RFC 8446 §4.2.11: the ServerHello echoes the index of the
			// identity it chose. We offer exactly one, so anything but 0 —
			// or an echo we never asked for — is a protocol violation.
			if hs.offered == nil {
				return 0, nil, nil, "", fmt.Errorf("server selected a psk we did not offer")
			}
			if len(extData) != 2 {
				return 0, nil, nil, "", fmt.Errorf("malformed pre_shared_key in server hello")
			}
			if idx := binary.BigEndian.Uint16(extData); idx != 0 {
				return 0, nil, nil, "", fmt.Errorf("server selected psk identity %d, only 0 was offered", idx)
			}
			hs.pskAccepted = true
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
	if 4+keyLen > len(data) {
		return nil, fmt.Errorf("key_share entry overruns extension: declares %d bytes, have %d", keyLen, len(data)-4)
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
		if len(keyData) < mlkemCTSize+32 {
			return nil, fmt.Errorf("x25519mlkem768 key data too short: %d", len(keyData))
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

// certVerifyContext is the RFC 8446 §4.4.3 context string for a server
// CertificateVerify signature.
const certVerifyContext = "TLS 1.3, server CertificateVerify"

// certVerifyPayload builds the octet string the server signs in
// CertificateVerify: 64 spaces, the context string, a zero separator, then the
// transcript hash up to and including the Certificate message.
func certVerifyPayload(transcriptHash []byte) []byte {
	b := make([]byte, 0, 64+len(certVerifyContext)+1+len(transcriptHash))
	for i := 0; i < 64; i++ {
		b = append(b, 0x20)
	}
	b = append(b, certVerifyContext...)
	b = append(b, 0x00)
	b = append(b, transcriptHash...)
	return b
}

// verifyCertVerifySignature checks the server's CertificateVerify signature
// against the leaf certificate's public key.
//
// This is the step that actually authenticates the peer. A certificate chain
// alone proves nothing — certificates are public and anyone can replay one — so
// without this check any party able to route the traffic can impersonate any
// host whose chain they can fetch. Unsupported or forbidden algorithms fail
// closed: a signature we cannot verify is not an authenticated server.
func verifyCertVerifySignature(leaf *x509.Certificate, sigAlg uint16, sig, transcriptHash []byte) error {
	payload := certVerifyPayload(transcriptHash)

	switch sigAlg {
	case sigECDSAP256SHA256, sigECDSAP384SHA384, sigECDSAP521SHA512:
		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("scheme 0x%04x needs an ECDSA key, certificate has %T", sigAlg, leaf.PublicKey)
		}
		var digest []byte
		var want elliptic.Curve
		switch sigAlg {
		case sigECDSAP256SHA256:
			s := sha256.Sum256(payload)
			digest, want = s[:], elliptic.P256()
		case sigECDSAP384SHA384:
			s := sha512.Sum384(payload)
			digest, want = s[:], elliptic.P384()
		default:
			s := sha512.Sum512(payload)
			digest, want = s[:], elliptic.P521()
		}
		if pub.Curve != want {
			return fmt.Errorf("scheme 0x%04x does not match certificate curve %s", sigAlg, pub.Curve.Params().Name)
		}
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return fmt.Errorf("ECDSA signature does not verify")
		}
		return nil

	case sigRSAPSSRSAeSHA256, sigRSAPSSRSAeSHA384, sigRSAPSSRSAeSHA512,
		sigRSAPSSPSSSHA256, sigRSAPSSPSSSHA384, sigRSAPSSPSSSHA512:
		pub, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("scheme 0x%04x needs an RSA key, certificate has %T", sigAlg, leaf.PublicKey)
		}
		var digest []byte
		var h crypto.Hash
		switch sigAlg {
		case sigRSAPSSRSAeSHA256, sigRSAPSSPSSSHA256:
			s := sha256.Sum256(payload)
			digest, h = s[:], crypto.SHA256
		case sigRSAPSSRSAeSHA384, sigRSAPSSPSSSHA384:
			s := sha512.Sum384(payload)
			digest, h = s[:], crypto.SHA384
		default:
			s := sha512.Sum512(payload)
			digest, h = s[:], crypto.SHA512
		}
		// RFC 8446 §4.2.3 mandates a salt length equal to the digest length.
		if err := rsa.VerifyPSS(pub, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return fmt.Errorf("RSA-PSS signature does not verify: %w", err)
		}
		return nil

	case sigEd25519:
		pub, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("scheme 0x%04x needs an Ed25519 key, certificate has %T", sigAlg, leaf.PublicKey)
		}
		if !ed25519.Verify(pub, payload, sig) {
			return fmt.Errorf("Ed25519 signature does not verify")
		}
		return nil

	default:
		return fmt.Errorf("unsupported CertificateVerify scheme 0x%04x", sigAlg)
	}
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
	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[0:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if extLen > len(exts) {
			return ""
		}
		extData := exts[:extLen]
		exts = exts[extLen:]

		if extType == extALPN && len(extData) >= 3 {
			protoLen := int(extData[2])
			if 3+protoLen <= len(extData) {
				return string(extData[3 : 3+protoLen])
			}
		}
	}
	return ""
}
