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
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
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
	sessions   *SessionCache
	sessionKey string
	psk        *pskOffer
	resumed    bool
	alpn       []string
	skipVerify bool
	rootCAs    *x509.CertPool
	browser    BrowserType

	km             *keyMaterial
	suite          uint16
	ks             *tlsKeySchedule
	transcript     hash.Hash
	negotiatedALPN string

	// clientHSER is the client's handshake-traffic record writer. It exists
	// from the point handshake secrets are derived, which is also the point
	// from which an abort must be reported in an encrypted alert rather than a
	// plaintext one — a server that has installed handshake keys treats a
	// cleartext record as a protocol violation in its own right.
	clientHSER *encryptedRecord

	clientHelloMsg []byte
	ccsSent        bool
	alertSent      bool
}

// handshake performs the full TLS 1.3 handshake and returns a *Conn.
//
// On failure it tells the server why before the caller drops the connection.
// RFC 8446 §6 asks for that ("Whenever an implementation encounters a fatal
// error condition, it SHOULD send an appropriate fatal alert"), and it also
// matters for what this package exists to do: a browser answers a bad
// certificate or an unusable ServerHello with an alert, so a client that
// instead vanishes mid-handshake looks like nothing that ships on a phone.
func handshake(conn net.Conn, serverName string, alpn []string, skipVerify bool, rootCAs *x509.CertPool, browser BrowserType, sessions *SessionCache, sessionKey string) (*Conn, error) {
	if sessionKey == "" {
		sessionKey = serverName
	}
	km, err := generateKeyMaterial()
	if err != nil {
		return nil, withAlert(alertInternalError, fmt.Errorf("generate keys: %w", err))
	}

	hs := &handshakeState{
		conn:       conn,
		br:         newRecordReader(conn),
		serverName: serverName,
		sessions:   sessions,
		sessionKey: sessionKey,
		alpn:       alpn,
		skipVerify: skipVerify,
		rootCAs:    rootCAs,
		browser:    browser,
		km:         km,
	}

	tlsConn, err := hs.run()
	if err != nil {
		hs.sendFatalAlert(err)
		return nil, err
	}
	return tlsConn, nil
}

// sendFatalAlert reports an aborting handshake to the peer, once, best-effort.
//
// The description comes from the error itself (see localAlert), so each failure
// path names its own alert instead of everything collapsing to one generic
// code. Failures that are the connection itself dying send nothing: there is no
// peer left to tell, and on a read timeout the deadline has already expired.
func (hs *handshakeState) sendFatalAlert(cause error) {
	if hs.alertSent || isNetworkFailure(cause) {
		return
	}
	hs.alertSent = true

	// The handshake deadline may already have expired, and on a dial whose
	// context carried none there is no deadline at all. Either way this write
	// gets its own short bound rather than blocking a torn-down handshake.
	_ = hs.conn.SetWriteDeadline(time.Now().Add(alertWriteTimeout))

	body := alertRecord(alertLevelFatal, alertDescFor(cause))
	if hs.clientHSER != nil {
		if ciphertext, err := hs.clientHSER.encrypt(body, recordTypeAlert); err == nil {
			_ = writeRawRecord(hs.conn, recordTypeApplicationData, ciphertext)
			return
		}
	}
	_ = writeRawRecord(hs.conn, recordTypeAlert, body)
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

// handshakeAlert turns an alert record body received mid-handshake into an
// error, or nil when the alert is one to read past. See receivedAlert for why
// the record's level field is not consulted.
func handshakeAlert(body []byte) error {
	desc, err := receivedAlert(body)
	if err != nil {
		return err
	}
	if desc == alertCloseNotify {
		return errHandshakeClosed
	}
	// user_canceled: a courtesy notice that a close_notify is coming. Keep
	// reading; the close_notify or the EOF behind it ends the handshake.
	return nil
}

// readServerHelloMessage reads one ServerHello (or HelloRetryRequest, which
// shares its message type), reassembling across records rather than assuming a
// single record carries the whole message.
func (hs *handshakeState) readServerHelloMessage() ([]byte, error) {
	var shReader handshakeReader
	idleRecords := 0
	for {
		rec, err := readRawRecord(hs.br)
		if err != nil {
			return nil, fmt.Errorf("read server hello record: %w", err)
		}
		if rec.typ == recordTypeAlert || rec.typ == recordTypeChangeCipherSpec {
			if idleRecords++; idleRecords > maxNoProgressRecords {
				return nil, alertErrf(alertUnexpectedMessage,
					"server sent %d records without a server hello", idleRecords)
			}
		}
		if rec.typ == recordTypeAlert {
			if err := handshakeAlert(rec.data); err != nil {
				return nil, err
			}
			continue
		}
		if rec.typ == recordTypeChangeCipherSpec {
			continue
		}
		if rec.typ != recordTypeHandshake {
			return nil, alertErrf(alertUnexpectedMessage, "expected handshake record, got %d", rec.typ)
		}
		// RFC 8446 §5.1 forbids zero-length handshake fragments. Accepting them
		// also punched a hole through maxNoProgressRecords: the budget is only
		// charged for alerts and ChangeCipherSpec, so an empty handshake record
		// advanced nothing yet cost nothing, and a peer could hold this loop
		// open indefinitely. WrapConn only installs a deadline when the caller's
		// context carries one, so on a context.Background() dial that is a
		// permanent hang, not a slow failure.
		if len(rec.data) == 0 {
			return nil, alertErrf(alertDecodeError, "server sent a zero-length handshake fragment")
		}
		if err := shReader.add(rec.data); err != nil {
			return nil, withAlert(alertRecordOverflow, fmt.Errorf("read server hello: %w", err))
		}
		msg, err := shReader.next()
		if err != nil {
			return nil, withAlert(alertDecodeError, fmt.Errorf("read server hello: %w", err))
		}
		if msg != nil {
			return msg, nil
		}
	}
}

// sendChangeCipherSpec emits the dummy ChangeCipherSpec record TLS 1.3 keeps
// for middlebox compatibility, at most once per handshake.
//
// RFC 8446 appendix D.4 places it "immediately before its second flight", which
// is the second ClientHello when a HelloRetryRequest intervened and the
// encrypted Finished otherwise — one record either way. Not sending it at all
// is a fingerprint leak anti-bot services check for.
func (hs *handshakeState) sendChangeCipherSpec() error {
	if hs.ccsSent {
		return nil
	}
	if err := writeRawRecord(hs.conn, recordTypeChangeCipherSpec, []byte{0x01}); err != nil {
		return fmt.Errorf("send ccs: %w", err)
	}
	hs.ccsSent = true
	return nil
}

func (hs *handshakeState) run() (*Conn, error) {
	// Take a ticket before building the hello: whether one is offered decides
	// the shape of the message, and the binder is computed from its PSK.
	hs.psk = newPSKOffer(hs.sessions, hs.sessionKey, resumableSuites, time.Now())

	var chMsg []byte
	var err error
	switch hs.browser {
	case BrowserChrome:
		chMsg, err = buildChromeClientHello(hs.serverName, hs.alpn, hs.km, hs.psk)
	default:
		// Safari's resumed ClientHello has not been captured, so it is not
		// offered one. Sending a PSK shaped like a guess would trade a real
		// fingerprint for an unverified one.
		chMsg, err = buildSafariClientHello(hs.serverName, hs.alpn, hs.km)
		hs.psk = nil
	}
	if err != nil {
		return nil, withAlert(alertInternalError, fmt.Errorf("build client hello: %w", err))
	}
	hs.clientHelloMsg = chMsg

	if err := writeInitialClientHello(hs.conn, chMsg); err != nil {
		return nil, fmt.Errorf("send client hello: %w", err)
	}

	serverHelloMsg, err := hs.readServerHelloMessage()
	if err != nil {
		return nil, err
	}
	shell, err := parseServerHelloShell(serverHelloMsg)
	if err != nil {
		return nil, fmt.Errorf("parse server hello: %w", err)
	}
	if err := hs.checkServerHelloShell(shell); err != nil {
		return nil, err
	}

	if shell.isHRR {
		// The server could not use either key share we sent. Answering the
		// retry sets up hs.suite, hs.ks and the whole transcript — including
		// the synthetic message_hash that stands in for ClientHello1 and the
		// second ServerHello — so unlike the branch below there is nothing left
		// for this function to hash. The message itself is discarded rather than
		// assigned back: it was, and reading the old name afterwards would have
		// given the *retry*, not the ServerHello that replaced it.
		_, shell, err = hs.retryAfterHelloRetryRequest(serverHelloMsg, shell)
		if err != nil {
			return nil, err
		}
	} else {
		hs.suite = shell.suite

		// A PSK only enters the key schedule when the server took it *and* the
		// suite it chose hashes the same way the ticket was derived under.
		// Either half missing means a full handshake, which is the same code
		// path with a zero PSK.
		//
		// The comparison is on the hash, not the suite: §4.2.11 permits a
		// server to accept the PSK and negotiate any suite sharing its hash,
		// and AES-128-GCM and ChaCha20-Poly1305 are both SHA-256. Requiring the
		// exact suite back rejected that legal answer, and the resulting
		// zero-PSK schedule failed at the server's Finished.
		if hs.psk != nil {
			accepted, perr := parseSelectedIdentity(shell.exts)
			if perr != nil {
				return nil, perr
			}
			hs.resumed = accepted && sameHashSuite(shell.suite, hs.psk.ticket.suite)
		}
		if hs.resumed {
			hs.ks = newKeyScheduleWithPSK(shell.suite, hs.psk.ticket.psk)
		} else {
			hs.ks = newKeySchedule(shell.suite)
		}

		// Initialize transcript with SHA-256 or SHA-384
		hs.transcript = hs.ks.h()
		hs.transcript.Write(chMsg)
		hs.transcript.Write(serverHelloMsg)
	}

	dhe, err := hs.parseServerHello(shell)
	if err != nil {
		return nil, fmt.Errorf("parse server hello: %w", err)
	}

	// Derive handshake secrets
	transcriptHash := hs.transcript.Sum(nil)
	hs.ks.deriveHandshakeSecrets(dhe, transcriptHash)

	// Set up server handshake AEAD
	serverHSAEAD, serverHSIV, err := hs.ks.makeTrafficKeys(hs.ks.serverHSTraffic)
	if err != nil {
		return nil, withAlert(alertInternalError,
			fmt.Errorf("server hs keys (suite=0x%04x): %w", hs.suite, err))
	}
	serverHSER := newEncryptedRecord(serverHSAEAD, serverHSIV)

	// The client's own handshake writer is built here rather than just before
	// the Finished flight, because everything below this line fails *after* the
	// server has installed handshake keys — and from that point an abort has to
	// be reported in an encrypted alert. Building it here is what lets
	// sendFatalAlert reach the server at all for a rejected certificate, which
	// is the single most likely way this handshake ends badly.
	clientHSAEAD, clientHSIV, err := hs.ks.makeTrafficKeys(hs.ks.clientHSTraffic)
	if err != nil {
		return nil, withAlert(alertInternalError, fmt.Errorf("client hs keys: %w", err))
	}
	hs.clientHSER = newEncryptedRecord(clientHSAEAD, clientHSIV)

	// Read encrypted handshake messages: EncryptedExtensions, Certificate,
	// CertificateVerify, Finished. What they accumulate lives in flightState so
	// that the QUIC driver, which reads the same messages out of CRYPTO frames,
	// can share the handling — see flight.go.
	var st flightState
	var hr handshakeReader

	idleRecords := 0
	for !st.finished {
		rec, err := readRawRecord(hs.br)
		if err != nil {
			return nil, fmt.Errorf("read handshake: %w", err)
		}

		if rec.typ != recordTypeApplicationData {
			if idleRecords++; idleRecords > maxNoProgressRecords {
				return nil, alertErrf(alertUnexpectedMessage,
					"server sent %d records carrying no handshake data", idleRecords)
			}
		}

		// Skip ChangeCipherSpec records (middlebox compat)
		if rec.typ == recordTypeChangeCipherSpec {
			continue
		}

		if rec.typ == recordTypeAlert {
			if err := handshakeAlert(rec.data); err != nil {
				return nil, err
			}
			continue
		}

		if rec.typ != recordTypeApplicationData {
			return nil, alertErrf(alertUnexpectedMessage, "expected encrypted record, got type %d", rec.typ)
		}

		plaintext, innerType, err := serverHSER.decrypt(rec.data)
		if err != nil {
			return nil, alertErrf(alertBadRecordMAC,
				"decrypt hs record (suite=0x%04x dheLen=%d recLen=%d): %v", hs.suite, len(dhe), len(rec.data), err)
		}

		if innerType == recordTypeAlert {
			if err := handshakeAlert(plaintext); err != nil {
				return nil, err
			}
			// An ignorable alert decrypts fine but advances nothing, so it
			// counts against the same budget as a plaintext one.
			if idleRecords++; idleRecords > maxNoProgressRecords {
				return nil, alertErrf(alertUnexpectedMessage,
					"server sent %d records carrying no handshake data", idleRecords)
			}
			continue
		}

		if innerType != recordTypeHandshake {
			return nil, alertErrf(alertUnexpectedMessage, "expected handshake inner type, got %d", innerType)
		}

		// Same rule as the plaintext loop above: an encrypted record whose
		// inner content is an empty handshake fragment is illegal, and it is
		// not charged against the no-progress budget because it arrives as
		// application data.
		if len(plaintext) == 0 {
			return nil, alertErrf(alertDecodeError, "server sent a zero-length handshake fragment")
		}

		if err := hr.add(plaintext); err != nil {
			return nil, withAlert(alertRecordOverflow, err)
		}

		for !st.finished {
			msg, err := hr.next()
			if err != nil {
				return nil, withAlert(alertDecodeError, err)
			}
			if msg == nil {
				break
			}
			if err := hs.handleFlightMessage(msg, &st); err != nil {
				return nil, err
			}
		}
	}

	// A chain that never arrived, or one that arrived without a matching
	// CertificateVerify, means the peer never proved it holds the private key.
	// Neither may be treated as "nothing to check".
	//
	// A resumed handshake is the exception: RFC 8446 §2.2 has the server send
	// neither Certificate nor CertificateVerify when it accepts a PSK, because
	// the PSK is the authentication — it can only have come from a session this
	// client already verified. Demanding a chain there would reject every
	// successful resumption as a protocol violation.
	if !hs.skipVerify && !hs.resumed {
		if len(st.serverCerts) == 0 {
			return nil, alertErrf(alertCertificateRequired, "server sent no certificate")
		}
		if !st.sawCertVerify {
			return nil, alertErrf(alertUnexpectedMessage, "server sent no certificate_verify")
		}
	}

	// Master secrets are derived from the transcript up to and including the
	// server Finished — the client's own Certificate does not feed into them
	// (RFC 8446 §7.1), even though it does feed into the client Finished MAC
	// computed below.
	transcriptAfterSF := hs.transcript.Sum(nil)
	hs.ks.deriveMasterSecrets(transcriptAfterSF)

	// The client's second flight: an empty Certificate when one was asked for,
	// then Finished. Both go in a single record, which is what a real client
	// emits and keeps the flight to one write.
	var flight []byte
	if st.sawCertRequest {
		flight = append(flight, emptyCertificateMessage(st.certReqContext)...)
		hs.transcript.Write(flight)
		// No CertificateVerify follows: §4.4.2 forbids one when the Certificate
		// carried no certificates, since there is no key to prove possession of.
	}

	// §4.4.4 puts the client's own Certificate inside the context its Finished
	// covers, so this hash is taken after the message above was folded in.
	clientFinishedKey := hs.ks.finishedKey(hs.ks.clientHSTraffic)
	clientFinishedMAC := computeFinishedMAC(hs.ks.h, clientFinishedKey, hs.transcript.Sum(nil))

	finishedMsg := make([]byte, 4+len(clientFinishedMAC))
	finishedMsg[0] = handshakeTypeFinished
	finishedMsg[1] = byte(len(clientFinishedMAC) >> 16)
	finishedMsg[2] = byte(len(clientFinishedMAC) >> 8)
	finishedMsg[3] = byte(len(clientFinishedMAC))
	copy(finishedMsg[4:], clientFinishedMAC)
	flight = append(flight, finishedMsg...)

	// The resumption secret is the only one taken from the transcript through
	// the client's own Finished, so it is derived here rather than beside the
	// application traffic secrets above.
	hs.transcript.Write(finishedMsg)
	hs.ks.deriveResumptionMaster(hs.transcript.Sum(nil))

	// Middlebox-compatibility ChangeCipherSpec. A retried handshake already
	// sent it ahead of the second ClientHello, so this is a no-op there.
	if err := hs.sendChangeCipherSpec(); err != nil {
		return nil, err
	}

	// hs.clientHSER was built alongside the server's, right after the handshake
	// secrets were derived, so that an abort between there and here could be
	// reported in an encrypted alert. Its sequence number is still 0 on this
	// path: nothing writes to it unless the handshake is failing.
	encFlight, err := hs.clientHSER.encrypt(flight, recordTypeHandshake)
	if err != nil {
		return nil, withAlert(alertInternalError, fmt.Errorf("encrypt finished: %w", err))
	}

	if err := writeRawRecord(hs.conn, recordTypeApplicationData, encFlight); err != nil {
		return nil, fmt.Errorf("send finished: %w", err)
	}

	// Derive application traffic keys
	serverAppAEAD, serverAppIV, err := hs.ks.makeTrafficKeys(hs.ks.serverAppTraffic)
	if err != nil {
		return nil, withAlert(alertInternalError, fmt.Errorf("server app keys: %w", err))
	}

	clientAppAEAD, clientAppIV, err := hs.ks.makeTrafficKeys(hs.ks.clientAppTraffic)
	if err != nil {
		return nil, withAlert(alertInternalError, fmt.Errorf("client app keys: %w", err))
	}

	return &Conn{
		Conn:            hs.conn,
		br:              hs.br,
		serverName:      hs.serverName,
		sessionKey:      hs.sessionKey,
		negotiatedALPN:  hs.negotiatedALPN,
		suite:           hs.suite,
		didResume:       hs.resumed,
		peerCerts:       st.serverCerts,
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
		// The alert distinguishes the reasons the way a browser does, so the
		// server's log says whether it served an expired certificate, one from
		// a CA we do not carry, or one for the wrong name.
		return alertErrf(certificateAlertFor(err), "certificate verify: %v", err)
	}
	return nil
}

// certificateAlertFor maps a chain verification failure to the alert RFC 8446
// §6.2 defines for it.
func certificateAlertFor(err error) uint8 {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return alertCertificateExpired
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return alertUnknownCA
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return alertBadCertificate
	}
	return alertBadCertificate
}

// forEachExtension walks a TLS extension block, calling fn for each entry.
// Every length in the block is attacker-controlled, so an overrun returns an
// error instead of slicing past the end.
//
// Repeated extension types are rejected. RFC 8446 §4.2: "There MUST NOT be more
// than one extension of the same type in a given extension block. [...] Receiving
// [...] MUST abort the handshake with an 'illegal_parameter' alert." Without the
// check, a second key_share or supported_versions silently overwrote the first,
// so which one took effect came down to the order a hostile server chose to send
// them in — the classic shape of a parser-differential bug. Blocks are a handful
// of entries, so the linear scan costs nothing measurable.
func forEachExtension(exts []byte, fn func(extType uint16, extData []byte) error) error {
	var seen []uint16
	for len(exts) > 0 {
		if len(exts) < 4 {
			return alertErrf(alertDecodeError, "trailing %d bytes in extension block", len(exts))
		}
		extType := binary.BigEndian.Uint16(exts[0:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if extLen > len(exts) {
			return alertErrf(alertDecodeError,
				"extension 0x%04x claims %d bytes, %d remain", extType, extLen, len(exts))
		}
		if containsUint16(seen, extType) {
			return alertErrf(alertIllegalParameter, "extension 0x%04x appears twice in one block", extType)
		}
		seen = append(seen, extType)
		if err := fn(extType, exts[:extLen]); err != nil {
			return err
		}
		exts = exts[extLen:]
	}
	return nil
}

// serverHelloShell is the part of a ServerHello that parses the same way
// whether the message is a real ServerHello or a HelloRetryRequest — the two
// share a message type and differ only by the fixed random and by what their
// key_share carries.
type serverHelloShell struct {
	suite     uint16
	exts      []byte
	isHRR     bool
	random    []byte
	sessionID []byte
}

// tls12DowngradeSentinel and tls11DowngradeSentinel are the values RFC 8446
// §4.1.3 has a TLS 1.3-capable server put in the last 8 bytes of
// ServerHello.random when it negotiates 1.2 or below. A client that offered 1.3
// and sees one has had its version list tampered with in flight, and "MUST abort
// the handshake with an 'illegal_parameter' alert".
var (
	tls12DowngradeSentinel = []byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01}
	tls11DowngradeSentinel = []byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00}
)

// parseServerHelloShell parses the fixed header of a ServerHello. data must be
// one complete handshake message including its header.
func parseServerHelloShell(data []byte) (*serverHelloShell, error) {
	if len(data) < 4 {
		return nil, alertErrf(alertDecodeError, "server hello too short")
	}

	msgType := data[0]
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])

	if msgType != handshakeTypeServerHello {
		return nil, alertErrf(alertUnexpectedMessage, "expected ServerHello (2), got %d", msgType)
	}
	if 4+msgLen > len(data) {
		return nil, alertErrf(alertDecodeError,
			"server hello claims %d bytes, %d available", msgLen, len(data)-4)
	}

	body := data[4 : 4+msgLen]

	if len(body) < 2+32+1 {
		return nil, alertErrf(alertDecodeError, "server hello body too short")
	}

	sh := &serverHelloShell{random: body[2:34]}

	// A HelloRetryRequest is a ServerHello carrying this fixed random. Its
	// key_share holds a bare 2-byte group id instead of a key, so the caller
	// has to know which shape to expect before reading the extensions.
	sh.isHRR = bytes.Equal(sh.random, helloRetryRequestRandom)

	// Skip legacy version (2) + random (32)
	offset := 2 + 32

	// Session ID length + session ID
	sessionIDLen := int(body[offset])
	offset++
	if offset+sessionIDLen > len(body) {
		return nil, alertErrf(alertDecodeError,
			"server hello session id claims %d bytes, %d remain", sessionIDLen, len(body)-offset)
	}
	sh.sessionID = body[offset : offset+sessionIDLen]
	offset += sessionIDLen

	// Cipher suite (2) + compression method (1)
	if offset+3 > len(body) {
		return nil, alertErrf(alertDecodeError, "truncated server hello")
	}
	sh.suite = binary.BigEndian.Uint16(body[offset:])
	offset += 2

	// legacy_compression_method. RFC 8446 §4.1.3 fixes it at null, and a client
	// "MUST abort the handshake with an 'illegal_parameter' alert" on anything
	// else. It was being skipped unread; a non-zero value here means the peer is
	// not speaking TLS 1.3, whatever its supported_versions claims.
	if body[offset] != 0x00 {
		return nil, alertErrf(alertIllegalParameter,
			"server hello legacy_compression_method is %d, want 0", body[offset])
	}
	offset++

	switch sh.suite {
	case cipherTLS_AES_128_GCM_SHA256, cipherTLS_AES_256_GCM_SHA384, cipherTLS_CHACHA20_POLY1305_SHA256:
	default:
		// §4.1.3 again: the suite has to be one the ClientHello offered. Every
		// suite this stack can key is a TLS 1.3 one, so anything else is both
		// unusable and out of contract.
		//
		// Naming the version is the whole of this message's job, and it used to
		// name only the number. A TLS 1.2 server always trips this check rather
		// than the supported_versions one below — the suite is read first — so
		// the one failure mode a user actually meets was reported as "unsupported
		// cipher suite 0xc030" with no mention of a version anywhere. That is a
		// diagnosis nobody arrives at from the text: it reads like a missing
		// algorithm, sends the reader looking for a cipher list, and the answer
		// is that the connection is not TLS 1.3 at all.
		return nil, alertErrf(alertIllegalParameter,
			"server selected cipher suite 0x%04x, which is not one of the three TLS 1.3 suites — "+
				"this client speaks TLS 1.3 only, so the peer has negotiated TLS 1.2 or earlier. "+
				"Either the server does not offer TLS 1.3, or something between here and it is "+
				"terminating the connection", sh.suite)
	}

	// Extensions. TLS 1.3 is signalled by supported_versions, so a ServerHello
	// without extensions is by definition not a 1.3 handshake.
	if offset+2 > len(body) {
		return nil, alertErrf(alertProtocolVersion, "server hello has no extensions (not TLS 1.3)")
	}
	extsLen := int(binary.BigEndian.Uint16(body[offset:]))
	offset += 2
	if offset+extsLen > len(body) {
		return nil, alertErrf(alertDecodeError,
			"server hello extensions claim %d bytes, %d remain", extsLen, len(body)-offset)
	}
	if offset+extsLen != len(body) {
		return nil, alertErrf(alertDecodeError,
			"server hello has %d trailing bytes after its extensions", len(body)-offset-extsLen)
	}
	sh.exts = body[offset : offset+extsLen]

	return sh, nil
}

// checkServerHelloShell applies the checks that need to compare the message
// against the ClientHello we actually sent. They cover both a real ServerHello
// and a HelloRetryRequest, which shares this header.
func (hs *handshakeState) checkServerHelloShell(sh *serverHelloShell) error {
	// RFC 8446 §4.1.3: "A client which receives a legacy_session_id_echo field
	// that does not match what it sent in the ClientHello MUST abort the
	// handshake with an 'illegal_parameter' alert."
	//
	// Both profiles send a fresh 32-byte session id for middlebox compatibility,
	// so this is a live check rather than a formality: an echo that does not
	// match means the hello that reached the server is not the hello that left,
	// which is what a rewriting middlebox looks like from here. It is also the
	// cheapest way to catch a response that belongs to a different connection.
	sessionID, err := clientHelloSessionID(hs.clientHelloMsg)
	if err != nil {
		return withAlert(alertInternalError, fmt.Errorf("re-read own client hello: %w", err))
	}
	if !bytes.Equal(sh.sessionID, sessionID) {
		return alertErrf(alertIllegalParameter,
			"server echoed a %d-byte session id that does not match the %d-byte one sent",
			len(sh.sessionID), len(sessionID))
	}

	// The downgrade sentinels only mean something in a ServerHello; §4.1.3
	// exempts a HelloRetryRequest, whose random is the fixed HRR value.
	if !sh.isHRR && len(sh.random) == 32 {
		tail := sh.random[24:]
		if bytes.Equal(tail, tls12DowngradeSentinel) || bytes.Equal(tail, tls11DowngradeSentinel) {
			return alertErrf(alertIllegalParameter,
				"server signalled a TLS downgrade in ServerHello.random")
		}
	}
	return nil
}

// serverHelloOnlyExtensions is the complete set RFC 8446 §4.2 permits in a
// ServerHello. Anything else that we recognise is forbidden there — most of it
// because TLS 1.3 moved it into EncryptedExtensions.
var serverHelloForbiddenExtensions = []uint16{
	extServerName, extStatusRequest, extSupportedGroups, extECPointFormats,
	extSignatureAlgorithms, extALPN, extSCT, extExtendedMasterSecret,
	extCompressCertificate, extSessionTicket, extCookie, extPSKKeyExchangeModes,
	extALPS, extECH, extRenegotiationInfo,
}

// parseServerHello extracts the DHE shared secret (X25519, P-256, P-384, P-521
// or X25519MLKEM768) from an already-shelled ServerHello.
//
// ALPN is deliberately not read here. TLS 1.3 moved it into
// EncryptedExtensions, so a ServerHello carrying one is a server contradicting
// the version it just negotiated — and honouring it would let a cleartext,
// unauthenticated field decide the application protocol for the connection.
func (hs *handshakeState) parseServerHello(sh *serverHelloShell) (dhe []byte, err error) {
	fail := func(desc uint8, format string, args ...any) ([]byte, error) {
		return nil, alertErrf(desc, format, args...)
	}

	var (
		isTLS13      bool
		keyShareData []byte
	)
	if err := forEachExtension(sh.exts, func(extType uint16, extData []byte) error {
		switch extType {
		case extSupportedVersions:
			if len(extData) == 2 && binary.BigEndian.Uint16(extData) == versionTLS13 {
				isTLS13 = true
			}
		case extKeyShare:
			keyShareData = extData
		case extPreSharedKey:
			// Selecting from an empty list is still a contract violation.
			// Ignoring it used to mean deriving the key schedule without the PSK
			// the server had already mixed in, and the handshake died several
			// messages later at "server finished MAC mismatch" — a decryption
			// symptom for what is really a ServerHello violation. When a PSK was
			// offered, the acceptance was already read in run() and the schedule
			// built from it, so there is nothing left to check here.
			if hs.psk == nil {
				return alertErrf(alertIllegalParameter, "server selected a pre-shared key that was never offered")
			}
		default:
			if containsUint16(serverHelloForbiddenExtensions, extType) {
				return alertErrf(alertUnsupportedExtension,
					"extension 0x%04x is not allowed in a TLS 1.3 ServerHello", extType)
			}
			// Genuinely unknown types are left alone: §4.2 only requires
			// aborting on extensions the client recognises but did not expect
			// here, and GREASE relies on the rest being ignored.
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if !isTLS13 {
		return fail(alertProtocolVersion, "server did not negotiate TLS 1.3 (falling back not supported)")
	}
	if keyShareData == nil {
		return fail(alertMissingExtension, "no key_share in ServerHello")
	}

	dhe, err = hs.processServerKeyShare(keyShareData)
	if err != nil {
		return nil, withAlert(alertIllegalParameter, fmt.Errorf("key share: %w", err))
	}

	return dhe, nil
}

// checkNegotiatedALPN rejects a protocol the ClientHello never offered.
//
// RFC 7301 §3.2: "In the event that the server supports no protocols that the
// client advertises, then the server SHALL respond with a fatal
// 'no_application_protocol' alert" — the selection is not the server's to invent.
// Letting one through is not cosmetic here: dialTLSForH2 treats any value other
// than "h2" as an HTTP/1.1 server and caches that verdict for ten minutes, so a
// peer answering with a protocol nobody offered can force every later request to
// that host onto HTTP/1.1.
func (hs *handshakeState) checkNegotiatedALPN(proto string) error {
	for _, offered := range hs.alpn {
		if proto == offered {
			return nil
		}
	}
	return alertErrf(alertNoApplicationProtocol,
		"server selected ALPN %q, which was not offered (%v)", proto, hs.alpn)
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

	default:
		// Every remaining group we can negotiate is a plain ECDH curve. The
		// private key is looked up rather than switched on so the set stays in
		// one place: X25519 and P-256 are generated up front, and P-384/P-521
		// only appear here after a HelloRetryRequest asked for one.
		priv := hs.km.privateKeyFor(group)
		if priv == nil {
			return nil, fmt.Errorf("unsupported server key share group: 0x%04x", group)
		}
		serverPub, err := priv.Curve().NewPublicKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse server key for group 0x%04x: %w", group, err)
		}
		shared, err := priv.ECDH(serverPub)
		if err != nil {
			return nil, fmt.Errorf("ecdh for group 0x%04x: %w", group, err)
		}
		return shared, nil
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

// parseCertificateRequestContext pulls the certificate_request_context out of a
// CertificateRequest body, which RFC 8446 §4.3.2 lays out as:
//
//	opaque certificate_request_context<0..2^8-1>;
//	Extension extensions<2..2^16-1>;
//
// It is opaque and normally empty in a handshake-time request, but it must be
// echoed byte-for-byte in the answering Certificate, so it is read rather than
// assumed.
func parseCertificateRequestContext(body []byte) ([]byte, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("certificate_request too short")
	}
	ctxLen := int(body[0])
	if 1+ctxLen > len(body) {
		return nil, fmt.Errorf("certificate_request context claims %d bytes, %d remain", ctxLen, len(body)-1)
	}
	return append([]byte(nil), body[1:1+ctxLen]...), nil
}

// emptyCertificateMessage builds the Certificate message a client sends when it
// was asked for one and has none: the echoed context, then a zero-length
// certificate_list. RFC 8446 §4.4.2 explicitly allows the empty list, and it is
// how anonymous clients answer an optional-mTLS server.
func emptyCertificateMessage(reqContext []byte) []byte {
	body := make([]byte, 0, 1+len(reqContext)+3)
	body = append(body, byte(len(reqContext)))
	body = append(body, reqContext...)
	body = append(body, 0x00, 0x00, 0x00) // certificate_list length: 0

	msg := make([]byte, 4+len(body))
	msg[0] = handshakeTypeCertificate
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)
	return msg
}

// maxCertificateChain bounds how many certificates one chain may carry. A
// 256 KiB message has room for thousands of tiny ones, each costing an
// x509.ParseCertificate, and x509.Verify's path building is worse than linear in
// the size of the intermediate pool. Real chains are three or four deep.
const maxCertificateChain = 32

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
		// A trailing stub too short to hold an entry header is a malformed
		// list, not the end of one. Breaking out of the loop accepted whatever
		// had been parsed so far and let the handshake continue against a chain
		// the server never finished sending.
		if offset+3 > end {
			return nil, fmt.Errorf("certificate entry header truncated")
		}
		certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if offset+certLen > end {
			return nil, fmt.Errorf("certificate data overflow")
		}
		if len(certs) == maxCertificateChain {
			return nil, fmt.Errorf("certificate chain exceeds %d certificates", maxCertificateChain)
		}

		cert, err := x509.ParseCertificate(data[offset : offset+certLen])
		if err != nil {
			return nil, fmt.Errorf("parse cert: %w", err)
		}
		certs = append(certs, cert)
		offset += certLen

		// Every TLS 1.3 CertificateEntry carries an extensions field, so its
		// two length bytes are mandatory rather than optional trailing data.
		if offset+2 > end {
			return nil, fmt.Errorf("certificate entry extensions truncated")
		}
		extLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		// An overrunning length used to push offset past end, which ended the
		// loop quietly and returned a chain built from a message that did not
		// parse.
		if offset+extLen > end {
			return nil, fmt.Errorf("certificate entry extensions claim %d bytes, %d remain", extLen, end-offset)
		}
		offset += extLen
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
// the negotiated ALPN protocol, or "" if the server selected none. Body layout:
//
//	extensions_length(2) + [ ext_type(2) + ext_length(2) + ext_data ]*
//
// For ALPN the data is protocol_name_list_length(2) + length(1) + name.
//
// A malformed extension is an error rather than a silent "". EncryptedExtensions
// is authenticated, so anything unparseable in it is a genuine protocol failure —
// and swallowing it produced the worst possible outcome downstream: an empty ALPN
// makes dialTLSForH2 record the host as HTTP/1.1 for ten minutes, so a single
// garbled extension quietly downgraded every subsequent request to that host.
func parseEncryptedExtensionsALPN(body []byte) (string, error) {
	if len(body) < 2 {
		return "", alertErrf(alertDecodeError, "encrypted_extensions too short")
	}
	extsLen := int(binary.BigEndian.Uint16(body[0:2]))
	exts := body[2:]
	if extsLen > len(exts) {
		return "", alertErrf(alertDecodeError,
			"encrypted_extensions claims %d bytes, %d remain", extsLen, len(exts))
	}
	exts = exts[:extsLen]

	var alpn string
	err := forEachExtension(exts, func(extType uint16, extData []byte) error {
		if extType != extALPN {
			return nil
		}
		// RFC 7301: ProtocolNameList holds exactly one name in a server's
		// answer, and both its length prefixes have a minimum of 1.
		if len(extData) < 3 {
			return alertErrf(alertDecodeError, "malformed alpn extension (%d bytes)", len(extData))
		}
		listLen := int(binary.BigEndian.Uint16(extData[0:2]))
		if 2+listLen != len(extData) {
			return alertErrf(alertDecodeError,
				"alpn list claims %d bytes, %d remain", listLen, len(extData)-2)
		}
		protoLen := int(extData[2])
		if protoLen == 0 || 3+protoLen != len(extData) {
			return alertErrf(alertDecodeError,
				"alpn protocol claims %d bytes, %d remain", protoLen, len(extData)-3)
		}
		alpn = string(extData[3 : 3+protoLen])
		return nil
	})
	if err != nil {
		return "", err
	}
	return alpn, nil
}
