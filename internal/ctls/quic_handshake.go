package ctls

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// The TLS 1.3 handshake, driven over QUIC instead of over records.
//
// QUIC carries handshake messages in CRYPTO frames and does its own packet
// protection, so the record layer that handshake.go is built around has nothing
// to do here. What remains is the same handshake: the same ClientHello builders,
// the same key schedule, the same transcript discipline, the same certificate
// verification. flight.go holds the part both transports share.
//
// The shape of this API is deliberate. It matches crypto/tls's QUICConn — Start,
// HandleData, NextEvent, with events that hand out secrets and outbound bytes —
// because that is the interface quic-go already consumes. Swapping this package
// in for crypto/tls in the fork is then a change of names rather than a change
// of design, and anything that reads oddly here can be checked against the
// standard library's version of the same idea.
//
// Three things differ from the TCP path, and each is a rule rather than a
// preference:
//
//   - No ChangeCipherSpec. RFC 9001 section 8.4 forbids it outright, where the
//     TCP path sends one for middlebox compatibility.
//   - Fatal alerts are not records. RFC 9001 section 4.8 maps them onto a
//     CONNECTION_CLOSE frame with error code 0x0100 + the alert, so this driver
//     surfaces the alert to its caller rather than writing anything.
//   - The peer's transport parameters arrive in EncryptedExtensions, not in the
//     ServerHello, and a handshake that completes without them is not usable.

// QUICEncryptionLevel names the packet protection level a payload belongs to.
type QUICEncryptionLevel int

const (
	QUICEncryptionLevelInitial QUICEncryptionLevel = iota
	QUICEncryptionLevelHandshake
	QUICEncryptionLevelApplication
)

func (l QUICEncryptionLevel) String() string {
	switch l {
	case QUICEncryptionLevelInitial:
		return "Initial"
	case QUICEncryptionLevelHandshake:
		return "Handshake"
	case QUICEncryptionLevelApplication:
		return "Application"
	}
	return fmt.Sprintf("level(%d)", int(l))
}

// QUICEventKind is what the handshake is asking the transport to do.
type QUICEventKind int

const (
	// QUICNoEvent means the queue is empty: feed more data.
	QUICNoEvent QUICEventKind = iota

	// QUICSetReadSecret and QUICSetWriteSecret hand over a traffic secret for
	// one direction at one level. The transport derives its own key, IV and
	// header-protection key from it with QUIC's labels; handing over the secret
	// rather than the keys is what keeps those labels out of this package.
	QUICSetReadSecret
	QUICSetWriteSecret

	// QUICWriteData carries handshake bytes for the transport to put in CRYPTO
	// frames at the given level.
	QUICWriteData

	// QUICHandshakeDone is emitted once, after the client's Finished.
	QUICHandshakeDone
)

// QUICEvent is one instruction from the handshake to the transport.
type QUICEvent struct {
	Kind  QUICEventKind
	Level QUICEncryptionLevel

	// Data is the handshake bytes for QUICWriteData.
	Data []byte

	// Suite and Secret carry a traffic secret for the Set*Secret events.
	Suite  uint16
	Secret []byte
}

// QUICConfig configures a client handshake.
type QUICConfig struct {
	ServerName string
	ALPN       []string

	// TransportParams is the encoded quic_transport_parameters extension body.
	// Required.
	TransportParams []byte

	SkipVerify bool
	RootCAs    *x509.CertPool
}

// QUICHandshake is a client-side TLS 1.3 handshake driven by a QUIC transport.
//
// It is a state machine with no I/O of its own: the transport feeds it CRYPTO
// data with HandleData and drains its instructions with NextEvent.
type QUICHandshake struct {
	cfg QUICConfig
	hs  *handshakeState

	events  []QUICEvent
	flight  flightState
	reader  map[QUICEncryptionLevel]*handshakeReader
	started bool
	done    bool

	// sawServerHello gates the Initial level: exactly one ServerHello is
	// expected there and nothing else.
	sawServerHello bool

	peerParams []byte
}

// NewQUICClient prepares a handshake. Nothing is sent until Start.
func NewQUICClient(cfg QUICConfig) (*QUICHandshake, error) {
	if len(cfg.TransportParams) == 0 {
		return nil, errors.New("ctls: QUIC handshake needs transport parameters")
	}
	km, err := generateKeyMaterial()
	if err != nil {
		return nil, err
	}
	return &QUICHandshake{
		cfg: cfg,
		hs: &handshakeState{
			serverName: cfg.ServerName,
			alpn:       cfg.ALPN,
			skipVerify: cfg.SkipVerify,
			rootCAs:    cfg.RootCAs,
			browser:    BrowserChrome,
			km:         km,
		},
		reader: map[QUICEncryptionLevel]*handshakeReader{
			QUICEncryptionLevelInitial:   {},
			QUICEncryptionLevelHandshake: {},
		},
	}, nil
}

// Start builds the ClientHello and queues it for the Initial level.
func (q *QUICHandshake) Start() error {
	if q.started {
		return errors.New("ctls: handshake already started")
	}
	q.started = true

	msg, err := buildChromeQUICClientHelloWith(QUICHelloConfig{
		ServerName:      q.cfg.ServerName,
		ALPN:            q.cfg.ALPN,
		TransportParams: q.cfg.TransportParams,
	}, q.hs.km, nil)
	if err != nil {
		return fmt.Errorf("ctls: build QUIC client hello: %w", err)
	}
	q.hs.clientHelloMsg = msg
	q.emit(QUICEvent{Kind: QUICWriteData, Level: QUICEncryptionLevelInitial, Data: msg})
	return nil
}

// HandleData feeds CRYPTO frame payload arriving at one encryption level.
//
// Data may arrive in any number of pieces; the reader for each level
// reassembles complete handshake messages before any of them is processed.
func (q *QUICHandshake) HandleData(level QUICEncryptionLevel, data []byte) error {
	if !q.started {
		return errors.New("ctls: handshake not started")
	}
	hr, ok := q.reader[level]
	if !ok {
		return fmt.Errorf("ctls: no handshake data expected at level %s", level)
	}
	if err := hr.add(data); err != nil {
		return withAlert(alertRecordOverflow, err)
	}
	for {
		msg, err := hr.next()
		if err != nil {
			return withAlert(alertDecodeError, err)
		}
		if msg == nil {
			return nil
		}
		if err := q.handle(level, msg); err != nil {
			return err
		}
	}
}

// NextEvent pops one instruction, or a QUICNoEvent when there are none.
func (q *QUICHandshake) NextEvent() QUICEvent {
	if len(q.events) == 0 {
		return QUICEvent{Kind: QUICNoEvent}
	}
	e := q.events[0]
	q.events = q.events[1:]
	return e
}

// PeerTransportParams returns the parameters the server sent in
// EncryptedExtensions, or nil before they arrive.
func (q *QUICHandshake) PeerTransportParams() []byte { return q.peerParams }

// NegotiatedALPN returns the protocol the server chose.
func (q *QUICHandshake) NegotiatedALPN() string { return q.hs.negotiatedALPN }

// PeerCertificates returns the chain the server presented.
func (q *QUICHandshake) PeerCertificates() []*x509.Certificate { return q.flight.serverCerts }

// Done reports whether the handshake has completed.
func (q *QUICHandshake) Done() bool { return q.done }

func (q *QUICHandshake) emit(e QUICEvent) { q.events = append(q.events, e) }

// handle routes one complete handshake message.
func (q *QUICHandshake) handle(level QUICEncryptionLevel, msg []byte) error {
	switch level {
	case QUICEncryptionLevelInitial:
		if msg[0] != handshakeTypeServerHello {
			return alertErrf(alertUnexpectedMessage,
				"expected server hello at the Initial level, got handshake type %d", msg[0])
		}
		if q.sawServerHello {
			return alertErrf(alertUnexpectedMessage, "second server hello")
		}
		q.sawServerHello = true
		return q.handleServerHello(msg)

	case QUICEncryptionLevelHandshake:
		if !q.sawServerHello {
			return alertErrf(alertUnexpectedMessage,
				"handshake-level data before the server hello")
		}
		if q.flight.finished {
			return alertErrf(alertUnexpectedMessage,
				"handshake type %d after the server's Finished", msg[0])
		}
		if msg[0] == handshakeTypeEncryptedExtensions {
			params, err := parseEncryptedExtensionsTransportParams(msg[4:])
			if err != nil {
				return err
			}
			q.peerParams = params
		}
		if err := q.hs.handleFlightMessage(msg, &q.flight); err != nil {
			return err
		}
		if q.flight.finished {
			return q.finish()
		}
		return nil
	}
	return fmt.Errorf("ctls: unexpected handshake data at level %s", level)
}

// handleServerHello sets up the key schedule and publishes the handshake
// secrets.
func (q *QUICHandshake) handleServerHello(msg []byte) error {
	hs := q.hs

	shell, err := parseServerHelloShell(msg)
	if err != nil {
		return alertErrf(alertDecodeError, "parse server hello: %v", err)
	}
	if err := hs.checkServerHelloShell(shell); err != nil {
		return err
	}
	if shell.isHRR {
		// Answering a retry means re-sending a second ClientHello with the
		// substitutions RFC 8446 section 4.1.2 allows, and keeping the
		// synthetic message_hash transcript that replaces the first one. The
		// TCP path does all of that through the record layer. Rather than a
		// half-written QUIC version, this says what happened: both profiles
		// key X25519MLKEM768 and X25519 preemptively, and no server that
		// speaks HTTP/3 has been observed asking for anything else.
		return alertErrf(alertHandshakeFailure,
			"server sent a hello retry request; not implemented for QUIC")
	}

	hs.suite = shell.suite
	hs.ks = newKeySchedule(shell.suite)
	hs.transcript = hs.ks.h()
	hs.transcript.Write(hs.clientHelloMsg)
	hs.transcript.Write(msg)

	dhe, err := hs.parseServerHello(shell)
	if err != nil {
		return alertErrf(alertIllegalParameter, "parse server hello: %v", err)
	}
	hs.ks.deriveHandshakeSecrets(dhe, hs.transcript.Sum(nil))

	// Both directions become available at once: the server is already writing
	// at this level and the client's Finished will go out at it.
	q.emit(QUICEvent{
		Kind: QUICSetReadSecret, Level: QUICEncryptionLevelHandshake,
		Suite: hs.suite, Secret: hs.ks.serverHSTraffic,
	})
	q.emit(QUICEvent{
		Kind: QUICSetWriteSecret, Level: QUICEncryptionLevelHandshake,
		Suite: hs.suite, Secret: hs.ks.clientHSTraffic,
	})
	return nil
}

// finish derives the application secrets and queues the client's Finished.
func (q *QUICHandshake) finish() error {
	hs := q.hs

	if !hs.skipVerify {
		if len(q.flight.serverCerts) == 0 {
			return alertErrf(alertCertificateRequired, "server sent no certificate")
		}
		if !q.flight.sawCertVerify {
			return alertErrf(alertUnexpectedMessage, "server sent no certificate_verify")
		}
	}
	if len(q.peerParams) == 0 {
		return alertErrf(alertMissingExtension,
			"server sent no quic_transport_parameters")
	}

	// RFC 8446 section 7.1: the master secrets come from the transcript through
	// the server's Finished, before anything the client adds.
	hs.ks.deriveMasterSecrets(hs.transcript.Sum(nil))

	var flight []byte
	if q.flight.sawCertRequest {
		flight = append(flight, emptyCertificateMessage(q.flight.certReqContext)...)
		hs.transcript.Write(flight)
	}

	finishedKey := hs.ks.finishedKey(hs.ks.clientHSTraffic)
	mac := computeFinishedMAC(hs.ks.h, finishedKey, hs.transcript.Sum(nil))

	finishedMsg := make([]byte, 4+len(mac))
	finishedMsg[0] = handshakeTypeFinished
	finishedMsg[1] = byte(len(mac) >> 16)
	finishedMsg[2] = byte(len(mac) >> 8)
	finishedMsg[3] = byte(len(mac))
	copy(finishedMsg[4:], mac)
	flight = append(flight, finishedMsg...)

	hs.transcript.Write(finishedMsg)
	hs.ks.deriveResumptionMaster(hs.transcript.Sum(nil))

	// The application secrets are published before the Finished goes out, so a
	// transport that wants to send 1-RTT immediately after it can.
	q.emit(QUICEvent{
		Kind: QUICSetReadSecret, Level: QUICEncryptionLevelApplication,
		Suite: hs.suite, Secret: hs.ks.serverAppTraffic,
	})
	q.emit(QUICEvent{
		Kind: QUICSetWriteSecret, Level: QUICEncryptionLevelApplication,
		Suite: hs.suite, Secret: hs.ks.clientAppTraffic,
	})
	q.emit(QUICEvent{
		Kind: QUICWriteData, Level: QUICEncryptionLevelHandshake, Data: flight,
	})
	q.emit(QUICEvent{Kind: QUICHandshakeDone})
	q.done = true
	return nil
}

// parseEncryptedExtensionsTransportParams pulls extension 0x0039 out of an
// EncryptedExtensions body.
//
// Over TCP this extension does not exist; over QUIC a handshake that completes
// without it has agreed no flow control limits, so its absence is a protocol
// error rather than a missing option.
func parseEncryptedExtensionsTransportParams(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, alertErrf(alertDecodeError, "encrypted_extensions is %d bytes", len(body))
	}
	total := int(body[0])<<8 | int(body[1])
	if 2+total > len(body) {
		return nil, alertErrf(alertDecodeError, "encrypted_extensions overruns its body")
	}
	var out []byte
	err := forEachExtension(body[2:2+total], func(extType uint16, extData []byte) error {
		if extType == extQUICTransportParameters {
			out = append([]byte(nil), extData...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
