package handshake

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/ctls"
)

// FORK DELTA. Not present upstream.
//
// The seam that lets this client's own TLS stack drive a quic-go handshake.
//
// quic-go talks to crypto/tls through eight methods on *tls.QUICConn. This file
// names them as an interface, which *tls.QUICConn already satisfies, and adds
// one implementation beside it that wraps internal/ctls instead. crypto_setup.go
// then holds the interface rather than the concrete type, which is the whole of
// the change there: two lines and a constructor.
//
// Doing it this way rather than by rewriting crypto_setup.go keeps the fork's
// diff against upstream small enough to re-apply by hand after a rebase, which
// is the property internal/quicgo/FORK.md is built on.
//
// The server path is untouched and still runs on crypto/tls. This is a client
// library; a server here would have no fingerprint to emulate, and forking a
// second code path to gain nothing would be paying the rebase cost twice.

// tlsConn is the surface quic-go uses. *tls.QUICConn satisfies it as written.
type tlsConn interface {
	Start(ctx context.Context) error
	NextEvent() tls.QUICEvent
	HandleData(level tls.QUICEncryptionLevel, data []byte) error
	SetTransportParameters(params []byte)
	ConnectionState() tls.ConnectionState
	SendSessionTicket(opts tls.QUICSessionTicketOptions) error
	StoreSession(session *tls.SessionState) error
	Close() error
}

var _ tlsConn = (*tls.QUICConn)(nil)

// ctlsConn drives internal/ctls behind the same interface.
//
// The translation is almost one to one, because internal/ctls's QUIC API was
// written against crypto/tls's on purpose. What is left is the shape of the
// two lifecycles: crypto/tls takes its transport parameters after construction
// and this package's client takes them at construction, so they are held here
// until Start.
type ctlsConn struct {
	cfg    ctls.QUICConfig
	hs     *ctls.QUICHandshake
	params []byte

	// pending holds events produced before the caller drains them, so that a
	// single Start or HandleData can yield several.
	pending []tls.QUICEvent

	// sentParams records that the peer's transport parameters have been passed
	// up. quic-go expects them as an event; internal/ctls exposes them as state,
	// so the transition is synthesised once, when it becomes true.
	sentParams bool
}

// newCTLSClient builds a client-side connection backed by internal/ctls.
//
// The ALPN and server name come from the tls.Config quic-go was handed, so a
// caller configures this exactly as it configures crypto/tls. Everything else
// about the ClientHello — ciphers, groups, extensions, their order, the absence
// of GREASE — is the profile's, and is not configurable: that is the point.
func newCTLSClient(conf *tls.Config) *ctlsConn {
	cfg := ctls.QUICConfig{
		ALPN: conf.NextProtos,
	}
	if conf != nil {
		cfg.ServerName = conf.ServerName
		cfg.SkipVerify = conf.InsecureSkipVerify
		cfg.RootCAs = conf.RootCAs
	}
	return &ctlsConn{cfg: cfg}
}

func (c *ctlsConn) SetTransportParameters(params []byte) {
	c.params = params
	if c.hs != nil {
		// After the handshake has started there is nothing to do with them:
		// they went out in the ClientHello. crypto/tls only asks again on the
		// server side, which this type never serves.
		return
	}
}

func (c *ctlsConn) Start(ctx context.Context) error {
	if c.hs != nil {
		return errors.New("quicgo: TLS handshake already started")
	}
	if len(c.params) == 0 {
		return errors.New("quicgo: transport parameters were never set")
	}
	c.cfg.TransportParams = c.params

	hs, err := ctls.NewQUICClient(c.cfg)
	if err != nil {
		return err
	}
	c.hs = hs
	return c.hs.Start()
}

func (c *ctlsConn) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	if c.hs == nil {
		return errors.New("quicgo: TLS handshake not started")
	}
	return c.hs.HandleData(fromTLSLevel(level), data)
}

func (c *ctlsConn) NextEvent() tls.QUICEvent {
	if len(c.pending) > 0 {
		e := c.pending[0]
		c.pending = c.pending[1:]
		return e
	}
	if c.hs == nil {
		return tls.QUICEvent{Kind: tls.QUICNoEvent}
	}

	ev := c.hs.NextEvent()
	switch ev.Kind {
	case ctls.QUICNoEvent:
		return tls.QUICEvent{Kind: tls.QUICNoEvent}

	case ctls.QUICSetReadSecret:
		return tls.QUICEvent{
			Kind:  tls.QUICSetReadSecret,
			Level: toTLSLevel(ev.Level),
			Suite: ev.Suite,
			Data:  ev.Secret,
		}

	case ctls.QUICSetWriteSecret:
		return tls.QUICEvent{
			Kind:  tls.QUICSetWriteSecret,
			Level: toTLSLevel(ev.Level),
			Suite: ev.Suite,
			Data:  ev.Secret,
		}

	case ctls.QUICWriteData:
		// The peer's transport parameters arrive in EncryptedExtensions, which
		// this package processes while feeding data rather than emitting an
		// event for. quic-go needs them before it can use the connection, so
		// the transition is announced here, once, ahead of whatever is being
		// written at the time.
		out := tls.QUICEvent{
			Kind:  tls.QUICWriteData,
			Level: toTLSLevel(ev.Level),
			Data:  ev.Data,
		}
		if params := c.hs.PeerTransportParams(); !c.sentParams && len(params) > 0 {
			c.sentParams = true
			c.pending = append(c.pending, out)
			return tls.QUICEvent{Kind: tls.QUICTransportParameters, Data: params}
		}
		return out

	case ctls.QUICHandshakeDone:
		return tls.QUICEvent{Kind: tls.QUICHandshakeDone}
	}
	return tls.QUICEvent{Kind: tls.QUICNoEvent}
}

// ConnectionState reports what quic-go passes up to its caller.
//
// Only the fields this client can answer for are filled in. Anything else stays
// zero rather than being invented: a plausible-looking value here would be
// worse than an empty one, because it would be believed.
func (c *ctlsConn) ConnectionState() tls.ConnectionState {
	st := tls.ConnectionState{Version: tls.VersionTLS13}
	if c.hs == nil {
		return st
	}
	st.NegotiatedProtocol = c.hs.NegotiatedALPN()
	st.ServerName = c.cfg.ServerName
	st.PeerCertificates = c.hs.PeerCertificates()
	st.HandshakeComplete = c.hs.Done()
	return st
}

// SendSessionTicket is the server's job and this type is a client.
func (c *ctlsConn) SendSessionTicket(tls.QUICSessionTicketOptions) error {
	return errors.New("quicgo: this TLS stack does not issue session tickets")
}

// StoreSession is reached only through the QUICStoreSession event, which this
// type does not emit yet: internal/ctls has no QUIC ticket store, so there is
// nothing to store. See internal/ctls/quic_hello.go on resumption.
func (c *ctlsConn) StoreSession(*tls.SessionState) error {
	return errors.New("quicgo: this TLS stack does not resume QUIC sessions yet")
}

func (c *ctlsConn) Close() error { return nil }

func toTLSLevel(l ctls.QUICEncryptionLevel) tls.QUICEncryptionLevel {
	switch l {
	case ctls.QUICEncryptionLevelInitial:
		return tls.QUICEncryptionLevelInitial
	case ctls.QUICEncryptionLevelHandshake:
		return tls.QUICEncryptionLevelHandshake
	default:
		return tls.QUICEncryptionLevelApplication
	}
}

func fromTLSLevel(l tls.QUICEncryptionLevel) ctls.QUICEncryptionLevel {
	switch l {
	case tls.QUICEncryptionLevelInitial:
		return ctls.QUICEncryptionLevelInitial
	case tls.QUICEncryptionLevelHandshake:
		return ctls.QUICEncryptionLevelHandshake
	default:
		return ctls.QUICEncryptionLevelApplication
	}
}
