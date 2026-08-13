package ctls

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Conn is a TLS 1.3 connection with browser fingerprint emulation.
// It implements net.Conn and provides ConnectionState() for HTTP/2 compatibility.
type Conn struct {
	net.Conn // underlying TCP connection

	serverName     string
	negotiatedALPN string
	suite          uint16
	peerCerts      []*x509.Certificate

	// ks and the traffic secrets are retained so post-handshake KeyUpdate can
	// re-derive record keys.
	ks              *tlsKeySchedule
	serverAppSecret []byte
	clientAppSecret []byte

	// br buffers record reads so a header and its body come from one syscall.
	// It is inherited from the handshake, which may already have pulled the
	// first application-data bytes into it.
	br *bufio.Reader

	serverReader *encryptedRecord // server → client application data
	readBuf      []byte           // decrypted application data buffer
	readErr      error            // stored read error
	postHS       []byte           // partial post-handshake message reassembly
	keyUpdates   int              // KeyUpdates honoured, bounded by maxKeyUpdates

	// sessions receives the tickets this connection is handed, if the dialer
	// supplied a cache. Tickets arrive after the handshake, on the application
	// data stream, so this has to outlive the handshake that set it up.
	sessions      *SessionCache
	ticketsStored int
	didResume     bool

	// writeMu serialises everything that touches clientWriter. The AEAD
	// sequence number it holds must advance exactly once per record, and
	// http2 calls Close from a different goroutine than the one running the
	// write loop — without this, two records can be sealed under the same
	// nonce, which both corrupts the stream and destroys AEAD security.
	writeMu      sync.Mutex
	clientWriter *encryptedRecord // client → server application data
	writeBuf     []byte           // reusable record buffer, guarded by writeMu
	closeSent    bool
}

// NegotiatedProtocol returns the negotiated ALPN protocol.
func (c *Conn) NegotiatedProtocol() string {
	return c.negotiatedALPN
}

// ConnectionState returns a tls.ConnectionState for HTTP/2 transport
// compatibility and for callers inspecting Response.TLS.
func (c *Conn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		Version:                    tls.VersionTLS13,
		HandshakeComplete:          true,
		ServerName:                 c.serverName,
		NegotiatedProtocol:         c.negotiatedALPN,
		NegotiatedProtocolIsMutual: true,
		CipherSuite:                c.suite,
		PeerCertificates:           c.peerCerts,
		DidResume:                  c.didResume,
	}
}

// Read reads decrypted application data from the TLS connection.
func (c *Conn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	if c.readErr != nil {
		return 0, c.readErr
	}

	// Read records until we get application data.
	//
	// idle counts consecutive records that yielded no application data —
	// ChangeCipherSpec, warning alerts, post-handshake messages and empty
	// payloads all fall through with a `continue`. Each is legal, but none of
	// them is bounded by anything else: net/http2 drives liveness with PINGs
	// rather than read deadlines, so without a ceiling a peer can pin this
	// goroutine forever by trickling records that say nothing. A real peer
	// sends a handful (two session tickets is typical), so 64 in a row is far
	// past anything legitimate. The counter is per-Read, so it resets as soon
	// as one byte of application data comes through.
	idle := 0
	noProgress := func() error {
		if idle++; idle > maxNoProgressRecords {
			return fmt.Errorf("peer sent %d records carrying no application data", idle)
		}
		return nil
	}
	for {
		rec, err := readRawRecord(c.br)
		if err != nil {
			c.readErr = err
			return 0, err
		}

		// Skip ChangeCipherSpec
		if rec.typ == recordTypeChangeCipherSpec {
			if err := noProgress(); err != nil {
				c.readErr = err
				return 0, err
			}
			continue
		}

		if rec.typ != recordTypeApplicationData {
			c.readErr = fmt.Errorf("unexpected record type %d", rec.typ)
			return 0, c.readErr
		}

		plaintext, innerType, err := c.serverReader.decrypt(rec.data)
		if err != nil {
			c.readErr = fmt.Errorf("decrypt: %w", err)
			return 0, c.readErr
		}

		switch innerType {
		case recordTypeApplicationData:
			if len(plaintext) == 0 {
				if err := noProgress(); err != nil {
					c.readErr = err
					return 0, err
				}
				continue
			}
			n := copy(b, plaintext)
			if n < len(plaintext) {
				c.readBuf = plaintext[n:]
			}
			return n, nil

		case recordTypeAlert:
			// close_notify is a clean shutdown and must surface as io.EOF.
			// net/http ends a Content-Length-less HTTP/1.1 body on EOF and
			// treats anything else as a truncated response, so reporting an
			// error here corrupts every connection-close-delimited body.
			//
			// Everything else except user_canceled is fatal regardless of the
			// level byte — see receivedAlert. Reading the level instead meant a
			// server tearing the connection down at warning level was ignored
			// here, and the caller saw the read spin to its deadline rather than
			// the reason the peer gave.
			desc, alertErr := receivedAlert(plaintext)
			if alertErr != nil {
				c.readErr = alertErr
				return 0, c.readErr
			}
			if desc == alertCloseNotify {
				c.readErr = io.EOF
				return 0, io.EOF
			}
			if err := noProgress(); err != nil {
				c.readErr = err
				return 0, err
			}
			continue

		case recordTypeHandshake:
			if err := c.handlePostHandshake(plaintext); err != nil {
				c.readErr = err
				return 0, err
			}
			if err := noProgress(); err != nil {
				c.readErr = err
				return 0, err
			}
			continue

		default:
			c.readErr = fmt.Errorf("unexpected inner type %d", innerType)
			return 0, c.readErr
		}
	}
}

// handlePostHandshake processes handshake messages arriving after the handshake
// completes. NewSessionTicket is banked for resumption when a cache is attached,
// and KeyUpdate must be acted on: once a server rekeys, every later record is
// encrypted under the new secret, so ignoring it turns the rest of the
// connection into decrypt failures. Long-lived, high-stream-count connections
// are exactly the ones servers rekey.
func (c *Conn) handlePostHandshake(data []byte) error {
	if len(c.postHS)+len(data) > maxHandshakeMessage {
		return fmt.Errorf("post-handshake message exceeds %d bytes", maxHandshakeMessage)
	}
	c.postHS = append(c.postHS, data...)

	for len(c.postHS) >= 4 {
		msgLen := int(c.postHS[1])<<16 | int(c.postHS[2])<<8 | int(c.postHS[3])
		if msgLen > maxHandshakeMessage-4 {
			return fmt.Errorf("post-handshake message length %d exceeds limit", msgLen)
		}
		if len(c.postHS) < 4+msgLen {
			// Message spans records; wait for the rest.
			return nil
		}
		msgType := c.postHS[0]
		body := c.postHS[4 : 4+msgLen]
		c.postHS = c.postHS[4+msgLen:]

		switch msgType {
		case handshakeTypeKeyUpdate:
			if len(body) != 1 {
				return fmt.Errorf("malformed key_update")
			}
			// Every KeyUpdate costs two HKDF expansions and an AEAD setup, and
			// an update_requested one also costs a record write — all driven by
			// the peer. The per-Read no-progress ceiling does not bound it,
			// because it resets on each byte of application data, so a peer
			// could alternate one byte with a burst of updates indefinitely.
			// Real servers rekey a handful of times over a connection's life.
			if c.keyUpdates++; c.keyUpdates > maxKeyUpdates {
				return fmt.Errorf("peer sent %d key_updates on one connection", c.keyUpdates)
			}
			if err := c.rekeyServer(); err != nil {
				return err
			}
			if body[0] == keyUpdateRequested {
				if err := c.sendKeyUpdate(); err != nil {
					return err
				}
			}

		case handshakeTypeNewSessionTicket:
			// A ticket is only worth keeping when someone asked for a cache and
			// the connection actually derived a resumption secret. Anything
			// malformed is dropped rather than fatal: a bad ticket costs a
			// resumption, and killing a working connection over one would be a
			// worse trade than the feature is worth.
			if c.sessions == nil || c.ks == nil || c.ticketsStored >= maxTicketsPerSession {
				break
			}
			lifetime, ageAdd, nonce, ticket, allowEarly, err := parseNewSessionTicket(body)
			if err != nil || lifetime <= 0 {
				break
			}
			psk := c.ks.resumptionPSK(nonce)
			if len(psk) == 0 {
				break
			}
			c.sessions.put(c.serverName, &sessionTicket{
				psk:        psk,
				identity:   ticket,
				ageAdd:     ageAdd,
				received:   time.Now(),
				lifetime:   lifetime,
				suite:      c.suite,
				allowEarly: allowEarly,
			})
			c.ticketsStored++

		default:
			// Anything else post-handshake (for example a CertificateRequest
			// for post-handshake auth we never opted into) is ignored.
		}
	}
	// Fully drained: release the buffer. Re-slicing alone leaves the read
	// offset marching forward through the backing array, so every later append
	// starts further in and the array is regrown for bytes already consumed.
	if len(c.postHS) == 0 {
		c.postHS = nil
	}
	return nil
}

// maxKeyUpdates bounds how many times one connection will follow the peer's
// rekeying. RFC 8446 sets no limit; servers that rekey at all do so on a byte or
// time budget, which is single digits over any realistic connection lifetime.
const maxKeyUpdates = 32

// rekeyServer advances the server's application traffic secret one generation
// (RFC 8446 §4.6.3) and installs the resulting record keys.
func (c *Conn) rekeyServer() error {
	next := hkdfExpandLabel(c.ks.h, c.serverAppSecret, "traffic upd", nil, c.ks.h().Size())
	aead, iv, err := c.ks.makeTrafficKeys(next)
	if err != nil {
		return fmt.Errorf("key_update server keys: %w", err)
	}
	c.serverAppSecret = next
	c.serverReader = newEncryptedRecord(aead, iv)
	return nil
}

// sendKeyUpdate replies to an update_requested KeyUpdate and rotates our own
// sending key. The send and the key swap happen under writeMu so no other
// writer can slip a record in between and encrypt it under the wrong key.
func (c *Conn) sendKeyUpdate() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	msg := []byte{handshakeTypeKeyUpdate, 0, 0, 1, keyUpdateNotRequested}
	ciphertext, err := c.clientWriter.encrypt(msg, recordTypeHandshake)
	if err != nil {
		return fmt.Errorf("encrypt key_update: %w", err)
	}
	if err := writeRawRecord(c.Conn, recordTypeApplicationData, ciphertext); err != nil {
		return fmt.Errorf("send key_update: %w", err)
	}

	next := hkdfExpandLabel(c.ks.h, c.clientAppSecret, "traffic upd", nil, c.ks.h().Size())
	aead, iv, err := c.ks.makeTrafficKeys(next)
	if err != nil {
		return fmt.Errorf("key_update client keys: %w", err)
	}
	c.clientAppSecret = next
	c.clientWriter = newEncryptedRecord(aead, iv)
	return nil
}

// Write encrypts and sends application data.
func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Split into max 16KB records
	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxPlaintextRecord {
			chunk = chunk[:maxPlaintextRecord]
		}

		// Seal straight into the connection's reusable buffer: header and
		// ciphertext land in one allocation-free slice and go out as one write.
		record, err := c.clientWriter.sealRecord(c.writeBuf, chunk, recordTypeApplicationData)
		if err != nil {
			return written, fmt.Errorf("encrypt: %w", err)
		}
		c.writeBuf = record

		if _, err := c.Conn.Write(record); err != nil {
			return written, err
		}

		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

// Close sends a close_notify alert and closes the underlying connection.
func (c *Conn) Close() error {
	c.writeMu.Lock()
	if !c.closeSent {
		c.closeSent = true
		// Best-effort close_notify
		alert := []byte{alertLevelWarning, alertCloseNotify}
		if ciphertext, err := c.clientWriter.encrypt(alert, recordTypeAlert); err == nil {
			writeRawRecord(c.Conn, recordTypeApplicationData, ciphertext) //nolint
		}
	}
	c.writeMu.Unlock()
	return c.Conn.Close()
}

// Dial creates a new TLS connection to addr with the Safari iOS 18 fingerprint.
// addr must be in host:port format. alpn specifies the ALPN protocols to offer.
func Dial(ctx context.Context, network, addr string, alpn []string) (*Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host port: %w", err)
	}
	return DialWithConfig(ctx, network, addr, host, alpn, false, nil, BrowserSafari)
}

// DialWithConfig creates a TLS connection with full configuration.
func DialWithConfig(ctx context.Context, network, addr, serverName string, alpn []string, skipVerify bool, rootCAs *x509.CertPool, browser BrowserType) (*Conn, error) {
	var d net.Dialer
	rawConn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}

	return WrapConn(ctx, rawConn, serverName, alpn, skipVerify, rootCAs, browser)
}

// DefaultHandshakeTimeout bounds a handshake whose context carries no deadline
// of its own.
//
// Without it there was no bound at all on that path: a peer that completes the
// TCP handshake and then sends nothing — a black-holing edge, a stalled proxy, a
// tarpit — held the dialing goroutine and its connection forever, because every
// other ceiling in this package bounds work rather than wall clock. The value is
// deliberately generous; it is a backstop, not a policy. Callers that care set a
// deadline on the context, which always wins when it is the earlier of the two.
const DefaultHandshakeTimeout = 30 * time.Second

// SetSessionCache tells the connection where to deposit the session tickets the
// server sends it.
//
// It is a setter rather than a handshake parameter because tickets are
// post-handshake messages: they arrive on the application data stream, so a
// cache attached any time before the first Read catches them all. Keeping it
// off WrapConn's signature also keeps resumption from becoming something every
// caller has to know about.
func (c *Conn) SetSessionCache(cache *SessionCache) {
	c.sessions = cache
}

// WrapConn performs the TLS 1.3 handshake over an existing net.Conn.
// This is the main entry point for use with pre-dialed connections (proxies, etc.).
func WrapConn(ctx context.Context, rawConn net.Conn, serverName string, alpn []string, skipVerify bool, rootCAs *x509.CertPool, browser BrowserType) (*Conn, error) {
	return WrapConnResuming(ctx, rawConn, serverName, alpn, skipVerify, rootCAs, browser, nil)
}

// WrapConnResuming is WrapConn with a session cache: tickets from this
// connection are deposited in it, and one already there is offered as a PSK.
//
// A resumed handshake is a shorter one, but that is not why it is here. A client
// that opens hundreds of connections to a host and resumes none of them is a
// client no browser reproduces — the pattern is visible whatever the
// ClientHello looks like.
func WrapConnResuming(ctx context.Context, rawConn net.Conn, serverName string, alpn []string, skipVerify bool, rootCAs *x509.CertPool, browser BrowserType, sessions *SessionCache) (*Conn, error) {
	// Set deadline from the context, falling back to the package default so
	// this can never run unbounded.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultHandshakeTimeout)
	}
	if err := rawConn.SetDeadline(deadline); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	tlsConn, err := handshake(rawConn, serverName, alpn, skipVerify, rootCAs, browser, sessions)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	// Attached before the deadline is cleared so the tickets that follow the
	// handshake land somewhere.
	tlsConn.sessions = sessions

	// Clear deadline after handshake
	if err := rawConn.SetDeadline(time.Time{}); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("clear deadline: %w", err)
	}

	return tlsConn, nil
}

// SetReadDeadline sets the read deadline.
//
// This and SetWriteDeadline must stay independent. net/http and http2 drive
// them separately — ResponseHeaderTimeout and ReadIdleTimeout against the read
// side, WriteByteTimeout against the write side — so collapsing both onto
// SetDeadline makes whichever was set last silently cancel the other, giving
// either spurious i/o timeouts or no timeout at all.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline. See SetReadDeadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
