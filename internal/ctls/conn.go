package ctls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Conn is a TLS 1.3 connection with browser fingerprint emulation.
// It implements net.Conn and provides ConnectionState() for HTTP/2 compatibility.
type Conn struct {
	net.Conn // underlying TCP connection

	serverName     string
	negotiatedALPN string
	serverReader   *encryptedRecord // server → client application data
	clientWriter   *encryptedRecord // client → server application data

	readBuf []byte // decrypted application data buffer
	readErr error  // stored read error

	// Resumption state. Tickets arrive after the handshake, interleaved with
	// application data, so the live connection is what turns them into
	// reusable sessions.
	didResume  bool
	hsBuf      []byte // partial post-handshake message awaiting more records
	suite      uint16
	resMaster  []byte
	sessions   *SessionCache
	sessionKey string
}

// DidResume reports whether this connection resumed an earlier session rather
// than performing a full handshake.
func (c *Conn) DidResume() bool { return c.didResume }

// NegotiatedProtocol returns the negotiated ALPN protocol.
func (c *Conn) NegotiatedProtocol() string {
	return c.negotiatedALPN
}

// ConnectionState returns a tls.ConnectionState for HTTP/2 transport compatibility.
// The http2 transport uses this to check the negotiated ALPN protocol.
func (c *Conn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		Version:                    tls.VersionTLS13,
		HandshakeComplete:          true,
		ServerName:                 c.serverName,
		NegotiatedProtocol:         c.negotiatedALPN,
		NegotiatedProtocolIsMutual: true,
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

	// Read records until we get application data
	for {
		rec, err := readRawRecord(c.Conn)
		if err != nil {
			// A clean close at a record boundary ends the stream. Hand back a
			// bare io.EOF rather than the wrapped form so callers comparing
			// against io.EOF see a normal end of data. io.ErrUnexpectedEOF —
			// a close mid-record — deliberately stays an error.
			if errors.Is(err, io.EOF) {
				err = io.EOF
			}
			c.readErr = err
			return 0, err
		}

		// Skip ChangeCipherSpec
		if rec.typ == recordTypeChangeCipherSpec {
			continue
		}

		if rec.typ != recordTypeApplicationData {
			return 0, fmt.Errorf("unexpected record type %d", rec.typ)
		}

		plaintext, innerType, err := c.serverReader.decrypt(rec.data)
		if err != nil {
			c.readErr = err
			return 0, fmt.Errorf("decrypt: %w", err)
		}

		switch innerType {
		case recordTypeApplicationData:
			if len(plaintext) == 0 {
				continue
			}
			n := copy(b, plaintext)
			if n < len(plaintext) {
				c.readBuf = plaintext[n:]
			}
			return n, nil

		case recordTypeAlert:
			if len(plaintext) >= 2 {
				// close_notify is an orderly shutdown, not a failure, and is
				// checked before the level: TLS 1.3 peers send it at either
				// level and treating it as a generic error would turn every
				// correctly terminated response whose length is delimited by
				// connection close into a failed request.
				if plaintext[1] == alertCloseNotify {
					c.readErr = io.EOF
					return 0, io.EOF
				}
				if plaintext[0] == alertLevelFatal {
					c.readErr = fmt.Errorf("tls alert: %d", plaintext[1])
					return 0, c.readErr
				}
			}
			continue

		case recordTypeHandshake:
			// Post-handshake messages. NewSessionTicket is what makes the next
			// connection to this host resumable; discarding it (the previous
			// behaviour) forced a full handshake every time, which is both
			// slower and unlike any real browser.
			c.absorbPostHandshake(plaintext)
			continue

		default:
			return 0, fmt.Errorf("unexpected inner type %d", innerType)
		}
	}
}

// absorbPostHandshake walks post-handshake handshake messages and turns any
// NewSessionTicket into a cached, resumable session. Anything malformed or
// unrecognised is ignored: a bad ticket costs a future resumption, never the
// current connection.
func (c *Conn) absorbPostHandshake(plaintext []byte) {
	if c.sessions == nil || len(c.resMaster) == 0 {
		return
	}
	// Post-handshake messages span records just as the flight does, so a
	// partial NewSessionTicket has to wait for the rest rather than be dropped.
	c.hsBuf = append(c.hsBuf, plaintext...)
	if len(c.hsBuf) > maxHandshakeBuffer {
		c.hsBuf = nil
		return
	}
	for len(c.hsBuf) >= 4 {
		msgType := c.hsBuf[0]
		msgLen := int(c.hsBuf[1])<<16 | int(c.hsBuf[2])<<8 | int(c.hsBuf[3])
		if 4+msgLen > len(c.hsBuf) {
			return // wait for more records
		}
		body := c.hsBuf[4 : 4+msgLen]
		c.hsBuf = c.hsBuf[4+msgLen:]

		if msgType != handshakeTypeNewSessionTicket {
			continue
		}
		lifetime, ageAdd, nonce, ticket, err := parseNewSessionTicket(body)
		if err != nil {
			continue
		}
		h := hashForCipher(c.suite)
		c.sessions.Put(c.sessionKey, &Session{
			psk:       deriveResumptionPSK(h, c.resMaster, nonce),
			ticket:    append([]byte(nil), ticket...),
			ageAdd:    ageAdd,
			lifetime:  lifetime,
			suite:     c.suite,
			createdAt: time.Now(),
		})
	}
}

// Write encrypts and sends application data.
func (c *Conn) Write(b []byte) (int, error) {
	// Split into max 16KB records
	written := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > 16384 {
			chunk = chunk[:16384]
		}

		ciphertext, err := c.clientWriter.encrypt(chunk, recordTypeApplicationData)
		if err != nil {
			return written, fmt.Errorf("encrypt: %w", err)
		}

		if err := writeRawRecord(c.Conn, recordTypeApplicationData, ciphertext); err != nil {
			return written, err
		}

		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

// Close sends a close_notify alert and closes the underlying connection.
func (c *Conn) Close() error {
	// Best-effort close_notify
	alert := []byte{alertLevelWarning, alertCloseNotify}
	ciphertext, err := c.clientWriter.encrypt(alert, recordTypeAlert)
	if err == nil {
		writeRawRecord(c.Conn, recordTypeApplicationData, ciphertext) //nolint
	}
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

// Config carries everything WrapConnConfig needs for one handshake.
type Config struct {
	ServerName string
	ALPN       []string
	SkipVerify bool
	RootCAs    *x509.CertPool
	Browser    BrowserType

	// Sessions, when set, enables TLS 1.3 resumption. SessionKey scopes the
	// tickets: two connections sharing a key may present each other's tickets,
	// which proves to the server that they are the same client. Callers that
	// rotate proxies must include the proxy in the key, or resumption hands the
	// server exactly the correlation the rotation was meant to prevent.
	Sessions   *SessionCache
	SessionKey string
}

// WrapConn performs the TLS 1.3 handshake over an existing net.Conn without
// session resumption. It is the pre-dialed equivalent of Dial.
func WrapConn(ctx context.Context, rawConn net.Conn, serverName string, alpn []string, skipVerify bool, rootCAs *x509.CertPool, browser BrowserType) (*Conn, error) {
	return WrapConnConfig(ctx, rawConn, &Config{
		ServerName: serverName,
		ALPN:       alpn,
		SkipVerify: skipVerify,
		RootCAs:    rootCAs,
		Browser:    browser,
	})
}

// WrapConnConfig performs the TLS 1.3 handshake over an existing net.Conn.
// This is the main entry point for use with pre-dialed connections (proxies, etc.).
func WrapConnConfig(ctx context.Context, rawConn net.Conn, cfg *Config) (*Conn, error) {
	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		if err := rawConn.SetDeadline(deadline); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	tlsConn, err := handshake(rawConn, cfg)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	// Clear deadline after handshake
	if err := rawConn.SetDeadline(time.Time{}); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("clear deadline: %w", err)
	}

	return tlsConn, nil
}

// SetReadDeadline sets the read deadline.
//
// It must not collapse to SetDeadline: that also moves the write deadline, and
// the read and write sides of an HTTP/2 connection run in separate goroutines.
// The write path arms a deadline before each frame and clears it afterwards, so
// aliasing the two lets a write time out an idle read and lets a completed
// write silently clear the caller's read deadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline. See SetReadDeadline for why this
// does not delegate to SetDeadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
