package ctls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// Conn is a TLS 1.3 connection with browser fingerprint emulation.
// It implements net.Conn and provides ConnectionState() for HTTP/2 compatibility.
type Conn struct {
	net.Conn // underlying TCP connection

	serverName      string
	negotiatedALPN  string
	serverReader    *encryptedRecord // server → client application data
	clientWriter    *encryptedRecord // client → server application data

	readBuf []byte // decrypted application data buffer
	readErr error  // stored read error
}

// NegotiatedProtocol returns the negotiated ALPN protocol.
func (c *Conn) NegotiatedProtocol() string {
	return c.negotiatedALPN
}

// ConnectionState returns a tls.ConnectionState for HTTP/2 transport compatibility.
// The http2 transport uses this to check the negotiated ALPN protocol.
func (c *Conn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		Version:                     tls.VersionTLS13,
		HandshakeComplete:           true,
		ServerName:                  c.serverName,
		NegotiatedProtocol:          c.negotiatedALPN,
		NegotiatedProtocolIsMutual:  true,
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
				if plaintext[0] == alertLevelFatal {
					c.readErr = fmt.Errorf("tls alert: %s", alertText(plaintext[1]))
					return 0, c.readErr
				}
				if plaintext[1] == alertCloseNotify {
					c.readErr = fmt.Errorf("connection closed")
					return 0, c.readErr
				}
			}
			continue

		case recordTypeHandshake:
			// Post-handshake messages (e.g., NewSessionTicket) - skip
			continue

		default:
			return 0, fmt.Errorf("unexpected inner type %d", innerType)
		}
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

// Dial creates a new TLS connection to addr with Firefox 148 fingerprint.
// addr must be in host:port format. alpn specifies the ALPN protocols to offer.
func Dial(ctx context.Context, network, addr string, alpn []string) (*Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host port: %w", err)
	}
	return DialWithConfig(ctx, network, addr, host, alpn, false, nil, BrowserFirefox148)
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

// WrapConn performs the TLS 1.3 handshake over an existing net.Conn.
// This is the main entry point for use with pre-dialed connections (proxies, etc.).
func WrapConn(ctx context.Context, rawConn net.Conn, serverName string, alpn []string, skipVerify bool, rootCAs *x509.CertPool, browser BrowserType) (*Conn, error) {
	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		if err := rawConn.SetDeadline(deadline); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	tlsConn, err := handshake(rawConn, serverName, alpn, skipVerify, rootCAs, browser)
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
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}
