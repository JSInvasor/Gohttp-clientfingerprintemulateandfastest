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
		// DidResume stays false: this package never offers a PSK, so every
		// connection is a full handshake.
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
		rec, err := readRawRecord(c.br)
		if err != nil {
			c.readErr = err
			return 0, err
		}

		// Skip ChangeCipherSpec
		if rec.typ == recordTypeChangeCipherSpec {
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
				continue
			}
			n := copy(b, plaintext)
			if n < len(plaintext) {
				c.readBuf = plaintext[n:]
			}
			return n, nil

		case recordTypeAlert:
			if len(plaintext) >= 2 {
				// close_notify is a clean shutdown and must surface as io.EOF.
				// net/http ends a Content-Length-less HTTP/1.1 body on EOF and
				// treats anything else as a truncated response, so reporting an
				// error here corrupts every connection-close-delimited body.
				// It is sent at warning level, so check it before the level.
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
			if err := c.handlePostHandshake(plaintext); err != nil {
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
// completes. NewSessionTicket is dropped (this package never resumes), but
// KeyUpdate must be acted on: once a server rekeys, every later record is
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
			if err := c.rekeyServer(); err != nil {
				return err
			}
			if body[0] == keyUpdateRequested {
				if err := c.sendKeyUpdate(); err != nil {
					return err
				}
			}

		case handshakeTypeNewSessionTicket:
			// Ignored: no session resumption.

		default:
			// Anything else post-handshake (for example a CertificateRequest
			// for post-handshake auth we never opted into) is ignored.
		}
	}
	return nil
}

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
