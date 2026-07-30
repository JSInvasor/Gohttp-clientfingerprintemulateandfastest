package ctls

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestParseServerHelloRejectsMalformed asserts the ServerHello parser reports an
// error rather than panicking on attacker-controlled length fields.
//
// The parser runs on the dial path, so a panic here is not a failed request: it
// is an unrecovered panic in whichever goroutine is dialing, which takes the
// whole process down. Any host this client connects to — including one reached
// through an untrusted proxy — can send these bytes.
func TestParseServerHelloRejectsMalformed(t *testing.T) {
	// Minimal well-formed prefix: version(2) random(32) sid_len(1)=0
	// cipher(2) compression(1), then a 2-byte extensions length we corrupt.
	base := func(extsLen uint16, extBytes []byte) []byte {
		body := make([]byte, 0, 64)
		body = appendUint16(body, versionTLS12)
		body = append(body, make([]byte, 32)...)
		body = append(body, 0x00) // session_id length
		body = appendUint16(body, cipherTLS_AES_128_GCM_SHA256)
		body = append(body, 0x00) // compression
		body = appendUint16(body, extsLen)
		body = append(body, extBytes...)

		msg := make([]byte, 4+len(body))
		msg[0] = handshakeTypeServerHello
		msg[1] = byte(len(body) >> 16)
		msg[2] = byte(len(body) >> 8)
		msg[3] = byte(len(body))
		copy(msg[4:], body)
		return msg
	}

	// An extension whose declared length runs past the extensions block.
	overrunExt := func() []byte {
		e := make([]byte, 0, 8)
		e = appendUint16(e, extSupportedVersions)
		e = appendUint16(e, 0xFFF0) // claims 65520 bytes of data
		e = append(e, 0x03, 0x04)
		return e
	}()

	// A TLS 1.3 hello whose key_share entry declares more key bytes than exist.
	keyShareOverrun := func() []byte {
		ks := make([]byte, 0, 8)
		ks = appendUint16(ks, groupX25519)
		ks = appendUint16(ks, 0xFF00) // claims 65280 bytes of key
		ks = append(ks, 0x01, 0x02)

		exts := make([]byte, 0, 32)
		exts = appendExt(exts, extSupportedVersions, []byte{0x03, 0x04})
		exts = appendExt(exts, extKeyShare, ks)
		return base(uint16(len(exts)), exts)
	}()

	cases := map[string][]byte{
		"extensions length overruns body": base(0xFFFF, nil),
		"extension data overruns block":   base(uint16(len(overrunExt)), overrunExt),
		"key_share length overruns":       keyShareOverrun,
		"truncated after cipher suite":    base(0, nil)[:40],
	}

	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic instead of error: %v", r)
				}
			}()
			km, err := generateKeyMaterial()
			if err != nil {
				t.Fatalf("key material: %v", err)
			}
			hs := &handshakeState{km: km}
			if _, _, _, _, err := hs.parseServerHello(msg); err == nil {
				t.Fatal("expected an error for malformed ServerHello, got nil")
			}
		})
	}
	_ = binary.BigEndian
}

// TestReadAndWriteDeadlinesAreIndependent guards the deadline plumbing on Conn.
//
// The HTTP/2 write path arms a write deadline before every frame write
// (writeWithByteTimeout) and clears it afterwards. If SetWriteDeadline also
// moves the read deadline, that write path silently reaches across into the
// read loop running concurrently on the same socket: an in-flight write can
// time out an idle read, and clearing the write deadline wipes any read
// deadline the caller had set.
func TestReadAndWriteDeadlinesAreIndependent(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	tc := &Conn{Conn: c1}

	// Arm a write deadline that has already expired.
	if err := tc.SetWriteDeadline(time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		c2.Write([]byte("hello"))
	}()

	// Conn.Read reads from the embedded conn, so that is where the read
	// deadline has to be unset for this to work.
	buf := make([]byte, 5)
	if _, err := tc.Conn.Read(buf); err != nil {
		t.Fatalf("an expired write deadline broke reads: %v", err)
	}
}

// TestCloseNotifyReportsEOF pins the end-of-stream signal.
//
// net/http reads a body of unknown length until io.EOF; any other error makes
// the response fail. TLS close_notify is exactly that orderly end of stream, so
// mapping it to a generic error turns every correctly-terminated
// "Connection: close" response into a failed request.
func TestCloseNotifyReportsEOF(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ks := newKeySchedule(cipherTLS_AES_128_GCM_SHA256)
	secret := make([]byte, 32)
	aead, iv, err := ks.makeTrafficKeys(secret)
	if err != nil {
		t.Fatalf("traffic keys: %v", err)
	}
	reader := &Conn{Conn: c1, serverReader: newEncryptedRecord(aead, iv)}

	aead2, iv2, err := ks.makeTrafficKeys(secret)
	if err != nil {
		t.Fatalf("traffic keys: %v", err)
	}
	writer := newEncryptedRecord(aead2, iv2)

	go func() {
		ct, err := writer.encrypt([]byte{alertLevelWarning, alertCloseNotify}, recordTypeAlert)
		if err != nil {
			return
		}
		writeRawRecord(c2, recordTypeApplicationData, ct)
	}()

	buf := make([]byte, 16)
	_, err = reader.Read(buf)
	if err != io.EOF {
		t.Fatalf("close_notify surfaced as %v (%T), want io.EOF", err, err)
	}
}

// TestHandshakeMessageSpanningRecords covers reassembly across TLS records.
//
// RFC 8446 §5.1 is explicit that record boundaries carry no meaning for
// handshake messages: one message may span several records, and one record may
// hold several messages. Servers exercise this freely — a certificate chain
// large enough to pass the 16 KiB record limit forces it — so a client that
// treats each record as a self-contained flight works against most servers and
// fails against the rest, which is far harder to diagnose than failing against
// all of them.
func TestHandshakeMessageSpanningRecords(t *testing.T) {
	const host = "example.com"
	pool, leafDER, leafKey := testCertChain(t, host)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Split partway through the Certificate message: EncryptedExtensions is
		// a handful of bytes, so 40 lands inside the certificate.
		rogueServerHandshakeFragmented(c, leafDER, leafKey, 40)
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(15 * time.Second))

	conn, err := handshake(raw, &Config{
		ServerName: host,
		ALPN:       []string{"h2"},
		RootCAs:    pool,
		Browser:    BrowserSafari,
	})
	if err != nil {
		t.Fatalf("handshake failed when the server split its flight across "+
			"records, which RFC 8446 §5.1 permits: %v", err)
	}
	conn.Close()
}
