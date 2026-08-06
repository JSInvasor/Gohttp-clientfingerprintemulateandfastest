package ctls

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// alertProbe runs one handshake against a server that consumes the ClientHello
// and then replies with whatever reply writes, returning the client-side error.
func alertProbe(t *testing.T, reply func(net.Conn)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var hdr [recordHeaderLen]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		length := int(hdr[3])<<8 | int(hdr[4])
		if _, err := io.ReadFull(conn, make([]byte, length)); err != nil {
			return
		}
		reply(conn)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := WrapConn(ctx, conn, "example.com", []string{"h2"}, false, nil, BrowserChrome); err != nil {
		<-served
		return err.Error()
	}
	t.Fatal("handshake succeeded against a server that never sent a ServerHello")
	return ""
}

// TestFatalAlertIsNamed pins that a rejected ClientHello reports the server's
// own reason.
//
// A server that refuses the handshake answers with an alert record — content
// type 21 — and the description byte inside it is the only explanation we ever
// get. Reporting the record type ("expected handshake record, got 21") names
// the envelope and discards the message; reporting a bare description ("server
// alert: 40") leaves a lookup to the reader. Both were real outputs of this
// package, and both cost more debugging time than the handshake itself.
func TestFatalAlertIsNamed(t *testing.T) {
	cases := []struct {
		desc uint8
		want string
	}{
		{40, "handshake_failure (40)"},
		{70, "protocol_version (70)"},
		{80, "internal_error (80)"},
		{112, "unrecognized_name (112)"},
		{116, "certificate_required (116)"},
		{200, "unknown alert (200)"},
	}

	for _, tc := range cases {
		desc := tc.desc
		got := alertProbe(t, func(c net.Conn) {
			writeRawRecord(c, recordTypeAlert, []byte{alertLevelFatal, desc})
			// Stay open so the client fails on the alert, not on EOF.
			time.Sleep(200 * time.Millisecond)
		})
		if !strings.Contains(got, "server alert: "+tc.want) {
			t.Errorf("alert %d: got %q, want it to name %q", desc, got, tc.want)
		}
		// The record type is the envelope, never the diagnosis.
		if strings.Contains(got, "got 21") {
			t.Errorf("alert %d: error still reports the record type: %q", desc, got)
		}
	}
}

// TestWarningAlertSurvivesTheClose pins that a warning alert followed by a
// silent hangup keeps its explanation.
//
// Warning alerts are skipped so the handshake can continue, which is correct
// per RFC 8446 §6.1 — but plenty of servers warn (unrecognized_name is the
// common one) and then just close instead of alerting fatally. The skip left
// nothing behind but "read record header: EOF", which reads as a dropped
// connection — blaming the network for a rejection the server explained.
func TestWarningAlertSurvivesTheClose(t *testing.T) {
	got := alertProbe(t, func(c net.Conn) {
		writeRawRecord(c, recordTypeAlert, []byte{alertLevelWarning, 112})
		// No close_notify, no fatal alert: just hang up.
	})

	if !strings.Contains(got, "unrecognized_name (112)") {
		t.Fatalf("the warning alert was lost behind the EOF: %q", got)
	}
	if !strings.Contains(got, "EOF") {
		t.Fatalf("want the underlying read failure kept too, got %q", got)
	}
}

// TestNonTLSReplyIsReported pins that bytes which are not TLS at all say so.
//
// A proxy that answers the CONNECT in cleartext, a captive portal, or a plain
// HTTP port all deliver ASCII where a record header belongs. Parsing on read
// bytes 4-5 of "HTTP/" as a length and reported "record too large: 20527
// bytes" — a number with no relationship to anything the operator can act on.
func TestNonTLSReplyIsReported(t *testing.T) {
	cases := []struct {
		name  string
		reply string
	}{
		{"cleartext HTTP response", "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"},
		{"proxy error page", "<html><body>proxy auth required</body></html>"},
	}

	for _, tc := range cases {
		got := alertProbe(t, func(c net.Conn) {
			c.Write([]byte(tc.reply))
			time.Sleep(200 * time.Millisecond)
		})
		if !strings.Contains(got, "not a TLS record") {
			t.Errorf("%s: got %q, want it identified as non-TLS", tc.name, got)
		}
		// The readable form is what makes it actionable at a glance.
		if !strings.Contains(got, `"`+tc.reply[:recordHeaderLen]+`"`) {
			t.Errorf("%s: got %q, want the first bytes shown as ASCII", tc.name, got)
		}
		if strings.Contains(got, "record too large") {
			t.Errorf("%s: still reporting a bogus length: %q", tc.name, got)
		}
	}
}

// TestValidRecordHeadersStillAccepted guards the non-TLS check against
// rejecting real traffic: every content type TLS 1.3 puts on the wire, at both
// record versions this package writes, must still parse.
func TestValidRecordHeadersStillAccepted(t *testing.T) {
	types := []uint8{
		recordTypeChangeCipherSpec,
		recordTypeAlert,
		recordTypeHandshake,
		recordTypeApplicationData,
	}
	versions := []uint16{versionTLS10, versionTLS12, versionTLS13}

	for _, typ := range types {
		for _, vers := range versions {
			header := []byte{typ, byte(vers >> 8), byte(vers), 0x00, 0x03}
			raw := append(header, 'a', 'b', 'c')

			rec, err := readRawRecord(strings.NewReader(string(raw)))
			if err != nil {
				t.Fatalf("type %d version 0x%04x: %v", typ, vers, err)
			}
			if rec.typ != typ || string(rec.data) != "abc" {
				t.Fatalf("type %d version 0x%04x: got typ=%d data=%q", typ, vers, rec.typ, rec.data)
			}
		}
	}
}

// TestUnexpectedRecordTypeIsNamed pins the message that started all this: a
// content type we did not expect is reported by name, not as a bare integer.
func TestUnexpectedRecordTypeIsNamed(t *testing.T) {
	got := alertProbe(t, func(c net.Conn) {
		// Application data before any ServerHello: nothing is keyed yet.
		writeRawRecord(c, recordTypeApplicationData, []byte{0x01, 0x02, 0x03})
		time.Sleep(200 * time.Millisecond)
	})
	if !strings.Contains(got, "expected handshake record, got application_data(23)") {
		t.Fatalf("got %q, want the content type named", got)
	}
}
