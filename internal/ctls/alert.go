package ctls

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
)

// TLS alert levels (RFC 8446 §6).
//
// The level is vestigial in TLS 1.3 — §6.2 says the severity is implicit in the
// alert description and that the field "can safely be ignored" — but it is still
// on the wire, so both values are needed to build and to read a record.
const (
	alertLevelWarning = 1
	alertLevelFatal   = 2
)

// Alert descriptions (RFC 8446 §6, plus the RFC 7301 and RFC 6066 additions the
// profiles' extensions can provoke).
const (
	alertCloseNotify                  = 0
	alertUnexpectedMessage            = 10
	alertBadRecordMAC                 = 20
	alertRecordOverflow               = 22
	alertHandshakeFailure             = 40
	alertBadCertificate               = 42
	alertUnsupportedCertificate       = 43
	alertCertificateRevoked           = 44
	alertCertificateExpired           = 45
	alertCertificateUnknown           = 46
	alertIllegalParameter             = 47
	alertUnknownCA                    = 48
	alertAccessDenied                 = 49
	alertDecodeError                  = 50
	alertDecryptError                 = 51
	alertProtocolVersion              = 70
	alertInsufficientSecurity         = 71
	alertInternalError                = 80
	alertInappropriateFallback        = 86
	alertUserCanceled                 = 90
	alertMissingExtension             = 109
	alertUnsupportedExtension         = 110
	alertUnrecognizedName             = 112
	alertBadCertificateStatusResponse = 113
	alertUnknownPSKIdentity           = 115
	alertCertificateRequired          = 116
	alertNoApplicationProtocol        = 120
)

// alertNames gives the failures a server reports a readable name.
//
// "server alert: 47" says nothing about what went wrong; "illegal_parameter"
// points straight at a rejected ClientHello field, which is the difference
// between a diagnosable fingerprint bug and a mystery.
var alertNames = map[uint8]string{
	alertCloseNotify:                  "close_notify",
	alertUnexpectedMessage:            "unexpected_message",
	alertBadRecordMAC:                 "bad_record_mac",
	alertRecordOverflow:               "record_overflow",
	alertHandshakeFailure:             "handshake_failure",
	alertBadCertificate:               "bad_certificate",
	alertUnsupportedCertificate:       "unsupported_certificate",
	alertCertificateRevoked:           "certificate_revoked",
	alertCertificateExpired:           "certificate_expired",
	alertCertificateUnknown:           "certificate_unknown",
	alertIllegalParameter:             "illegal_parameter",
	alertUnknownCA:                    "unknown_ca",
	alertAccessDenied:                 "access_denied",
	alertDecodeError:                  "decode_error",
	alertDecryptError:                 "decrypt_error",
	alertProtocolVersion:              "protocol_version",
	alertInsufficientSecurity:         "insufficient_security",
	alertInternalError:                "internal_error",
	alertInappropriateFallback:        "inappropriate_fallback",
	alertUserCanceled:                 "user_canceled",
	alertMissingExtension:             "missing_extension",
	alertUnsupportedExtension:         "unsupported_extension",
	alertUnrecognizedName:             "unrecognized_name",
	alertBadCertificateStatusResponse: "bad_certificate_status_response",
	alertUnknownPSKIdentity:           "unknown_psk_identity",
	alertCertificateRequired:          "certificate_required",
	alertNoApplicationProtocol:        "no_application_protocol",
}

func alertName(desc uint8) string {
	if name, ok := alertNames[desc]; ok {
		return name
	}
	return fmt.Sprintf("alert(%d)", desc)
}

// peerAlert is a fatal alert received from the server.
type peerAlert struct {
	desc uint8
}

func (a *peerAlert) Error() string {
	return fmt.Sprintf("server alert: %s (%d)", alertName(a.desc), a.desc)
}

// localAlert pairs a local failure with the alert description the peer should
// be told about. sendFatalAlert reads the description back out with errors.As,
// so annotating an error is all a failure path has to do to get the right alert
// on the wire.
type localAlert struct {
	desc uint8
	err  error
}

func (a *localAlert) Error() string { return a.err.Error() }
func (a *localAlert) Unwrap() error { return a.err }

// alertErrf builds an error carrying the alert to send for it.
func alertErrf(desc uint8, format string, args ...any) error {
	return &localAlert{desc: desc, err: fmt.Errorf(format, args...)}
}

// withAlert tags an existing error with an alert description, leaving any
// description already attached deeper in the chain alone — the innermost
// failure knows best what went wrong.
func withAlert(desc uint8, err error) error {
	if err == nil {
		return nil
	}
	var la *localAlert
	if errors.As(err, &la) {
		return err
	}
	return &localAlert{desc: desc, err: err}
}

// alertDescFor returns the alert to send for err.
//
// Anything that was not explicitly tagged is a handshake_failure, which is what
// RFC 8446 §6.2 designates for "the sender was unable to negotiate an acceptable
// set of security parameters" — the honest description for a generic abort.
func alertDescFor(err error) uint8 {
	var la *localAlert
	if errors.As(err, &la) {
		return la.desc
	}
	return alertHandshakeFailure
}

// isNetworkFailure reports whether err is the connection dying rather than the
// peer misbehaving. There is nobody left to alert in that case, and a read that
// timed out has an expired deadline, so the write would fail anyway.
func isNetworkFailure(err error) bool {
	switch {
	case errors.Is(err, errHandshakeClosed),
		errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EPIPE):
		return true
	}
	var nerr net.Error
	return errors.As(err, &nerr)
}

// errHandshakeClosed is the peer ending the handshake with close_notify rather
// than a ServerHello. It is a clean shutdown, not a protocol failure, so no
// alert is owed in return beyond the close_notify Conn.Close would send — and
// there is no Conn yet.
var errHandshakeClosed = errors.New("server closed the connection during the handshake")

// alertWriteTimeout bounds the best-effort alert write on an aborting
// handshake. The connection is being torn down either way, so this only exists
// to stop a peer that has stopped reading from pinning the goroutine — which is
// a real risk on a dial whose context carried no deadline.
const alertWriteTimeout = 2 * time.Second

// alertRecord is the two-byte body of an alert record.
func alertRecord(level, desc uint8) []byte {
	return []byte{level, desc}
}

// receivedAlert turns an alert record body into an error, or nil if the alert
// is one a client may ignore and keep reading past.
//
// RFC 8446 §6.2 removed the level field's meaning: "all the alerts listed in
// Section 6.2 MUST be sent with AlertLevel=fatal and MUST be treated as error
// alerts when received regardless of the AlertLevel in the message. Unknown
// Alert types MUST be treated as error alerts."
//
// Trusting the level instead let a server abort us at warning level and have it
// silently ignored: the handshake kept reading, burned its no-progress budget
// and surfaced "server sent 64 records without a server hello" — or, past the
// handshake, spun until the read deadline — in place of the real reason. TLS
// 1.2 servers that send a warning-level unrecognized_name and carry on are the
// one population this used to help, and they cannot reach here anyway, since
// this stack negotiates 1.3 or fails.
//
// Only the two closure alerts of §6.1 are not errors. close_notify is handled by
// the caller, which knows whether an orderly shutdown is legal at that point;
// user_canceled is a courtesy notice that a close_notify follows, so it is
// ignored and the next record is read.
func receivedAlert(body []byte) (desc uint8, err error) {
	if len(body) < 2 {
		return 0, alertErrf(alertDecodeError, "malformed alert record (%d bytes)", len(body))
	}
	desc = body[1]
	switch desc {
	case alertCloseNotify, alertUserCanceled:
		return desc, nil
	default:
		return desc, &peerAlert{desc: desc}
	}
}
