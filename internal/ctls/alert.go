package ctls

import "fmt"

// Alert levels (RFC 8446 §6). In TLS 1.3 every alert except close_notify and
// user_canceled is fatal regardless of the level byte, but servers still set it.
const (
	alertLevelWarning = 1
	alertLevelFatal   = 2
)

// Alert descriptions (RFC 8446 §6.2).
const (
	alertCloseNotify            = 0
	alertUnexpectedMsg          = 10
	alertBadRecordMAC           = 20
	alertRecordOverflow         = 22
	alertHandshakeFailure       = 40
	alertBadCertificate         = 42
	alertUnsupportedCertificate = 43
	alertCertificateRevoked     = 44
	alertCertificateExpired     = 45
	alertCertificateUnknown     = 46
	alertIllegalParameter       = 47
	alertUnknownCA              = 48
	alertAccessDenied           = 49
	alertDecodeError            = 50
	alertDecryptError           = 51
	alertProtocolVersion        = 70
	alertInsufficientSecurity   = 71
	alertInternalError          = 80
	alertInappropriateFallback  = 86
	alertUserCanceled           = 90
	alertMissingExtension       = 109
	alertUnsupportedExtension   = 110
	alertUnrecognizedName       = 112
	alertBadCertStatusResponse  = 113
	alertUnknownPSKIdentity     = 115
	alertCertificateRequired    = 116
	alertNoApplicationProtocol  = 120
)

// alertNames maps an alert description byte to its RFC 8446 §6.2 name.
// Codes retired by TLS 1.3 are included: a server negotiating down or a
// middlebox on the path can still emit them, and a name beats a bare number.
var alertNames = map[uint8]string{
	0:   "close_notify",
	10:  "unexpected_message",
	20:  "bad_record_mac",
	21:  "decryption_failed_RESERVED",
	22:  "record_overflow",
	30:  "decompression_failure_RESERVED",
	40:  "handshake_failure",
	41:  "no_certificate_RESERVED",
	42:  "bad_certificate",
	43:  "unsupported_certificate",
	44:  "certificate_revoked",
	45:  "certificate_expired",
	46:  "certificate_unknown",
	47:  "illegal_parameter",
	48:  "unknown_ca",
	49:  "access_denied",
	50:  "decode_error",
	51:  "decrypt_error",
	60:  "export_restriction_RESERVED",
	70:  "protocol_version",
	71:  "insufficient_security",
	80:  "internal_error",
	86:  "inappropriate_fallback",
	90:  "user_canceled",
	100: "no_renegotiation_RESERVED",
	109: "missing_extension",
	110: "unsupported_extension",
	111: "certificate_unobtainable_RESERVED",
	112: "unrecognized_name",
	113: "bad_certificate_status_response",
	114: "bad_certificate_hash_value_RESERVED",
	115: "unknown_psk_identity",
	116: "certificate_required",
	120: "no_application_protocol",
}

// alertText renders an alert description as "name (code)", falling back to
// "unknown (code)" for values outside the registry.
func alertText(desc uint8) string {
	if name, ok := alertNames[desc]; ok {
		return fmt.Sprintf("%s (%d)", name, desc)
	}
	return fmt.Sprintf("unknown (%d)", desc)
}

// parseAlert decodes an alert record body. ok is false when the body is not a
// well-formed 2-byte alert, which callers report rather than silently skip.
func parseAlert(body []byte) (fatal bool, text string, ok bool) {
	if len(body) < 2 {
		return false, "", false
	}
	desc := body[1]
	// close_notify and user_canceled are the only non-fatal alerts in TLS 1.3
	// (§6.1); everything else terminates the connection whatever the level says.
	fatal = body[0] == alertLevelFatal || (desc != alertCloseNotify && desc != alertUserCanceled)
	return fatal, alertText(desc), true
}

// withAlertContext appends a previously skipped warning alert to err. Servers
// routinely send a warning (unrecognized_name, close_notify) and then just drop
// the connection; without this the caller only ever sees the trailing EOF.
func withAlertContext(err error, warning string) error {
	if warning == "" {
		return err
	}
	return fmt.Errorf("%w (after server warning alert: %s)", err, warning)
}
