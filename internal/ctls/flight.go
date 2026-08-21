package ctls

import (
	"crypto/hmac"
	"crypto/x509"
	"fmt"
)

// The server's encrypted flight, message by message.
//
// This is the half of the TLS 1.3 handshake that is pure: it reads handshake
// messages, folds them into the transcript, verifies the chain and the
// Finished MAC, and accumulates what the caller needs afterwards. It touches no
// records, no sockets and no packets.
//
// It lives apart from handshake.go because two transports need it. Over TCP the
// messages arrive inside encrypted records; over QUIC they arrive inside CRYPTO
// frames, with no record layer at all. Everything from the message header
// inward is identical, and duplicating it would have meant two copies of the
// certificate verification and the transcript discipline — the two places in
// this package where a divergence is both easy to introduce and silent.

// flightState accumulates what processing the server's flight produces.
type flightState struct {
	serverCerts    []*x509.Certificate
	sawCertVerify  bool
	sawCertRequest bool
	certReqContext []byte
	finished       bool
}

// handleFlightMessage processes one complete handshake message from the
// server's encrypted flight.
//
// msg includes its four-byte header, because the transcript covers it. Whether
// a message belongs in the transcript before or after it is verified differs
// per type and is the reason each case handles its own write rather than the
// loop doing it once.
func (hs *handshakeState) handleFlightMessage(msg []byte, st *flightState) error {
	body := msg[4:]

	switch msg[0] {
	case handshakeTypeEncryptedExtensions:
		// In TLS 1.3 ALPN is delivered here, not in ServerHello.
		// parseServerHello leaves negotiatedALPN empty for 1.3, so
		// extracting it now is what lets the caller route h1-only
		// servers to the HTTP/1.1 transport instead of pumping the
		// h2 preface into them.
		alpn, err := parseEncryptedExtensionsALPN(body)
		if err != nil {
			return err
		}
		if alpn != "" {
			if err := hs.checkNegotiatedALPN(alpn); err != nil {
				return err
			}
			hs.negotiatedALPN = alpn
		}
		hs.transcript.Write(msg)

	case handshakeTypeCertificate:
		hs.transcript.Write(msg)
		certs, err := parseCertificate(body)
		if err != nil {
			return withAlert(alertDecodeError, fmt.Errorf("parse certificate: %w", err))
		}
		st.serverCerts = certs
		if err := hs.verifyChain(st.serverCerts); err != nil {
			return err
		}

	case handshakeTypeCompressedCertificate:
		// RFC 8879: CompressedCertificate replaces Certificate in transcript
		hs.transcript.Write(msg)
		certs, err := parseCompressedCertificate(body)
		if err != nil {
			return withAlert(alertDecodeError, fmt.Errorf("parse compressed certificate: %w", err))
		}
		st.serverCerts = certs
		if err := hs.verifyChain(st.serverCerts); err != nil {
			return err
		}

	case handshakeTypeCertificateVerify:
		// RFC 8446 §4.4.3: the signature covers the transcript up to
		// and including Certificate, so the hash must be taken before
		// this message is folded in.
		if !hs.skipVerify {
			if len(st.serverCerts) == 0 {
				return alertErrf(alertUnexpectedMessage, "certificate_verify before certificate")
			}
			if err := verifyCertificateVerify(body, st.serverCerts[0], hs.transcript.Sum(nil)); err != nil {
				return alertErrf(alertDecryptError, "certificate_verify: %v", err)
			}
		}
		hs.transcript.Write(msg)
		st.sawCertVerify = true

	case handshakeTypeCertificateRequest:
		// The server is asking for a client certificate. We have none
		// to give, but silence is not a legal answer: §4.4.2 requires a
		// Certificate message either way, and a server that asked and
		// got nothing fails the handshake. Sites with optional mTLS —
		// which accept anonymous clients perfectly well once the empty
		// Certificate arrives — used to break here.
		//
		// The context has to be echoed verbatim, so it is kept rather
		// than assumed empty.
		ctx, err := parseCertificateRequestContext(body)
		if err != nil {
			return err
		}
		st.certReqContext = ctx
		st.sawCertRequest = true
		hs.transcript.Write(msg)

	case handshakeTypeFinished:
		// DO NOT update transcript yet - verify first
		finishedKey := hs.ks.finishedKey(hs.ks.serverHSTraffic)
		expectedMAC := computeFinishedMAC(hs.ks.h, finishedKey, hs.transcript.Sum(nil))
		if !hmac.Equal(expectedMAC, body) {
			return alertErrf(alertDecryptError, "server st.finished MAC mismatch")
		}
		// Now update transcript
		hs.transcript.Write(msg)
		st.finished = true

	default:
		// Unknown or unhandled messages still belong in the transcript.
		// Dropping one would desynchronise the Finished MAC and turn a
		// benign extension into a handshake failure.
		hs.transcript.Write(msg)
	}

	return nil
}
