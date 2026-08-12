package ctls

import (
	"encoding/binary"
	"fmt"
)

// HelloRetryRequest support (RFC 8446 §4.1.4).
//
// Both profiles put key shares on the wire for X25519MLKEM768 and X25519 only,
// while supported_groups additionally advertises P-256, P-384 and — for Safari
// — P-521. A server configured to require one of those curves therefore cannot
// use either share we sent, and answers with a HelloRetryRequest naming the
// group it wants.
//
// Refusing to answer used to fail those connections outright. That also read as
// non-browser behaviour: a real Chrome or Safari retries here, which is the
// whole reason they advertise groups they do not preemptively key.
//
// The retry is deliberately narrow:
//   - exactly one HelloRetryRequest is honoured (§4.1.4 requires aborting on a
//     second one),
//   - the group has to be one we advertised and one we did not already offer a
//     share for, which is the "would not result in any change" check §4.1.4
//     puts on the client,
//   - the second ClientHello is the first one byte-for-byte with only the
//     substitutions §4.1.2 permits, so the fingerprint the server scores is
//     still the profile's.

// helloRetryRequest is the parsed content of a HelloRetryRequest.
type helloRetryRequest struct {
	suite         uint16
	selectedGroup uint16
	hasGroup      bool
	cookie        []byte
	isTLS13       bool
}

// parseHelloRetryRequest reads the extensions a HelloRetryRequest carries.
//
// Its key_share holds a bare 2-byte NamedGroup rather than a KeyShareEntry,
// which is why it cannot go through the ordinary ServerHello path.
func parseHelloRetryRequest(sh *serverHelloShell) (*helloRetryRequest, error) {
	hrr := &helloRetryRequest{suite: sh.suite}

	if err := forEachExtension(sh.exts, func(extType uint16, extData []byte) error {
		switch extType {
		case extSupportedVersions:
			if len(extData) == 2 && binary.BigEndian.Uint16(extData) == versionTLS13 {
				hrr.isTLS13 = true
			}
		case extKeyShare:
			if len(extData) != 2 {
				return alertErrf(alertDecodeError,
					"hello retry request key_share is %d bytes, want 2", len(extData))
			}
			hrr.selectedGroup = binary.BigEndian.Uint16(extData)
			hrr.hasGroup = true
		case extCookie:
			// Opaque to us; §4.2.2 only requires echoing it back verbatim.
			if len(extData) < 2 {
				return alertErrf(alertDecodeError, "malformed cookie extension")
			}
			cookieLen := int(binary.BigEndian.Uint16(extData))
			if 2+cookieLen != len(extData) {
				return alertErrf(alertDecodeError,
					"cookie claims %d bytes, %d remain", cookieLen, len(extData)-2)
			}
			// Stored with its length prefix so it can be re-emitted as-is.
			hrr.cookie = append([]byte(nil), extData[:2+cookieLen]...)
		default:
			// §4.1.4 gives a HelloRetryRequest the ServerHello extension rules,
			// and those three are the only ones defined for it. Anything else we
			// recognise is forbidden here; unknown types stay ignored so GREASE
			// keeps working.
			if containsUint16(serverHelloForbiddenExtensions, extType) || extType == extPreSharedKey {
				return alertErrf(alertUnsupportedExtension,
					"extension 0x%04x is not allowed in a hello retry request", extType)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if !hrr.isTLS13 {
		return nil, alertErrf(alertProtocolVersion, "hello retry request did not select TLS 1.3")
	}
	if !hrr.hasGroup && len(hrr.cookie) == 0 {
		// Neither a new group nor a cookie means resending the same hello,
		// which §4.1.4 forbids as it cannot make progress.
		return nil, alertErrf(alertIllegalParameter, "hello retry request asks for no change")
	}
	return hrr, nil
}

// retryAfterHelloRetryRequest answers a HelloRetryRequest and returns the real
// ServerHello that follows.
//
// On entry hs.transcript is not yet initialised: the hash is chosen by the
// cipher suite, and for a retried handshake that suite is fixed by the
// HelloRetryRequest rather than by the final ServerHello.
func (hs *handshakeState) retryAfterHelloRetryRequest(hrrMsg []byte, shell *serverHelloShell) ([]byte, *serverHelloShell, error) {
	hrr, err := parseHelloRetryRequest(shell)
	if err != nil {
		return nil, nil, err
	}

	if hrr.hasGroup {
		if err := hs.checkRetryGroup(hrr.selectedGroup); err != nil {
			return nil, nil, err
		}
	}

	// The transcript for a retried handshake replaces ClientHello1 with a
	// synthetic message_hash (§4.4.1), because the server has to be able to
	// reconstruct it without having kept the original hello.
	hs.suite = hrr.suite
	hs.ks = newKeySchedule(hrr.suite)
	hs.transcript = hs.ks.h()

	ch1Hash := hs.ks.h()
	ch1Hash.Write(hs.clientHelloMsg)
	hs.transcript.Write(messageHashMessage(ch1Hash.Sum(nil)))
	hs.transcript.Write(hrrMsg)

	ch2, err := hs.buildRetryClientHello(hrr)
	if err != nil {
		return nil, nil, err
	}

	// Middlebox compatibility: the dummy ChangeCipherSpec goes immediately
	// before the client's second flight, and with a retry that flight is the
	// second ClientHello rather than Finished (RFC 8446 appendix D.4). Sending
	// it here is what stops the later one from going out as well.
	if err := hs.sendChangeCipherSpec(); err != nil {
		return nil, nil, err
	}

	if err := writeRawRecord(hs.conn, recordTypeHandshake, ch2); err != nil {
		return nil, nil, fmt.Errorf("send second client hello: %w", err)
	}
	hs.clientHelloMsg = ch2
	hs.transcript.Write(ch2)

	sh2Msg, err := hs.readServerHelloMessage()
	if err != nil {
		return nil, nil, err
	}
	sh2, err := parseServerHelloShell(sh2Msg)
	if err != nil {
		return nil, nil, fmt.Errorf("parse second server hello: %w", err)
	}
	// The second ServerHello gets the same header checks as the first — session
	// id echo and downgrade sentinel. Skipping them here would have left the
	// retry path as the way around both.
	if err := hs.checkServerHelloShell(sh2); err != nil {
		return nil, nil, err
	}
	if sh2.isHRR {
		// §4.1.4: "If a client receives a second HelloRetryRequest in the same
		// connection [...] it MUST abort the handshake."
		return nil, nil, alertErrf(alertUnexpectedMessage, "server sent a second hello retry request")
	}
	if sh2.suite != hrr.suite {
		// §4.1.4: the ServerHello must keep the suite the retry chose,
		// otherwise the transcript hash the two sides computed disagree.
		return nil, nil, alertErrf(alertIllegalParameter,
			"server changed cipher suite from 0x%04x to 0x%04x after retry", hrr.suite, sh2.suite)
	}

	hs.transcript.Write(sh2Msg)
	return sh2Msg, sh2, nil
}

// checkRetryGroup applies the two limits §4.1.4 puts on the selected group,
// reading both lists back out of the ClientHello we actually sent so they can
// never drift from what the builders emit.
func (hs *handshakeState) checkRetryGroup(group uint16) error {
	supported, offered, err := clientHelloGroups(hs.clientHelloMsg)
	if err != nil {
		return fmt.Errorf("re-read own client hello: %w", err)
	}
	if !containsUint16(supported, group) {
		return alertErrf(alertIllegalParameter,
			"hello retry request selected group 0x%04x, which was not offered in supported_groups", group)
	}
	if containsUint16(offered, group) {
		return alertErrf(alertIllegalParameter,
			"hello retry request selected group 0x%04x, for which a key share was already sent", group)
	}
	if ecdhCurveForGroup(group) == nil {
		return alertErrf(alertIllegalParameter,
			"hello retry request selected group 0x%04x, which has no key exchange", group)
	}
	return nil
}

// buildRetryClientHello produces ClientHello2. RFC 8446 §4.1.2 requires it to
// be ClientHello1 unmodified apart from a small closed set of substitutions, so
// this rewrites the extension block of the original message rather than
// rebuilding a hello from scratch — a rebuild would redraw the GREASE values
// and reshuffle Chrome's extension order, which a server comparing the two
// hellos is entitled to reject.
func (hs *handshakeState) buildRetryClientHello(hrr *helloRetryRequest) ([]byte, error) {
	extStart, err := clientHelloExtensionsStart(hs.clientHelloMsg)
	if err != nil {
		return nil, err
	}
	oldExts := hs.clientHelloMsg[extStart:]

	var newKeyShare []byte
	if hrr.hasGroup {
		pub, err := hs.km.generateRetryKey(hrr.selectedGroup)
		if err != nil {
			return nil, err
		}
		// §4.2.8: "replace the original 'key_share' extension with one
		// containing only a new KeyShareEntry for the group indicated in the
		// selected_group field". Only — so the GREASE entry goes too.
		entry := make([]byte, 2+2+2+len(pub))
		binary.BigEndian.PutUint16(entry[0:], uint16(2+2+len(pub)))
		binary.BigEndian.PutUint16(entry[2:], hrr.selectedGroup)
		binary.BigEndian.PutUint16(entry[4:], uint16(len(pub)))
		copy(entry[6:], pub)
		newKeyShare = entry
	}

	var out []byte
	if err := forEachExtension(oldExts, func(extType uint16, extData []byte) error {
		switch extType {
		case extKeyShare:
			if newKeyShare == nil {
				// Cookie-only retry: the shares stay exactly as they were.
				out = appendExt(out, extKeyShare, extData)
				return nil
			}
			out = appendExt(out, extKeyShare, newKeyShare)
			// §4.2.2 requires the cookie to be echoed. Placing it next to
			// key_share keeps the profile's trailing GREASE extension last,
			// which is where both emulated browsers put theirs.
			if len(hrr.cookie) > 0 {
				out = appendExt(out, extCookie, hrr.cookie)
			}
		case extCookie:
			// A cookie in our own hello can only be one we added on an earlier
			// pass; the HelloRetryRequest's replaces it.
		case extECH:
			// The ECH spec carves out its own exception to §4.1.2's "send the
			// same hello": the second ClientHelloOuter repeats the extension
			// with the same config_id, cipher suite and payload length, but
			// with an empty enc — the HPKE context was already established by
			// the first one. BoringSSL does this for its GREASE extension too,
			// so a real Chrome's second hello is a few bytes shorter here.
			retryECH, err := echGreaseForRetry(extData)
			if err != nil {
				return err
			}
			out = appendExt(out, extType, retryECH)
		default:
			out = appendExt(out, extType, extData)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("rewrite client hello extensions: %w", err)
	}

	// A cookie-only retry never reached the key_share branch above.
	if len(hrr.cookie) > 0 && newKeyShare == nil {
		out = appendExt(out, extCookie, hrr.cookie)
	}

	return assembleClientHello(hs.clientHelloMsg[:extStart], out)
}

// echGreaseForRetry rebuilds an outer encrypted_client_hello extension for the
// second ClientHello, which carries an empty enc. See buildECHGrease for the
// layout:
//
//	client_hello_type(1) kdf_id(2) aead_id(2) config_id(1)
//	enc_len(2) enc  payload_len(2) payload
func echGreaseForRetry(data []byte) ([]byte, error) {
	const headerLen = 1 + 2 + 2 + 1
	if len(data) < headerLen+2 {
		return nil, fmt.Errorf("encrypted_client_hello too short")
	}
	encLen := int(binary.BigEndian.Uint16(data[headerLen:]))
	rest := headerLen + 2 + encLen
	if rest+2 > len(data) {
		return nil, fmt.Errorf("encrypted_client_hello enc claims %d bytes, %d remain",
			encLen, len(data)-headerLen-2)
	}
	payloadLen := int(binary.BigEndian.Uint16(data[rest:]))
	if rest+2+payloadLen > len(data) {
		return nil, fmt.Errorf("encrypted_client_hello payload claims %d bytes, %d remain",
			payloadLen, len(data)-rest-2)
	}

	out := make([]byte, 0, headerLen+2+2+payloadLen)
	out = append(out, data[:headerLen]...) // type, kdf, aead, config_id
	out = appendUint16(out, 0)             // empty enc
	out = append(out, data[rest:rest+2+payloadLen]...)
	return out, nil
}

// messageHashMessage wraps a ClientHello1 digest as the synthetic handshake
// message §4.4.1 substitutes for the hello itself.
func messageHashMessage(sum []byte) []byte {
	msg := make([]byte, 4+len(sum))
	msg[0] = handshakeTypeMessageHash
	msg[1] = byte(len(sum) >> 16)
	msg[2] = byte(len(sum) >> 8)
	msg[3] = byte(len(sum))
	copy(msg[4:], sum)
	return msg
}

// clientHelloExtensionsStart returns the offset of the first extension byte in
// a ClientHello handshake message. The two bytes before it are the extension
// block length, so msg[:extStart] is everything that must be reproduced
// verbatim in a retry.
func clientHelloExtensionsStart(msg []byte) (int, error) {
	if len(msg) < 4 || msg[0] != handshakeTypeClientHello {
		return 0, fmt.Errorf("not a client hello")
	}
	bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if 4+bodyLen != len(msg) {
		return 0, fmt.Errorf("client hello claims %d bytes, %d available", bodyLen, len(msg)-4)
	}
	b := msg[4:]

	// legacy_version(2) + random(32)
	p := 2 + 32
	if p >= len(b) {
		return 0, fmt.Errorf("truncated client hello")
	}
	p += 1 + int(b[p]) // legacy_session_id
	if p+2 > len(b) {
		return 0, fmt.Errorf("truncated client hello at cipher_suites")
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:])) // cipher_suites
	if p >= len(b) {
		return 0, fmt.Errorf("truncated client hello at compression_methods")
	}
	p += 1 + int(b[p]) // legacy_compression_methods
	if p+2 > len(b) {
		return 0, fmt.Errorf("truncated client hello at extensions")
	}
	extsLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if p+extsLen != len(b) {
		return 0, fmt.Errorf("client hello extension block claims %d bytes, %d remain", extsLen, len(b)-p)
	}
	return 4 + p, nil
}

// assembleClientHello joins a verbatim prefix (everything up to and including
// the extension block length) with a new extension block, fixing both the
// block length and the handshake header length.
func assembleClientHello(prefix, exts []byte) ([]byte, error) {
	if len(prefix) < 6 {
		return nil, fmt.Errorf("client hello prefix too short")
	}
	if len(exts) > 0xFFFF {
		return nil, fmt.Errorf("client hello extensions are %d bytes, over the 65535 limit", len(exts))
	}

	msg := make([]byte, 0, len(prefix)+len(exts))
	msg = append(msg, prefix...)
	msg = append(msg, exts...)

	// Extension block length sits in the last two bytes of the prefix.
	binary.BigEndian.PutUint16(msg[len(prefix)-2:], uint16(len(exts)))

	bodyLen := len(msg) - 4
	if bodyLen > 0xFFFFFF {
		return nil, fmt.Errorf("client hello body is %d bytes, over the 16777215 limit", bodyLen)
	}
	msg[1] = byte(bodyLen >> 16)
	msg[2] = byte(bodyLen >> 8)
	msg[3] = byte(bodyLen)
	return msg, nil
}

// clientHelloSessionID returns the legacy_session_id a ClientHello carries.
//
// It is read back out of the sent message rather than stashed when the hello was
// built, for the same reason clientHelloGroups is: what matters is what actually
// went on the wire, and a value re-derived from the message can never drift from
// the builders. The retry path leaves the field untouched, so this answers for
// ClientHello1 and ClientHello2 alike.
func clientHelloSessionID(msg []byte) ([]byte, error) {
	if len(msg) < 4 || msg[0] != handshakeTypeClientHello {
		return nil, fmt.Errorf("not a client hello")
	}
	b := msg[4:]
	const p = 2 + 32 // legacy_version + random
	if p >= len(b) {
		return nil, fmt.Errorf("truncated client hello")
	}
	idLen := int(b[p])
	if p+1+idLen > len(b) {
		return nil, fmt.Errorf("client hello session id claims %d bytes, %d remain", idLen, len(b)-p-1)
	}
	return b[p+1 : p+1+idLen], nil
}

// clientHelloGroups returns the groups a ClientHello advertises in
// supported_groups and the groups it actually put key shares on the wire for.
func clientHelloGroups(msg []byte) (supported, offered []uint16, err error) {
	extStart, err := clientHelloExtensionsStart(msg)
	if err != nil {
		return nil, nil, err
	}
	err = forEachExtension(msg[extStart:], func(extType uint16, extData []byte) error {
		switch extType {
		case extSupportedGroups:
			if len(extData) < 2 {
				return fmt.Errorf("malformed supported_groups")
			}
			listLen := int(binary.BigEndian.Uint16(extData))
			if 2+listLen > len(extData) {
				return fmt.Errorf("supported_groups claims %d bytes, %d remain", listLen, len(extData)-2)
			}
			for i := 2; i+1 < 2+listLen; i += 2 {
				supported = append(supported, binary.BigEndian.Uint16(extData[i:]))
			}
		case extKeyShare:
			if len(extData) < 2 {
				return fmt.Errorf("malformed key_share")
			}
			for i := 2; i+4 <= len(extData); {
				group := binary.BigEndian.Uint16(extData[i:])
				n := int(binary.BigEndian.Uint16(extData[i+2:]))
				if i+4+n > len(extData) {
					return fmt.Errorf("key_share entry 0x%04x overruns", group)
				}
				offered = append(offered, group)
				i += 4 + n
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return supported, offered, nil
}

func containsUint16(haystack []uint16, needle uint16) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
