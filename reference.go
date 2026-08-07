package gofire

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/ctls"
)

// Reference is the complete fingerprint a profile is supposed to produce,
// across all three layers a bot-detection stack reads: TLS, HTTP/2 and the
// request headers.
//
// It exists so "does this client still look like the browser it claims to be"
// is a value that can be compared against a live capture, not a claim in a
// comment. cmd/fpcheck fetches a fingerprint API with each profile and diffs
// the response against this; the TLS half is additionally checked offline by
// internal/ctls's tests, which parse the ClientHello bytes the builders emit.
//
// Every field was captured from a real device; Reference.Device says which.
type Reference struct {
	// Profile is the browser this describes.
	Profile BrowserProfile

	// Device is what the reference values were captured from.
	Device string

	// UserAgent is the profile's default User-Agent.
	UserAgent string

	// JA3, JA3Hash are empty for Chrome by design — see ctls.TLSReference.
	JA3     string
	JA3Hash string

	// JA4 is stable for both profiles: it sorts before hashing.
	JA4 string

	// AkamaiFingerprint is the HTTP/2 fingerprint:
	//
	//	SETTINGS (id:value, in send order) | WINDOW_UPDATE | PRIORITY frames | pseudo-header order
	//
	// AkamaiHash is its MD5, which is what most tools display.
	AkamaiFingerprint string
	AkamaiHash        string

	// HeadersPriority reports whether HEADERS frames carry an RFC 7540
	// priority block. False for Safari, which advertises
	// SETTINGS_NO_RFC7540_PRIORITIES=1 and therefore must not send one.
	HeadersPriority bool

	// HeaderOrder is the order of the regular (non-pseudo) headers, listing
	// only those the profile always sends on a top-level navigation. Optional
	// headers that depend on the request (cookie, referer, content-type) are
	// left out so the list can be checked against any capture.
	HeaderOrder []string

	// PseudoHeaderOrder is the order of the HTTP/2 pseudo-headers.
	PseudoHeaderOrder []string
}

// ReferenceFor returns the expected fingerprint for a browser profile.
func ReferenceFor(profile BrowserProfile) Reference {
	if profile == Chrome150 {
		tls := ctls.ChromeReference
		h2 := Chrome146H2Profile()
		return Reference{
			Profile:           Chrome150,
			Device:            tls.Device,
			UserAgent:         Chrome150UserAgent,
			JA3:               tls.JA3,
			JA3Hash:           tls.JA3Hash,
			JA4:               tls.JA4,
			AkamaiFingerprint: AkamaiFingerprint(h2),
			AkamaiHash:        akamaiHash(AkamaiFingerprint(h2)),
			HeadersPriority:   h2.PrioritySignals,
			HeaderOrder: []string{
				"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
				"upgrade-insecure-requests", "user-agent", "accept",
				"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
				"sec-fetch-dest", "accept-encoding", "accept-language",
				"priority",
			},
			PseudoHeaderOrder: h2.PseudoHeaders,
		}
	}

	tls := ctls.SafariReference
	h2 := SafariIOS18H2Profile()
	return Reference{
		Profile:           SafariIOS18,
		Device:            tls.Device,
		UserAgent:         SafariIOS18UserAgent,
		JA3:               tls.JA3,
		JA3Hash:           tls.JA3Hash,
		JA4:               tls.JA4,
		AkamaiFingerprint: AkamaiFingerprint(h2),
		AkamaiHash:        akamaiHash(AkamaiFingerprint(h2)),
		HeadersPriority:   h2.PrioritySignals,
		HeaderOrder: []string{
			"sec-fetch-dest", "user-agent", "accept",
			"sec-fetch-site", "sec-fetch-mode", "accept-language",
			"priority", "accept-encoding",
		},
		PseudoHeaderOrder: h2.PseudoHeaders,
	}
}

// AkamaiFingerprint renders the Akamai HTTP/2 fingerprint string for a profile,
// derived from the same values the transport is configured with rather than
// restated as a literal — so it cannot drift away from what goes on the wire.
func AkamaiFingerprint(p H2Profile) string {
	parts := make([]string, 0, 7)
	for _, s := range buildH2Settings(p.Settings) {
		parts = append(parts, strconv.Itoa(int(s.ID))+":"+strconv.FormatUint(uint64(s.Val), 10))
	}

	pseudo := make([]string, 0, len(p.PseudoHeaders))
	for _, ph := range p.PseudoHeaders {
		pseudo = append(pseudo, strings.TrimPrefix(ph, ":")[:1])
	}

	// The PRIORITY-frame field is always "0": neither profile sends standalone
	// PRIORITY frames. Chrome carries its priority on the HEADERS frame and
	// Safari sends none at all.
	return strings.Join(parts, ";") + "|" +
		strconv.FormatUint(uint64(p.Settings.ConnectionWindowSize), 10) +
		"|0|" + strings.Join(pseudo, ",")
}

func akamaiHash(fp string) string {
	sum := md5.Sum([]byte(fp))
	return hex.EncodeToString(sum[:])
}
