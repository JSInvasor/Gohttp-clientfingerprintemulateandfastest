package gofire

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"

	http2 "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/http2"
)

// Reference Akamai HTTP/2 fingerprints, captured alongside the TLS references
// pinned in internal/ctls: a real iPhone 13 on iOS 26.5.2 and a real Chrome 151
// on Windows.
//
// Format (Akamai's "HTTP/2 fingerprint"):
//
//	SETTINGS (id:value, semicolon-separated, in send order)
//	| connection-level WINDOW_UPDATE increment
//	| PRIORITY frames (0 when none are sent)
//	| pseudo-header order, first letter of each
const (
	safariAkamaiFP   = "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p"
	safariAkamaiHash = "c52879e43202aeb92740be6e8c86ea96"
	chromeAkamaiFP   = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	chromeAkamaiHash = "52d84b11737d980aef856699f885ca86"
)

func TestAkamaiFingerprints(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile H2Profile
		fp      string
		hash    string
	}{
		{"safari", SafariIOS18H2Profile(), safariAkamaiFP, safariAkamaiHash},
		{"chrome", Chrome146H2Profile(), chromeAkamaiFP, chromeAkamaiHash},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AkamaiFingerprint(tc.profile)
			if got != tc.fp {
				t.Errorf("akamai fingerprint mismatch\n got: %s\nwant: %s", got, tc.fp)
			}
			sum := md5.Sum([]byte(got))
			if h := hex.EncodeToString(sum[:]); h != tc.hash {
				t.Errorf("akamai hash = %s, want %s", h, tc.hash)
			}
		})
	}
}

// TestSafariSendsNoHeadersPriority pins the wire bytes of a Safari HEADERS
// frame.
//
// Safari advertises SETTINGS_NO_RFC7540_PRIORITIES=1 (the "9:1" above), which
// per RFC 9218 §2.1 means it does not use the RFC 7540 priority scheme; its
// HEADERS frames therefore carry no priority block and stream priority travels
// in the `priority` request header. A revision that set PriorityWeight for
// Safari made the framer append 00 00 00 00 ff to every HEADERS frame and set
// FlagHeadersPriority — a client announcing it does not speak RFC 7540
// priorities and then speaking them on every request, which is a shape no
// shipping browser produces and which any HTTP/2 fingerprinter records in its
// sent_frames list.
func TestSafariSendsNoHeadersPriority(t *testing.T) {
	flags, payload := writeHeadersFrame(t, headerPriorityFor(SafariIOS18H2Profile()))

	if flags&http2.FlagHeadersPriority != 0 {
		t.Error("Safari HEADERS frame sets the PRIORITY flag; a client sending " +
			"SETTINGS_NO_RFC7540_PRIORITIES=1 must not carry an RFC 7540 priority block")
	}
	if want := []byte("hpack"); !bytes.Equal(payload, want) {
		t.Errorf("Safari HEADERS payload = % x, want just the header block % x "+
			"(a 5-byte priority prefix means the block is still being emitted)", payload, want)
	}
}

// TestChromeSendsHeadersPriority is the other half: Chrome does not send
// NO_RFC7540_PRIORITIES, so it does attach the priority block, and the values
// are exclusive=1, depends_on=0, weight=256 (encoded as 255).
func TestChromeSendsHeadersPriority(t *testing.T) {
	flags, payload := writeHeadersFrame(t, headerPriorityFor(Chrome146H2Profile()))

	if flags&http2.FlagHeadersPriority == 0 {
		t.Fatal("Chrome HEADERS frame does not set the PRIORITY flag")
	}
	if len(payload) < 5 {
		t.Fatalf("payload is %d bytes, too short for a priority block", len(payload))
	}
	// exclusive bit set, stream dependency 0 => 0x80000000.
	if want := []byte{0x80, 0x00, 0x00, 0x00, 0xff}; !bytes.Equal(payload[:5], want) {
		t.Errorf("priority block = % x, want % x (exclusive=1, depends_on=0, weight=256)",
			payload[:5], want)
	}
}

// writeHeadersFrame serialises one HEADERS frame with the given priority and
// returns its flags byte and payload, so the assertions above read the same
// bytes the peer would.
func writeHeadersFrame(t *testing.T, prio http2.PriorityParam) (flags http2.Flags, payload []byte) {
	t.Helper()

	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, &buf)
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: []byte("hpack"),
		EndStream:     true,
		EndHeaders:    true,
		Priority:      prio,
	}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	raw := buf.Bytes()
	const frameHeaderLen = 9
	if len(raw) < frameHeaderLen {
		t.Fatalf("frame is %d bytes, shorter than a frame header", len(raw))
	}
	length := int(raw[0])<<16 | int(raw[1])<<8 | int(raw[2])
	if got := len(raw) - frameHeaderLen; got != length {
		t.Fatalf("frame length header says %d, payload is %d bytes", length, got)
	}
	return http2.Flags(raw[4]), raw[frameHeaderLen:]
}

// TestH2SettingsOrder pins the order and identity of the SETTINGS entries, so a
// failure localises to the settings rather than showing only a moved hash.
func TestH2SettingsOrder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile H2Profile
		want    []string
	}{
		{"safari", SafariIOS18H2Profile(), []string{"2:0", "3:100", "4:2097152", "9:1"}},
		{"chrome", Chrome146H2Profile(), []string{"1:65536", "2:0", "4:6291456", "6:262144"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := buildH2Settings(tc.profile.Settings)
			got := make([]string, len(settings))
			for i, s := range settings {
				got[i] = fmt.Sprintf("%d:%d", s.ID, s.Val)
			}
			if strings.Join(got, ";") != strings.Join(tc.want, ";") {
				t.Errorf("SETTINGS\n got: %v\nwant: %v", got, tc.want)
			}
		})
	}
}

// A browser profile always sends Accept and Accept-Language.
//
// Both were built with setIfEmpty, which reads "" as "nothing to set", so an
// empty configured value dropped the header from the request entirely rather
// than falling back. A request from a profile that claims to be Chrome or Safari
// and carries neither header is a stronger signal than any wrong value would be,
// and WithAccept("")/WithAcceptLanguage("") is an easy accident for a caller
// computing the value — the config defaults are non-empty, so only an explicit
// empty string gets here.
//
// The User-Agent already worked this way through resolveUserAgent; this is the
// same rule applied to the other two.
func TestEmptyAcceptAndLanguageFallBackToTheProfileDefaults(t *testing.T) {
	for _, profile := range []BrowserProfile{Chrome151, SafariIOS18} {
		req, err := http.NewRequest("GET", "https://site.test/", nil)
		if err != nil {
			t.Fatal(err)
		}
		applyBrowserHeaders(req, profile, "", "", "")

		if got := req.Header.Get("Accept-Language"); got != DefaultAcceptLanguage {
			t.Errorf("%v: Accept-Language = %q, want the default %q",
				profile, got, DefaultAcceptLanguage)
		}
		if got := req.Header.Get("Accept"); got == "" {
			t.Errorf("%v: Accept was dropped from the request", profile)
		}
		if got := req.Header.Get("User-Agent"); got == "" {
			t.Errorf("%v: User-Agent was dropped from the request", profile)
		}
	}
}

// A value the caller did give still wins, so the fallback cannot mask a real
// setting.
func TestConfiguredAcceptAndLanguageAreNotOverridden(t *testing.T) {
	req, err := http.NewRequest("GET", "https://site.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	applyBrowserHeaders(req, Chrome151, "text/plain", "tr-TR,tr;q=0.9", "")

	if got := req.Header.Get("Accept-Language"); got != "tr-TR,tr;q=0.9" {
		t.Errorf("Accept-Language = %q, want the configured value", got)
	}
	if got := req.Header.Get("Accept"); got != "text/plain" {
		t.Errorf("Accept = %q, want the configured value", got)
	}
}
