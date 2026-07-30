package gofire

import (
	http2 "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/http2"
)

// H2Settings defines HTTP/2 connection settings for browser fingerprinting.
type H2Settings struct {
	HeaderTableSize      uint32
	EnablePush           uint32
	MaxConcurrentStreams uint32 // 0 = not sent (Safari sends 100, Chrome doesn't)
	InitialWindowSize    uint32
	MaxFrameSize         uint32 // 0 = not sent (neither Safari nor Chrome send it)
	MaxHeaderListSize    uint32 // 0 = not sent (Chrome sends 262144, Safari doesn't)
	NoRFC7540Priorities  uint32 // 0 = not sent (Safari sends 1, Chrome doesn't)
	ConnectionWindowSize uint32
}

// H2Profile holds the complete HTTP/2 fingerprint.
type H2Profile struct {
	Settings          H2Settings
	PseudoHeaders     []string
	PriorityWeight    uint8
	PriorityExclusive bool
}

// ========== Safari iOS 18 ==========
//
// Safari HTTP/2 fingerprint. Verified against a real iPhone 13 / iOS 26.5.2.
//
// Akamai HTTP/2 fingerprint: 2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p
// Akamai hash: c52879e43202aeb92740be6e8c86ea96

func SafariIOS18H2Settings() H2Settings {
	return H2Settings{
		EnablePush:           0,
		MaxConcurrentStreams: 100,
		InitialWindowSize:    2097152,
		NoRFC7540Priorities:  1,
		ConnectionWindowSize: 10420225,
	}
}

func SafariIOS18PseudoHeaderOrder() []string {
	return []string{":method", ":scheme", ":authority", ":path"}
}

func SafariIOS18H2Profile() H2Profile {
	return H2Profile{
		Settings:      SafariIOS18H2Settings(),
		PseudoHeaders: SafariIOS18PseudoHeaderOrder(),
		// No HEADERS priority. Safari advertises NO_RFC7540_PRIORITIES=1 and
		// then uses the RFC 9218 "priority: u=0, i" header field instead, so
		// emitting RFC 7540 stream dependency and weight would contradict the
		// setting in the same connection — a combination no real client sends.
		//
		// Verified against an iPhone 13 / Safari 26.5.2 capture: its HEADERS
		// frame carries EndStream and EndHeaders only, with no Priority flag.
		// A non-zero weight here sets that flag (PriorityParam.IsZero drives it),
		// which is what an earlier revision did.
		PriorityWeight:    0,
		PriorityExclusive: false,
	}
}

// ========== Chrome ==========
//
// Chrome HTTP/2 fingerprint. Verified byte-for-byte against a real Chrome 150
// capture (SETTINGS order, WINDOW_UPDATE increment, pseudo-header order, and
// the HEADERS priority flag: weight 256, depends_on 0, exclusive).
//
// Akamai HTTP/2 fingerprint: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
// Akamai hash: 52d84b11737d980aef856699f885ca86
//
// The Chrome146* function names are retained for API compatibility; the HTTP/2
// layer is unchanged from Chrome 146 through 150.

func Chrome146H2Settings() H2Settings {
	return H2Settings{
		HeaderTableSize:      65536,
		EnablePush:           0,
		InitialWindowSize:    6291456,
		MaxHeaderListSize:    262144,
		ConnectionWindowSize: 15663105,
	}
}

func Chrome146PseudoHeaderOrder() []string {
	return []string{":method", ":authority", ":scheme", ":path"}
}

func Chrome146H2Profile() H2Profile {
	return H2Profile{
		Settings:          Chrome146H2Settings(),
		PseudoHeaders:     Chrome146PseudoHeaderOrder(),
		PriorityWeight:    255, // weight 256 is encoded as 255
		PriorityExclusive: true,
	}
}

// buildH2Settings converts H2Settings into the ordered []http2.Setting slice.
// The order matches what each browser sends (critical for Akamai fingerprinting).
func buildH2Settings(s H2Settings) []http2.Setting {
	var settings []http2.Setting

	if s.HeaderTableSize > 0 {
		settings = append(settings, http2.Setting{ID: http2.SettingHeaderTableSize, Val: s.HeaderTableSize})
	}
	settings = append(settings, http2.Setting{ID: http2.SettingEnablePush, Val: s.EnablePush})
	if s.MaxConcurrentStreams > 0 {
		settings = append(settings, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: s.MaxConcurrentStreams})
	}
	settings = append(settings, http2.Setting{ID: http2.SettingInitialWindowSize, Val: s.InitialWindowSize})
	if s.MaxFrameSize > 0 {
		settings = append(settings, http2.Setting{ID: http2.SettingMaxFrameSize, Val: s.MaxFrameSize})
	}
	if s.MaxHeaderListSize > 0 {
		settings = append(settings, http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: s.MaxHeaderListSize})
	}
	if s.NoRFC7540Priorities > 0 {
		settings = append(settings, http2.Setting{ID: http2.SettingNoRFC7540Priorities, Val: s.NoRFC7540Priorities})
	}
	return settings
}
