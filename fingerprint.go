package gofire

import (
	http2 "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/http2"
)

// H2Settings defines HTTP/2 connection settings for Safari iOS 18 fingerprinting.
type H2Settings struct {
	HeaderTableSize      uint32
	EnablePush           uint32
	MaxConcurrentStreams uint32 // 0 = not sent (Safari sends 100)
	InitialWindowSize    uint32
	MaxFrameSize         uint32 // 0 = not sent (Safari does not send)
	MaxHeaderListSize    uint32 // 0 = not sent (Safari does not send)
	NoRFC7540Priorities  uint32 // 0 = not sent (Safari sends 1)
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
// Safari iOS 18.7 HTTP/2 fingerprint.
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
		Settings:          SafariIOS18H2Settings(),
		PseudoHeaders:     SafariIOS18PseudoHeaderOrder(),
		PriorityWeight:    255, // weight 256 is encoded as 255
		PriorityExclusive: false,
	}
}

// buildH2Settings converts H2Settings into the ordered []http2.Setting slice.
// The order matches what Safari iOS 18 sends (critical for Akamai fingerprinting).
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
