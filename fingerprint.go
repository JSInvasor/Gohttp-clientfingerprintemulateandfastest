package gofire

import (
	http2 "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/http2"
)

// H2Settings defines HTTP/2 connection settings for browser fingerprinting.
type H2Settings struct {
	HeaderTableSize      uint32
	EnablePush           uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32 // 0 = not sent (Chrome omits this)
	MaxHeaderListSize    uint32 // 0 = not sent (Firefox omits this)
	ConnectionWindowSize uint32
}

// H2Profile holds the complete HTTP/2 fingerprint for a browser.
type H2Profile struct {
	Settings         H2Settings
	PseudoHeaders    []string
	PriorityWeight   uint8
	PriorityExclusive bool
}

// ========== Firefox 148 ==========

// Firefox148 TLS fingerprint identifiers (verified via tls.peet.ws on 2026-03-22).
//
// JA3 Hash: 6f7889b9fb1a62a9577e685c1fcfa919
// JA4: t13d1717h2_5b57614c22b0_3cbfd9057e0d
//
// Akamai HTTP/2 fingerprint: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
// Akamai hash: 6ea73faa8fc5aac76bded7bd238f6433

func Firefox148H2Settings() H2Settings {
	return H2Settings{
		HeaderTableSize:      65536,
		EnablePush:           0,
		InitialWindowSize:    131072,
		MaxFrameSize:         16384,
		ConnectionWindowSize: 12517377,
	}
}

func Firefox148PseudoHeaderOrder() []string {
	return []string{":method", ":path", ":authority", ":scheme"}
}

func Firefox148PriorityWeight() uint8 { return 42 }

func Firefox148H2Profile() H2Profile {
	return H2Profile{
		Settings:         Firefox148H2Settings(),
		PseudoHeaders:    Firefox148PseudoHeaderOrder(),
		PriorityWeight:   42,
		PriorityExclusive: false,
	}
}

// ========== Chrome 146 ==========

// Chrome146 TLS fingerprint identifiers (verified via tls.peet.ws on 2026-03-28).
//
// JA3 Hash: 9271bc66017f8920fe4549ad9e47e63b
// JA4: t13d1517h2_8daaf6152771_b6f405a00624
//
// Akamai HTTP/2 fingerprint: 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
// Akamai hash: 52d84b11737d980aef856699f885ca86

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

func Chrome146PriorityWeight() uint8 { return 255 } // weight 256 is encoded as 255 (0-indexed)

func Chrome146H2Profile() H2Profile {
	return H2Profile{
		Settings:         Chrome146H2Settings(),
		PseudoHeaders:    Chrome146PseudoHeaderOrder(),
		PriorityWeight:   255,
		PriorityExclusive: true,
	}
}

// buildH2Settings converts H2Settings into the ordered []http2.Setting slice.
func buildH2Settings(s H2Settings) []http2.Setting {
	var settings []http2.Setting
	settings = append(settings, http2.Setting{ID: http2.SettingHeaderTableSize, Val: s.HeaderTableSize})
	settings = append(settings, http2.Setting{ID: http2.SettingEnablePush, Val: s.EnablePush})
	settings = append(settings, http2.Setting{ID: http2.SettingInitialWindowSize, Val: s.InitialWindowSize})
	if s.MaxFrameSize > 0 {
		settings = append(settings, http2.Setting{ID: http2.SettingMaxFrameSize, Val: s.MaxFrameSize})
	}
	if s.MaxHeaderListSize > 0 {
		settings = append(settings, http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: s.MaxHeaderListSize})
	}
	return settings
}
