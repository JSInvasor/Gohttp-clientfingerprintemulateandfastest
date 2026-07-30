package gofire

import (
	"fmt"
)

// BrowserProfile identifies which browser fingerprint to emulate.
type BrowserProfile int

const (
	// SafariIOS18 emulates Safari on iPhone with full TLS/HTTP2/header
	// fingerprint (JA4 t13d2013h2_a09f3c656075_7f0f34a4126d, Akamai H2
	// c52879e4...), verified against a real iPhone 13 on iOS 26.5.2.
	//
	// The name is kept for API compatibility and still matches the frozen
	// "iPhone OS 18_7" token in Safari's User-Agent; see SafariIOS18UserAgent.
	// Every browser on iOS produces this same TLS fingerprint.
	SafariIOS18 BrowserProfile = iota
	// Chrome147 emulates Chrome 147 on Windows with full TLS/HTTP2/header
	// fingerprint. The TLS layer (ciphers, per-connection extension shuffle,
	// JA4 t13d1516h2_8daaf6152771_d8a2da3f94cd, Akamai H2 52d84b1...) matches
	// Chrome 146; only the UA and sec-ch-ua brand list differ.
	//
	// This is desktop Chrome. For Chrome on an iPhone use SafariIOS18 with a
	// CriOS User-Agent override — iOS forces every browser onto Apple's TLS
	// stack, so Chrome-on-iOS emits the Safari fingerprint, not this one.
	Chrome147

	// Chrome146 is a backward-compatible alias for Chrome147: the TLS layer is
	// unchanged between the two releases, only UA + sec-ch-ua moved.
	Chrome146 = Chrome147
)

// String returns the browser profile name.
func (b BrowserProfile) String() string {
	switch b {
	case SafariIOS18:
		return "Safari/18.7"
	case Chrome147:
		return "Chrome/147.0"
	default:
		return "Unknown"
	}
}

// Emulate creates a fully configured Client that emulates the given browser.
//
// Usage:
//
//	client, err := gofire.Emulate(gofire.SafariIOS18)
//	client, err := gofire.Emulate(gofire.Chrome147)
//	client, err := gofire.Emulate(gofire.Chrome147, gofire.WithProxy("socks5://..."))
func Emulate(profile BrowserProfile, opts ...Option) (*Client, error) {
	switch profile {
	case SafariIOS18, Chrome147:
		allOpts := make([]Option, 0, len(opts)+1)
		allOpts = append(allOpts, withBrowserProfile(profile))
		allOpts = append(allOpts, opts...)
		return NewClient(allOpts...)
	default:
		return nil, fmt.Errorf("unsupported browser profile: %d", profile)
	}
}

// withBrowserProfile applies all settings for a specific browser profile.
func withBrowserProfile(profile BrowserProfile) Option {
	return func(c *clientConfig) {
		c.browser = profile
		c.transport.DisableCompression = true

		switch profile {
		case Chrome147:
			c.acceptLanguage = "en-US,en;q=0.9"
			c.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
		default:
			c.acceptLanguage = "en-US,en;q=0.9"
			c.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		}
	}
}
