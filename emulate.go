package gofire

import (
	"fmt"
)

// BrowserProfile identifies which browser fingerprint to emulate.
type BrowserProfile int

const (
	// SafariIOS18 emulates Safari iOS 18.7 with full TLS/HTTP2/header fingerprint.
	SafariIOS18 BrowserProfile = iota
	// Chrome147 emulates Chrome 147 with full TLS/HTTP2/header fingerprint.
	// The TLS layer (ciphers, per-connection extension shuffle, JA4
	// t13d1517h2_8daaf6152771_b6f405a00624, Akamai H2 52d84b1...) matches
	// Chrome 146; only the UA and sec-ch-ua brand list differ.
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
