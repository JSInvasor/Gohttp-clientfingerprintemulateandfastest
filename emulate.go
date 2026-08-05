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
	// Chrome150 emulates Chrome 150 on Windows with full TLS/HTTP2/header
	// fingerprint (JA4 t13d1516h2_8daaf6152771_806a8c22fdea, Akamai H2
	// 52d84b1...), verified against a real Chrome 150 capture.
	//
	// This is desktop Chrome. For Chrome on an iPhone use SafariIOS18 with a
	// CriOS User-Agent override — iOS forces every browser onto Apple's TLS
	// stack, so Chrome-on-iOS emits the Safari fingerprint, not this one.
	Chrome150

	// Chrome147 and Chrome146 are backward-compatible aliases for Chrome150.
	// The cipher list, extension set, and HTTP/2 fingerprint are unchanged
	// across those releases; the signature algorithms, UA, and sec-ch-ua moved,
	// and callers get the current verified values under any of these names.
	Chrome147 = Chrome150
	Chrome146 = Chrome150
)

// String returns the browser profile name.
func (b BrowserProfile) String() string {
	switch b {
	case SafariIOS18:
		return "Safari/26.5.2"
	case Chrome150:
		return "Chrome/150.0"
	default:
		return "Unknown"
	}
}

// Emulate creates a fully configured Client that emulates the given browser.
//
// Usage:
//
//	client, err := gofire.Emulate(gofire.SafariIOS18)
//	client, err := gofire.Emulate(gofire.Chrome150)
//	client, err := gofire.Emulate(gofire.Chrome150, gofire.WithProxy("socks5://..."))
func Emulate(profile BrowserProfile, opts ...Option) (*Client, error) {
	switch profile {
	case SafariIOS18, Chrome150:
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

		// Both constants live in headers.go so acceptFor can recognise them as
		// profile defaults and swap them for */* on a fetch/XHR. Inlining the
		// strings here is what let the Chrome default drift out of that set.
		switch profile {
		case Chrome150:
			c.acceptLanguage = "en-US,en;q=0.9"
			c.accept = chromeNavigateAccept
		default:
			c.acceptLanguage = "en-US,en;q=0.9"
			c.accept = defaultNavigateAccept
		}
	}
}
