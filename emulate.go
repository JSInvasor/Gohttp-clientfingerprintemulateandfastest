package gofire

import (
	"fmt"
)

// BrowserProfile defines a browser to emulate.
type BrowserProfile int

const (
	// Firefox151 emulates Firefox 151 with full TLS/HTTP2/header fingerprint.
	// The TLS profile (16-suite cipher order, supported_groups including
	// P-521 + ffdhe, delegated_credentials, record_size_limit,
	// compress_certificate variants) matches Firefox 151 as captured from
	// tls.peet.ws. Cold-connection JA4 is t13d1617h2_86a278354501_...
	// (resumed sessions swap session_ticket for pre_shared_key).
	Firefox151 BrowserProfile = iota
	// Chrome148 emulates Chrome 148 with full TLS/HTTP2/header fingerprint.
	// TLS layer (ciphers, extensions, Akamai H2 52d84b1...) is shared with
	// Chrome 146/147; only UA and sec-ch-ua brand list differ. Cold-connection
	// JA4 is t13d1516h2_8daaf6152771_... (resumed sessions add pre_shared_key
	// for t13d1517h2).
	Chrome148
	// SafariIOS18 emulates Safari iOS 18.7 with full TLS/HTTP2/header fingerprint.
	SafariIOS18

	// Firefox148 / Firefox150 are backward-compatible aliases for Firefox151.
	// The underlying TLS/H2 fingerprint is shared across those releases; only
	// the User-Agent string changed. New code should use Firefox151.
	Firefox150 = Firefox151
	Firefox148 = Firefox151
	// Chrome146 / Chrome147 are backward-compatible aliases for Chrome148. Same
	// reason as Firefox148: TLS layer is unchanged, only UA + sec-ch-ua moved.
	// New code should use Chrome148.
	Chrome146 = Chrome148
	Chrome147 = Chrome148
)

// String returns the browser profile name.
func (b BrowserProfile) String() string {
	switch b {
	case Firefox151:
		return "Firefox/151.0"
	case Chrome148:
		return "Chrome/148.0"
	case SafariIOS18:
		return "Safari/18.7"
	default:
		return "Unknown"
	}
}

// Emulate creates a fully configured Client that emulates the given browser profile.
// This is the recommended way to create a client.
//
// Usage:
//
//	client, err := gofire.Emulate(gofire.Firefox151)
//	client, err := gofire.Emulate(gofire.Chrome148)
//	client, err := gofire.Emulate(gofire.Chrome148, gofire.WithProxy("socks5://..."))
func Emulate(profile BrowserProfile, opts ...Option) (*Client, error) {
	switch profile {
	case Firefox151, Chrome148, SafariIOS18:
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
		case Firefox151:
			c.acceptLanguage = "en-US,en;q=0.5"
			c.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		case Chrome148:
			c.acceptLanguage = "en-US,en;q=0.9"
			c.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
		case SafariIOS18:
			c.acceptLanguage = "en-US,en;q=0.9"
			c.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		}
	}
}
