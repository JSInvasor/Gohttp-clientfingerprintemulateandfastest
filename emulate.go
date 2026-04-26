package gofire

import (
	"fmt"
)

// BrowserProfile defines a browser to emulate.
type BrowserProfile int

const (
	// Firefox150 emulates Firefox 150 with full TLS/HTTP2/header fingerprint.
	// The TLS profile (cipher order, supported_groups including P-521 + ffdhe,
	// delegated_credentials, record_size_limit, compress_certificate variants)
	// matches Firefox 150 as captured from tls.peet.ws.
	Firefox150 BrowserProfile = iota
	// Chrome146 emulates Chrome 146 with full TLS/HTTP2/header fingerprint.
	Chrome146
	// SafariIOS18 emulates Safari iOS 18.7 with full TLS/HTTP2/header fingerprint.
	SafariIOS18

	// Firefox148 is a backward-compatible alias for Firefox150. The previous
	// Firefox 148 fingerprint was bumped to 150 because the underlying TLS
	// extensions and ClientHello layout already matched the newer release;
	// only the User-Agent string changed. New code should use Firefox150.
	Firefox148 = Firefox150
)

// String returns the browser profile name.
func (b BrowserProfile) String() string {
	switch b {
	case Firefox150:
		return "Firefox/150.0"
	case Chrome146:
		return "Chrome/146.0"
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
//	client, err := gofire.Emulate(gofire.Firefox148)
//	client, err := gofire.Emulate(gofire.Chrome146)
//	client, err := gofire.Emulate(gofire.Chrome146, gofire.WithProxy("socks5://..."))
func Emulate(profile BrowserProfile, opts ...Option) (*Client, error) {
	switch profile {
	case Firefox150, Chrome146, SafariIOS18:
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
		case Firefox150:
			c.acceptLanguage = "en-US,en;q=0.5"
			c.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		case Chrome146:
			c.acceptLanguage = "en-US,en;q=0.9"
			c.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
		case SafariIOS18:
			c.acceptLanguage = "tr-TR,tr;q=0.9"
			c.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		}
	}
}
