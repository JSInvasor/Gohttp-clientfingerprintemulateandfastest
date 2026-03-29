package gofire

import (
	"fmt"
)

// BrowserProfile defines a browser to emulate.
type BrowserProfile int

const (
	// Firefox148 emulates Firefox 148 with full TLS/HTTP2/header fingerprint.
	Firefox148 BrowserProfile = iota
	// Chrome146 emulates Chrome 146 with full TLS/HTTP2/header fingerprint.
	Chrome146
	// SafariIOS18 emulates Safari iOS 18.7 with full TLS/HTTP2/header fingerprint.
	SafariIOS18
)

// String returns the browser profile name.
func (b BrowserProfile) String() string {
	switch b {
	case Firefox148:
		return "Firefox/148.0"
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
	case Firefox148, Chrome146, SafariIOS18:
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
		case Firefox148:
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
