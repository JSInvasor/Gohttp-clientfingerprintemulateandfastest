package gofire

import (
	"fmt"
)

// BrowserProfile defines a browser to emulate.
type BrowserProfile int

const (
	// Firefox148 emulates Firefox 148 with full TLS/HTTP2/header fingerprint.
	Firefox148 BrowserProfile = iota
)

// String returns the browser profile name.
func (b BrowserProfile) String() string {
	switch b {
	case Firefox148:
		return "Firefox/148.0"
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
//	client, err := gofire.Emulate(gofire.Firefox148, gofire.WithProxy("socks5://..."))
func Emulate(profile BrowserProfile, opts ...Option) (*Client, error) {
	switch profile {
	case Firefox148:
		// Prepend the browser profile option so user opts can override
		allOpts := make([]Option, 0, len(opts)+1)
		allOpts = append(allOpts, withBrowserProfile(Firefox148))
		allOpts = append(allOpts, opts...)
		return NewClient(allOpts...)
	default:
		return nil, fmt.Errorf("unsupported browser profile: %d", profile)
	}
}

// withBrowserProfile applies all settings for a specific browser profile.
func withBrowserProfile(profile BrowserProfile) Option {
	return func(c *clientConfig) {
		switch profile {
		case Firefox148:
			c.browser = profile
			c.acceptLanguage = "en-US,en;q=0.5"
			c.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
			c.transport.DisableCompression = true
		}
	}
}
