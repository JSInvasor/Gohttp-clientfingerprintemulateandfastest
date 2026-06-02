package gofire

// BrowserProfile identifies which browser fingerprint to emulate.
// Safari iOS 18 is the only supported profile.
type BrowserProfile int

const (
	// SafariIOS18 emulates Safari iOS 18.7 with full TLS/HTTP2/header fingerprint.
	SafariIOS18 BrowserProfile = iota
)

// String returns the browser profile name.
func (b BrowserProfile) String() string {
	return "Safari/18.7"
}

// Emulate creates a fully configured Client that emulates Safari iOS 18.
//
// Usage:
//
//	client, err := gofire.Emulate(gofire.SafariIOS18)
//	client, err := gofire.Emulate(gofire.SafariIOS18, gofire.WithProxy("socks5://..."))
func Emulate(profile BrowserProfile, opts ...Option) (*Client, error) {
	allOpts := make([]Option, 0, len(opts)+1)
	allOpts = append(allOpts, withBrowserProfile(profile))
	allOpts = append(allOpts, opts...)
	return NewClient(allOpts...)
}

// withBrowserProfile applies all settings for the Safari iOS 18 profile.
func withBrowserProfile(profile BrowserProfile) Option {
	return func(c *clientConfig) {
		c.browser = profile
		c.transport.DisableCompression = true
		c.acceptLanguage = "en-US,en;q=0.9"
		c.accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	}
}
