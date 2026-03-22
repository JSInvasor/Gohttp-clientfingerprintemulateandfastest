package gofire

// Firefox148 TLS fingerprint identifiers (for documentation and verification).
// Verified against real Firefox 148 via tls.peet.ws on 2026-03-22.
//
// JA3 (initial connection, no PSK):
//   771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0
// JA3 Hash: 6f7889b9fb1a62a9577e685c1fcfa919
//
// JA4: t13d1717h2_5b57614c22b0_3cbfd9057e0d
//
// NOTE: On session resumption (with PSK), extension 35 is replaced by extension 41,
// producing different hashes: JA3=0e76c7e9d06fa0e211b1827687dd8f43, JA4=t13d1717h2_5b57614c22b0_e6dcd7ae0a9e.
// This library does not implement session resumption, so it always uses initial connection fingerprint.
//
// The actual TLS ClientHello is built byte-by-byte in internal/ctls/hello.go
// using Go's standard crypto packages (no uTLS dependency).

// H2Settings defines HTTP/2 connection settings for Firefox 148 fingerprinting.
type H2Settings struct {
	HeaderTableSize      uint32
	EnablePush           uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	ConnectionWindowSize uint32
}

// Firefox148H2Settings returns the exact HTTP/2 SETTINGS from Firefox 148.
//
// Akamai fingerprint: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
// Akamai hash: 6ea73faa8fc5aac76bded7bd238f6433
func Firefox148H2Settings() H2Settings {
	return H2Settings{
		HeaderTableSize:      65536,    // SETTINGS_HEADER_TABLE_SIZE
		EnablePush:           0,        // SETTINGS_ENABLE_PUSH (disabled)
		InitialWindowSize:    131072,   // SETTINGS_INITIAL_WINDOW_SIZE (128KB)
		MaxFrameSize:         16384,    // SETTINGS_MAX_FRAME_SIZE (16KB)
		ConnectionWindowSize: 12517377, // WINDOW_UPDATE increment
	}
}

// Firefox148PseudoHeaderOrder returns the HTTP/2 pseudo-header order.
// Akamai fingerprint suffix: m,p,a,s
func Firefox148PseudoHeaderOrder() []string {
	return []string{":method", ":path", ":authority", ":scheme"}
}

// Firefox148PriorityWeight returns the PRIORITY frame weight (0-indexed).
// Firefox 148 sends PRIORITY flag (0x20) with weight=42, depends_on=0, exclusive=0.
func Firefox148PriorityWeight() uint8 {
	return 42
}
