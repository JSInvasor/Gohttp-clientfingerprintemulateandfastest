package quic

// The HTTP/3 half of the profile: what Chrome puts on its control stream, and
// in what order.
//
// This is the layer the Initial datagram cannot reach. SETTINGS travels in
// 1-RTT packets, so recovering it from a capture needs the traffic keys;
// reading it out of Chrome's own net-log is possible but is the browser's
// account of itself rather than the wire. The values here come from a third
// source that is better than either: a server that reports what it received.
//
// Recorded from https://quic.browserleaks.com/, 2026-08-21, Chrome
// 151.0.7922.77 on Windows 10. That capture also recomputed the QUIC JA4
// independently and produced q13d0313h3_55b375c5d22e_226f3f127bbe — byte for
// byte what Chrome151QUICResumed pins and what this package's own decoder
// derives from the raw Initial bytes under testdata. Three separate paths to
// the same string is the strongest evidence in this package.
//
// One caveat is recorded rather than smoothed over: unlike the values in
// reference.go, these are not re-derived from bytes committed to this
// repository, because the report is text rather than a capture. They are
// evidence, but of a weaker kind, and they stay that way until cmd/fpcheck can
// fetch an h3 endpoint and diff against them.

// HTTP3Reference is the HTTP/3 layer of a browser profile.
type HTTP3Reference struct {
	// Device and Source say what produced these values and who observed them.
	Device string
	Source string

	// Settings are the SETTINGS frame's entries in send order. Order matters
	// here in a way it does not for the transport parameters: this one does not
	// move between connections.
	Settings []Setting

	// GreaseSetting records that a reserved setting rides along with a random
	// id and a random value. Neither is pinned — only that there is exactly one
	// and that it is last.
	GreaseSetting bool

	// SettingsStreamID is the unidirectional control stream SETTINGS goes out
	// on. Stream 2 is the client's first unidirectional stream, so opening the
	// control stream first is itself part of the profile.
	SettingsStreamID uint64

	// SettingsFrameLen is the encoded length of the SETTINGS frame body. Worth
	// pinning because it is a function of the varint encodings chosen for every
	// id and value above, and a re-encoding that picks non-minimal varints
	// somewhere would still parse and would still be a different length.
	SettingsFrameLen int

	// GreaseFrameAfterSettings records that a whole reserved FRAME follows
	// SETTINGS on the control stream. Its type and payload are random, so
	// neither is pinned — only that it is sent, and sent there.
	GreaseFrameAfterSettings bool

	// AfterSettings is the frame sequence that follows SETTINGS on the control
	// stream, by type, with the reserved frame above left out because its type
	// is random. Listing it as 0x00 would name it DATA, which it is not.
	AfterSettings []uint64

	// DefaultPriority is the PRIORITY_UPDATE payload for a fetch, in the RFC
	// 9218 structured-field form that also appears in the priority header.
	DefaultPriority string

	// PseudoHeaderOrder is the order of the four pseudo-headers. Chrome uses
	// the same order on HTTP/3 as on HTTP/2, which is worth stating: the two
	// agreeing is what a cross-protocol check would look for.
	PseudoHeaderOrder []string

	// FetchHeaderOrder is the order of the regular headers on a same-site
	// fetch — an XHR, not a top-level navigation. Named for what it is: a
	// document request carries a different set (sec-fetch-dest: document, an
	// accept of text/html, no origin) and its order is not this one.
	FetchHeaderOrder []string

	// Fingerprint is the HTTP/3 fingerprint string in the form the reporting
	// server printed it:
	//
	//	SETTINGS | control-stream frames | PRIORITY_UPDATE type | pseudo-header order
	//
	// The third field is 984832, which is 0x0f0700 — the PRIORITY_UPDATE frame
	// type itself rather than a value.
	Fingerprint string
}

// Setting is one HTTP/3 SETTINGS entry.
type Setting struct {
	ID    uint64
	Name  string
	Value uint64
}

// HTTP/3 setting identifiers this profile sends.
const (
	H3SettingQPACKMaxTableCapacity = 0x01
	H3SettingMaxFieldSectionSize   = 0x06
	H3SettingQPACKBlockedStreams   = 0x07
	// H3SettingDatagram is RFC 9297. Chrome advertises it; the transport
	// parameter max_datagram_frame_size in reference.go is the other half of
	// the same capability, and sending one without the other would be
	// incoherent.
	H3SettingDatagram = 0x33
)

// HTTP/3 frame types that appear on the control stream before any request.
const (
	H3FramePriorityUpdate = 0x0f0700 // RFC 9218, for a request stream
)

// Chrome151H3 is Chrome 151 on Windows 10 speaking HTTP/3.
//
// Two things here would be easy to get wrong and are visible immediately if
// they are:
//
// The GREASE that the QUIC ClientHello does not carry reappears at this layer.
// There is a reserved SETTINGS entry with a random id and value, and a whole
// reserved FRAME on the control stream after SETTINGS. A client that sends a
// clean SETTINGS frame and nothing else is distinguishable from Chrome on the
// first flight of the control stream, before it has made a single request.
//
// And SETTINGS is not the last thing on that stream. Chrome follows it with
// the reserved frame and then a PRIORITY_UPDATE, so a control stream that goes
// quiet after SETTINGS is its own signal.
//
// A third thing is not a mistake to avoid but a bill to pay, and it is recorded
// here because it decides how the HTTP/3 layer gets built rather than how it is
// checked. SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS
// are promises to the server about what this client's *decoder* will accept: 64
// KiB of dynamic table, and up to 100 streams blocked waiting on it. A server
// that takes them at face value may encode a response against the dynamic table,
// and github.com/quic-go/qpack — which quic-go's own http3 uses — has no dynamic
// table at all. Its decoder rejects a non-zero Required Insert Count outright.
//
// So these two numbers cannot be sent by an implementation that has not
// implemented QPACK's dynamic table. Sending zeroes instead is coherent and
// safe, and is a different fingerprint on the first frame of the control
// stream — 1:0;6:262144;7:0 rather than what is pinned above. That is the
// trade, and it is not one that can be split.
var Chrome151H3 = HTTP3Reference{
	Device: "Chrome 151.0.7922.77, Windows 10 (19045), AMD64",
	Source: "https://quic.browserleaks.com/, 2026-08-21",

	Settings: []Setting{
		{H3SettingQPACKMaxTableCapacity, "SETTINGS_QPACK_MAX_TABLE_CAPACITY", 65536},
		{H3SettingMaxFieldSectionSize, "SETTINGS_MAX_FIELD_SECTION_SIZE", 262144},
		{H3SettingQPACKBlockedStreams, "SETTINGS_QPACK_BLOCKED_STREAMS", 100},
		{H3SettingDatagram, "SETTINGS_H3_DATAGRAM", 1},
	},
	GreaseSetting:    true,
	SettingsStreamID: 2,
	SettingsFrameLen: 31,

	// A reserved frame first, then PRIORITY_UPDATE.
	GreaseFrameAfterSettings: true,
	AfterSettings:            []uint64{H3FramePriorityUpdate},
	DefaultPriority:          "u=1, i",

	// :method, :authority, :scheme, :path — the same order as the HTTP/2
	// profile in fingerprint.go.
	PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},

	// Note where the client hints sit: sec-ch-ua-platform leads, ahead of
	// user-agent, and the other two follow it. Alphabetical order would put
	// them elsewhere, and net/http's own sorting would too.
	FetchHeaderOrder: []string{
		"sec-ch-ua-platform",
		"user-agent",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"accept",
		"origin",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"accept-encoding",
		"accept-language",
		"priority",
	},

	Fingerprint: "1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p",
}
