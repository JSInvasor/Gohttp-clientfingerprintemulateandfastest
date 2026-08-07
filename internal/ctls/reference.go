package ctls

// Reference TLS fingerprints for the profiles this package builds.
//
// These are not aspirations — each one was read off a real device against
// tls.peet.ws, and the ClientHello builders are written to reproduce them.
// chrome_hello_test.go and safari_hello_test.go parse the bytes this package
// actually emits and assert against these values, so a change that shifts the
// fingerprint fails the build rather than silently making the client trackable.
//
// They live in a non-test file so the fpcheck command can compare a live
// response against the same constants the tests use. A second copy of these
// strings somewhere else would eventually disagree with this one, and the copy
// that disagreed would be the one nobody noticed.

// TLSReference is the set of TLS-layer fingerprint values a profile produces.
type TLSReference struct {
	// Device is what the values were captured from.
	Device string

	// JA3 is the full JA3 string, and JA3Hash its MD5.
	//
	// Both are empty for Chrome, and that is not an omission: Chrome permutes
	// its extension order on every connection (BoringSSL's
	// tls_extension_permutation, default-on since Chrome 110) and JA3 hashes
	// extensions in wire order, so a Chrome JA3 is a different value per
	// connection by design. A stable Chrome JA3 would itself be the bot signal.
	JA3     string
	JA3Hash string

	// JA4 sorts ciphers and extensions before hashing, so it is stable for
	// both profiles.
	JA4 string

	// JA4RExtensions is the sorted extension list that feeds JA4's c-part,
	// with SNI and ALPN removed (they are counted in the a-part instead).
	// Pinning it separately localises a failure to the extension set rather
	// than leaving it ambiguous with the signature algorithms.
	JA4RExtensions string
}

// SafariReference is a real iPhone 13 running iOS 26.5.2 (Safari 26.5.2).
//
// Every browser on iOS produces this same fingerprint — Chrome (CriOS) and the
// Google app were captured byte-identical — because iOS forces them all onto
// Apple's networking stack. Only the User-Agent differs.
var SafariReference = TLSReference{
	Device: "iPhone 13, iOS 26.5.2, Safari 26.5.2",
	JA3: "771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10," +
		"0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0",
	JA3Hash:        "ecdf4f49dd59effc439639da29186671",
	JA4:            "t13d2013h2_a09f3c656075_7f0f34a4126d",
	JA4RExtensions: "0005,000a,000b,000d,0012,0017,001b,002b,002d,0033,ff01",
}

// ChromeReference is a real Chrome 150 on Windows.
//
// The extension count in JA4_a is 16. An earlier revision documented 17, read
// off a capture of a RESUMED session that carried pre_shared_key (0x0029) as a
// seventeenth counted extension; this package never sends PSK on an initial
// connection, so it emits 16 and can never produce the 17-extension hash.
var ChromeReference = TLSReference{
	Device:         "Chrome 150, Windows 10 x64",
	JA4:            "t13d1516h2_8daaf6152771_806a8c22fdea",
	JA4RExtensions: "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01",
}

// ReferenceFor returns the TLS reference for a browser type.
func ReferenceFor(b BrowserType) TLSReference {
	if b == BrowserChrome {
		return ChromeReference
	}
	return SafariReference
}
