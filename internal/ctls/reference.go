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

	// JA4R is the full unhashed JA4: the a-part, then the sorted ciphers, the
	// sorted extensions and the signature algorithms in wire order.
	//
	// Worth checking alongside JA4 precisely because it is not hashed. A JA4
	// mismatch says only that something moved; a JA4_r mismatch shows which
	// cipher, extension or signature algorithm it was.
	JA4R string

	// PeetPrintHash is tls.peet.ws's own fingerprint. It covers fields JA3 and
	// JA4 both ignore — supported_versions, ALPN, PSK modes and the
	// ec_point_formats list — so it catches drift the other two cannot see.
	PeetPrintHash string
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
	JA4R: "t13d2013h2_" +
		"000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_" +
		"0005,000a,000b,000d,0012,0017,001b,002b,002d,0033,ff01_" +
		"0403,0804,0401,0503,0805,0805,0501,0806,0601,0201",
	PeetPrintHash: "62b834de729e78a9f0ebd1dd099314a7",
}

// ChromeReference is a real Chrome 151 on Windows.
//
// The extension count in JA4_a is 16. An earlier revision documented 17, read
// off a capture of a RESUMED session that carried pre_shared_key (0x0029) as a
// seventeenth counted extension; this package never sends PSK on an initial
// connection, so it emits 16 and can never produce the 17-extension hash. The
// device confirms 16 — and confirms application_settings is the 0x44CD
// codepoint alone, with no second 0x4469 entry.
//
// JA3 and JA3Hash stay empty: the capture reports
// e4a965cf74d922620ea020ec4aec14db, but that is one draw from the per-connection
// extension permutation and the next connection produces a different one.
// Pinning it would fail every correct run. JA4R and PeetPrint are safe to pin
// because both sort the extension list before rendering.
var ChromeReference = TLSReference{
	Device:         "Chrome 151, Windows 10 x64",
	JA4:            "t13d1516h2_8daaf6152771_806a8c22fdea",
	JA4RExtensions: "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01",
	JA4R: "t13d1516h2_" +
		"002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_" +
		"0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_" +
		"0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601",
	PeetPrintHash: "67c3e9111bed9e7f03d2f21d6d88994b",
}

// ReferenceFor returns the TLS reference for a browser type.
func ReferenceFor(b BrowserType) TLSReference {
	if b == BrowserChrome {
		return ChromeReference
	}
	return SafariReference
}
