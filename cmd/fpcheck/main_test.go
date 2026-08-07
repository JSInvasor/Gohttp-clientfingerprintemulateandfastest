package main

import (
	"encoding/json"
	"strings"
	"testing"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// safariCapture is a fingerprint-API response shaped like tls.peet.ws's, filled
// with what a correct Safari profile produces. The tests below mutate copies of
// it to check that each class of regression is actually caught — a checker that
// silently passes everything is worse than no checker.
func safariCapture(t *testing.T) capture {
	t.Helper()
	ref := gofire.ReferenceFor(gofire.SafariIOS18)

	raw := `{
	  "user_agent": ` + quote(ref.UserAgent) + `,
	  "tls": {
	    "ja3": ` + quote(ref.JA3) + `,
	    "ja3_hash": ` + quote(ref.JA3Hash) + `,
	    "ja4": ` + quote(ref.JA4) + `
	  },
	  "http2": {
	    "akamai_fingerprint": ` + quote(ref.AkamaiFingerprint) + `,
	    "akamai_fingerprint_hash": ` + quote(ref.AkamaiHash) + `,
	    "sent_frames": [
	      {"frame_type":"SETTINGS","stream_id":0,"flags":[]},
	      {"frame_type":"WINDOW_UPDATE","stream_id":0,"flags":[]},
	      {"frame_type":"HEADERS","stream_id":1,
	       "flags":["EndStream (0x1)","EndHeaders (0x4)"],
	       "headers":[
	         ":method: GET",
	         ":scheme: https",
	         ":authority: tls.peet.ws",
	         ":path: /api/all",
	         "sec-fetch-dest: document",
	         "user-agent: ` + ref.UserAgent + `",
	         "accept: text/html",
	         "sec-fetch-site: none",
	         "sec-fetch-mode: navigate",
	         "accept-language: en-US,en;q=0.9",
	         "priority: u=0, i",
	         "accept-encoding: gzip, deflate, br, zstd"
	       ]}
	    ]
	  }
	}`

	var c capture
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	return c
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestCheckAgainstReferencePasses(t *testing.T) {
	ref := gofire.ReferenceFor(gofire.SafariIOS18)
	for _, c := range checkAgainstReference(ref, safariCapture(t)) {
		if !c.ok() {
			t.Errorf("check %q failed on a correct capture\n want: %s\n got:  %s", c.name, c.want, c.got)
		}
	}
}

// TestCheckCatchesHeadersPriority is the regression this file exists for.
//
// Safari advertises SETTINGS_NO_RFC7540_PRIORITIES=1, so its HEADERS frames
// carry no RFC 7540 priority block. A build that attaches one anyway is
// contradicting its own SETTINGS on every request, and it must not read as a
// pass here.
func TestCheckCatchesHeadersPriority(t *testing.T) {
	got := safariCapture(t)
	hf := got.headersFrame()
	hf.Flags = append(hf.Flags, "Priority (0x20)")
	hf.Priority = &struct {
		Weight    int `json:"weight"`
		DependsOn int `json:"depends_on"`
		Exclusive int `json:"exclusive"`
	}{Weight: 256, DependsOn: 0, Exclusive: 0}

	assertFails(t, "http2.headers_priority", gofire.ReferenceFor(gofire.SafariIOS18), got)
}

func TestCheckCatchesHeaderOrder(t *testing.T) {
	got := safariCapture(t)
	hf := got.headersFrame()
	// Move accept-encoding to the front — the Chrome-ish position, and the
	// single most distinctive thing about Safari's order is that it is last.
	hf.Headers = append([]string{hf.Headers[0]},
		append([]string{"accept-encoding: gzip"}, hf.Headers[1:len(hf.Headers)-1]...)...)

	assertFails(t, "header_order", gofire.ReferenceFor(gofire.SafariIOS18), got)
}

func TestCheckCatchesJA4Drift(t *testing.T) {
	got := safariCapture(t)
	got.TLS.JA4 = "t13d2014h2_a09f3c656075_7f0f34a4126d" // one extra extension
	assertFails(t, "tls.ja4", gofire.ReferenceFor(gofire.SafariIOS18), got)
}

func TestCheckCatchesAkamaiDrift(t *testing.T) {
	got := safariCapture(t)
	got.HTTP2.AkamaiFingerprint = "2:0;3:100;4:2097152|10420225|0|m,s,a,p" // 9:1 dropped
	assertFails(t, "http2.akamai_fingerprint", gofire.ReferenceFor(gofire.SafariIOS18), got)
}

// assertFails checks that exactly the named check fails and every other one
// still passes, so a test cannot pass by breaking something unrelated.
func assertFails(t *testing.T, name string, ref gofire.Reference, got capture) {
	t.Helper()
	var sawFailure bool
	for _, c := range checkAgainstReference(ref, got) {
		switch {
		case c.name == name && c.ok():
			t.Errorf("check %q passed on a capture that should have failed it\n got: %s", name, c.got)
		case c.name == name:
			sawFailure = true
		case !c.ok():
			t.Errorf("unrelated check %q also failed\n want: %s\n got:  %s", c.name, c.want, c.got)
		}
	}
	if !sawFailure {
		t.Errorf("no check named %q ran", name)
	}
}

// TestChromeJA3IsNotChecked pins that a Chrome run does not fail on JA3.
// Chrome permutes its extension order per connection, so its JA3 is a different
// value every time; asserting a fixed one would fail on a correct client.
func TestChromeJA3IsNotChecked(t *testing.T) {
	ref := gofire.ReferenceFor(gofire.Chrome150)
	if ref.JA3Hash != "" {
		t.Fatal("Chrome reference carries a JA3 hash; it cannot have a stable one")
	}

	got := safariCapture(t) // JA3 fields hold Safari's values — deliberately wrong for Chrome
	for _, c := range checkAgainstReference(ref, got) {
		if strings.HasPrefix(c.name, "tls.ja3") && !c.skipped {
			t.Errorf("check %q ran for Chrome; JA3 must be reported as unverifiable, not compared", c.name)
		}
	}
}

func TestHeaderNamesSplitsPseudoHeaders(t *testing.T) {
	f := &frame{Headers: []string{
		":method: GET",
		":authority: example.com",
		"user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)",
		"accept-encoding: gzip, deflate, br, zstd",
	}}

	pseudo, regular := f.headerNames()
	if want := ":method,:authority"; strings.Join(pseudo, ",") != want {
		t.Errorf("pseudo-headers = %v, want %s", pseudo, want)
	}
	if want := "user-agent,accept-encoding"; strings.Join(regular, ",") != want {
		t.Errorf("headers = %v, want %s", regular, want)
	}
}
