package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
	quicprofile "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quic"
)

// The HTTP/3 half of fpcheck.
//
// The TCP path is checked against a service that reports the TLS and HTTP/2
// view of a request. There is an equivalent for QUIC — it reports the QUIC JA4
// and an HTTP/3 fingerprint string — and this asks it the same question the
// rest of the command asks: does what arrived match what internal/quic pinned
// from a real browser?
//
// It matters more here than on the TCP path, and for a reason worth stating.
// Everything in internal/quic/http3.go came from one report of one Chrome
// session, transcribed. The package's own tests prove this client emits those
// values, which is circular: if the transcription were wrong, the tests and the
// code would agree and both be wrong. A live check against the same kind of
// service is the only thing in the tree that can contradict it, the way
// browserleaks's JA4 already contradicts (and confirms) the decoder.

// defaultH3URL reports the QUIC and HTTP/3 view of a request, the way
// tls.peet.ws reports the TLS and HTTP/2 one.
//
// NOT YET RUN AGAINST A LIVE SERVICE. The reference in internal/quic/http3.go
// came from a browserleaks report that a person read and pasted in; this code
// has never made the request itself, because the environment it was written in
// has no egress. So the JSON field names below are read off that report's shape
// and are the least certain thing in this file.
//
// That is why every check skips rather than passes when a field is missing: a
// service naming things differently reports as "nobody looked", which is true,
// instead of as a row of green ticks, which would not be. Point -h3-url at
// whatever service you have and read the skips first.
const defaultH3URL = "https://quic.browserleaks.com/json"

// h3Capture is the subset of a QUIC fingerprinting response fpcheck reads.
//
// The field names follow browserleaks, which is where internal/quic/http3.go's
// reference came from. Unknown fields are ignored, so a service returning a
// superset still works; a service using different names reports every field as
// missing rather than as wrong, which is the safer failure.
type h3Capture struct {
	UserAgent string `json:"user_agent"`

	QUIC struct {
		JA4  string `json:"ja4"`
		JA4R string `json:"ja4_r"`
	} `json:"quic"`

	HTTP3 struct {
		Fingerprint string            `json:"fingerprint"`
		Settings    map[string]uint64 `json:"settings"`
		Frames      []string          `json:"frames"`
	} `json:"http3"`

	// Headers is the request's field list in the order it arrived, which is the
	// one thing a handler cannot recover: net/http gives it a map.
	Headers []string `json:"headers"`
}

// runH3 makes one HTTP/3 request and diffs what the server saw against the
// reference.
func runH3(ctx context.Context, url, proxy, save string, timeout time.Duration) error {
	opts := []gofire.Option{
		gofire.WithTimeout(timeout),
		// Forced, because there is nothing to discover: this command exists to
		// measure the QUIC path, and waiting for an Alt-Svc offer would measure
		// the TCP one instead. Everything else about the connection is what a
		// discovered upgrade would produce.
		gofire.WithForceHTTP3(),
	}
	if proxy != "" {
		// A QUIC connection does not go through an HTTP CONNECT proxy, and
		// silently ignoring -proxy would report a fingerprint measured from the
		// wrong address.
		return fmt.Errorf("-proxy does not apply to HTTP/3: QUIC is UDP and this " +
			"client does not tunnel it")
	}
	client, err := gofire.Emulate(gofire.Chrome151, opts...)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer client.Close()

	raw, err := fetchRaw(ctx, client, url)
	if err != nil {
		return err
	}
	if save != "" {
		if err := os.WriteFile(save, raw, 0o644); err != nil {
			return fmt.Errorf("save capture: %w", err)
		}
		fmt.Printf("saved raw capture to %s\n", save)
	}

	var got h3Capture
	if err := json.Unmarshal(raw, &got); err != nil {
		return fmt.Errorf("parse response (is %s a QUIC fingerprint API?): %w", url, err)
	}

	header := fmt.Sprintf("%s over HTTP/3  via %s", gofire.Chrome151, url)
	fmt.Println(header)
	fmt.Println(strings.Repeat("=", len(header)))
	fmt.Printf("reference device: %s\n\n", quicprofile.Chrome151QUIC.Device)

	checks := checkH3(got)
	failed := report(checks)

	// A skipped check means a field this command expected was not in the
	// response, and the field names here have never been checked against a live
	// service — see defaultH3URL. So print what did arrive: without it a run
	// that skipped everything says only that nobody looked, and gives no way to
	// find out what to look at instead.
	if skipped(checks) > 0 {
		fmt.Println()
		fmt.Printf("%d check(s) were skipped, which means this command did not find\n"+
			"the fields it expected. The raw response follows so the names can be\n"+
			"corrected — see the note on defaultH3URL in cmd/fpcheck/h3.go.\n\n", skipped(checks))
		fmt.Println(prettyJSON(raw))
	}

	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	return nil
}

func skipped(checks []check) int {
	var n int
	for _, c := range checks {
		if c.skipped {
			n++
		}
	}
	return n
}

// prettyJSON re-indents a response for reading, and falls back to the bytes as
// they came if that fails — an unparseable body is exactly the case where
// seeing it verbatim matters most.
func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

// checkH3 diffs a QUIC capture against the pinned profile, layer by layer.
func checkH3(got h3Capture) []check {
	ref := quicprofile.Chrome151QUIC
	h3 := quicprofile.Chrome151H3

	var checks []check
	add := func(name, want, actual string) {
		checks = append(checks, check{name: name, want: want, got: actual})
	}
	skip := func(name, note string) {
		checks = append(checks, check{name: name, skipped: true, note: note})
	}

	// The TLS layer, as QUIC carries it. This is the value browserleaks already
	// agreed with once, offline, in internal/quic/http3_test.go — so a
	// disagreement here is this client drifting rather than the reference being
	// wrong.
	if got.QUIC.JA4 == "" {
		skip("quic.ja4", "endpoint did not report a QUIC ja4")
	} else {
		add("quic.ja4", ref.JA4, got.QUIC.JA4)
	}
	switch {
	case ref.JA4R == "":
		skip("quic.ja4_r", "no device capture for this profile yet")
	case got.QUIC.JA4R == "":
		skip("quic.ja4_r", "endpoint did not report ja4_r")
	default:
		add("quic.ja4_r", ref.JA4R, got.QUIC.JA4R)
	}

	// The HTTP/3 layer. The fingerprint string folds the SETTINGS, the frames
	// after them and the pseudo-header order into one value, which is why it is
	// checked whole as well as in pieces: the pieces name what moved, the whole
	// catches something moving that the pieces do not cover.
	if got.HTTP3.Fingerprint == "" {
		skip("http3.fingerprint", "endpoint did not report an HTTP/3 fingerprint")
	} else {
		add("http3.fingerprint", h3.Fingerprint, got.HTTP3.Fingerprint)
	}

	if len(got.HTTP3.Settings) == 0 {
		skip("http3.settings", "endpoint did not report the SETTINGS frame")
	} else {
		for _, s := range h3.Settings {
			key := strconv.FormatUint(s.ID, 10)
			v, ok := got.HTTP3.Settings[key]
			if !ok {
				add("http3.settings["+s.Name+"]", strconv.FormatUint(s.Value, 10), "(absent)")
				continue
			}
			add("http3.settings["+s.Name+"]",
				strconv.FormatUint(s.Value, 10), strconv.FormatUint(v, 10))
		}
	}

	// The frames after SETTINGS are the check that only a live server can make.
	// Both exist to be ignored, so no test can fail for their absence, and
	// nothing but a server that reports what it received will ever notice they
	// stopped being sent.
	if len(got.HTTP3.Frames) == 0 {
		skip("http3.frames", "endpoint did not report the control stream frames")
	} else {
		seen := strings.Join(got.HTTP3.Frames, ",")
		for _, want := range h3.AfterSettings {
			name := fmt.Sprintf("http3.frames[%#x]", want)
			if containsFrame(got.HTTP3.Frames, want) {
				add(name, "present", "present")
			} else {
				add(name, "present", "absent (saw "+seen+")")
			}
		}
	}

	// And the header order, which is the oldest fingerprint of the four and the
	// one a handler cannot see.
	if len(got.Headers) == 0 {
		skip("http3.header_order", "endpoint did not report the request's field order")
	} else {
		var pseudo, regular []string
		for _, h := range got.Headers {
			// Each entry is "name: value". A pseudo-header starts with its own
			// colon, so the split has to skip that one or every one of them
			// comes back empty.
			if strings.HasPrefix(h, ":") {
				name, _, _ := strings.Cut(h[1:], ":")
				pseudo = append(pseudo, ":"+strings.ToLower(strings.TrimSpace(name)))
				continue
			}
			name, _, _ := strings.Cut(h, ":")
			regular = append(regular, strings.ToLower(strings.TrimSpace(name)))
		}
		add("http3.pseudo_header_order",
			strings.Join(h3.PseudoHeaderOrder, ","), strings.Join(pseudo, ","))

		// Only the profile's own headers are compared, in their relative order:
		// the request fpcheck sends is not a full fetch, and demanding every
		// name would report a difference that is this command's doing.
		var want, have []string
		for _, name := range h3.FetchHeaderOrder {
			if contains(regular, name) {
				want = append(want, name)
			}
		}
		for _, name := range regular {
			if contains(h3.FetchHeaderOrder, name) {
				have = append(have, name)
			}
		}
		add("http3.header_order", strings.Join(want, ","), strings.Join(have, ","))
	}

	if got.UserAgent != "" {
		add("user-agent", gofire.ReferenceFor(gofire.Chrome151).UserAgent, got.UserAgent)
	}

	return checks
}

func containsFrame(frames []string, want uint64) bool {
	dec := strconv.FormatUint(want, 10)
	hex := fmt.Sprintf("%#x", want)
	for _, f := range frames {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == dec || f == hex || strings.Contains(f, "priority_update") && want == quicprofile.H3FramePriorityUpdate {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
