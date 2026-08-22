package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
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
// The field names below are now the ones a live run returned, not a guess: the
// first version nested them under "quic" and "http3" and every check skipped.
// The response is flat, and the HTTP/3 fingerprint arrives as one string rather
// than as a settings map.
//
// Checks still skip rather than pass when a field is missing, because that is
// the honest reading for any other service: "nobody looked", not a green tick.
// Point -h3-url elsewhere and read the skips first.
const defaultH3URL = "https://quic.browserleaks.com/json"

// h3Capture is the subset of a QUIC fingerprinting response fpcheck reads.
//
// Flat, because that is what the service returns. Unknown fields are ignored,
// so one returning a superset still works, and one using different names
// reports every field as missing rather than as wrong — the safer failure.
type h3Capture struct {
	UserAgent string `json:"user_agent"`

	JA4  string `json:"ja4"`
	JA4R string `json:"ja4_r"`

	// H3Text is the HTTP/3 fingerprint, pipe-separated:
	//
	//	settings | reserved frame | frames after it | pseudo-header order
	//
	// The third field is a frame type in decimal and is absent, not empty, when
	// no such frame arrived — which is how the missing PRIORITY_UPDATE was
	// found. See splitH3Text.
	H3Text string `json:"h3_text"`
	H3Hash string `json:"h3_hash"`
}

// h3Fields is H3Text taken apart.
type h3Fields struct {
	settings string
	reserved string
	frames   []string
	pseudo   string
}

// splitH3Text reads the fingerprint string without assuming how many fields it
// has.
//
// It has four when everything the profile sends arrived, three when one of the
// two frames after SETTINGS did not, and two when neither did: the middle
// fields collapse rather than coming through empty. A parser that indexed them
// positionally would read the pseudo-header order out of the frame slot and
// report a difference in the wrong place — which is the failure that sends you
// looking at the wrong layer.
//
// So the first field is the settings and the last is the pseudo-header order,
// both always present. What is between them is the reserved frame, reported as
// the literal "GREASE", and then the frame types in decimal.
func splitH3Text(v string) (h3Fields, bool) {
	parts := strings.Split(v, "|")
	if len(parts) < 2 || !strings.Contains(parts[0], ":") {
		return h3Fields{}, false
	}
	f := h3Fields{
		settings: parts[0],
		pseudo:   parts[len(parts)-1],
	}
	mid := parts[1 : len(parts)-1]
	if len(mid) > 0 && mid[0] == "GREASE" {
		f.reserved = "GREASE"
		mid = mid[1:]
	}
	for _, p := range mid {
		for _, one := range strings.Split(p, ",") {
			if one = strings.TrimSpace(one); one != "" {
				f.frames = append(f.frames, one)
			}
		}
	}
	return f, true
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
	if got.JA4 == "" {
		skip("quic.ja4", "endpoint did not report a QUIC ja4")
	} else {
		add("quic.ja4", ref.JA4, got.JA4)
	}
	switch {
	case ref.JA4R == "":
		skip("quic.ja4_r", "no device capture for this profile yet")
	case got.JA4R == "":
		skip("quic.ja4_r", "endpoint did not report ja4_r")
	default:
		add("quic.ja4_r", ref.JA4R, got.JA4R)
	}

	fields, ok := splitH3Text(got.H3Text)
	if !ok {
		skip("http3.fingerprint", "endpoint did not report an HTTP/3 fingerprint")
		return checks
	}

	// The whole string as well as its parts. The parts name what moved; the
	// whole catches something moving that the parts do not cover.
	add("http3.fingerprint", h3.Fingerprint, got.H3Text)

	var want []string
	for _, s := range h3.Settings {
		want = append(want, fmt.Sprintf("%d:%d", s.ID, s.Value))
	}
	if h3.GreaseSetting {
		want = append(want, "GREASE")
	}
	add("http3.settings", strings.Join(want, ";"), fields.settings)

	if h3.GreaseFrameAfterSettings {
		got := fields.reserved
		if got == "" {
			got = "(absent)"
		}
		add("http3.reserved_frame", "GREASE", got)
	}

	// The frames after SETTINGS are the check only a live server can make. They
	// are ignorable by any peer, so nothing fails when they stop being sent and
	// no offline test can notice — this is where the missing PRIORITY_UPDATE
	// turned up, against a client whose own tests all passed.
	seen := "(none)"
	if len(fields.frames) > 0 {
		seen = strings.Join(fields.frames, ",")
	}
	for _, frameType := range h3.AfterSettings {
		name := fmt.Sprintf("http3.frames[%#x]", frameType)
		if containsFrame(fields.frames, frameType) {
			add(name, "present", "present")
		} else {
			add(name, "present", "absent (saw "+seen+")")
		}
	}

	// And the pseudo-header order, which a handler cannot see.
	var initials []string
	for _, p := range h3.PseudoHeaderOrder {
		initials = append(initials, string(p[1]))
	}
	add("http3.pseudo_header_order", strings.Join(initials, ","), fields.pseudo)

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
	return slices.Contains(list, want)
}
