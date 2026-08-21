package main

import (
	"strconv"
	"strings"
	"testing"

	quicprofile "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quic"
)

// checkH3 is what turns the pinned profile into PASS/FAIL lines, so the thing
// worth testing is that it fails when it should.
//
// A checker that reported PASS for a capture that did not match would be worse
// than no checker: it is the one thing in the tree meant to catch the client
// drifting, and a green tick from it is the reason nobody looks further.

// perfectCapture is what a correct client should produce.
func perfectCapture() h3Capture {
	ref := quicprofile.Chrome151QUIC
	h3 := quicprofile.Chrome151H3

	var c h3Capture
	c.QUIC.JA4 = ref.JA4
	c.QUIC.JA4R = ref.JA4R
	c.HTTP3.Fingerprint = h3.Fingerprint
	c.HTTP3.Settings = map[string]uint64{}
	for _, s := range h3.Settings {
		c.HTTP3.Settings[strconv.FormatUint(s.ID, 10)] = s.Value
	}
	for _, f := range h3.AfterSettings {
		c.HTTP3.Frames = append(c.HTTP3.Frames, strconv.FormatUint(f, 10))
	}
	for _, name := range h3.PseudoHeaderOrder {
		c.Headers = append(c.Headers, name+": x")
	}
	for _, name := range h3.FetchHeaderOrder {
		c.Headers = append(c.Headers, name+": x")
	}
	return c
}

func failures(checks []check) []string {
	var out []string
	for _, c := range checks {
		if !c.ok() {
			out = append(out, c.name)
		}
	}
	return out
}

func TestCheckH3AcceptsACorrectCapture(t *testing.T) {
	if bad := failures(checkH3(perfectCapture())); len(bad) > 0 {
		t.Errorf("a capture matching the reference failed: %v", bad)
	}
}

func TestCheckH3RejectsAChangedJA4(t *testing.T) {
	c := perfectCapture()
	c.QUIC.JA4 = "q13d0311h3_0000000000_0000000000"
	if bad := failures(checkH3(c)); !contains(bad, "quic.ja4") {
		t.Errorf("a changed QUIC JA4 was accepted (failures: %v)", bad)
	}
}

func TestCheckH3RejectsAChangedSetting(t *testing.T) {
	c := perfectCapture()
	// The QPACK table capacity dropping to zero is the exact regression that
	// would follow from reverting internal/qpack's dynamic table, and it would
	// leave everything else about the connection working.
	c.HTTP3.Settings[strconv.FormatUint(quicprofile.H3SettingQPACKMaxTableCapacity, 10)] = 0
	bad := failures(checkH3(c))
	var found bool
	for _, name := range bad {
		if strings.Contains(name, "QPACK_MAX_TABLE_CAPACITY") {
			found = true
		}
	}
	if !found {
		t.Errorf("a changed SETTINGS value was accepted (failures: %v)", bad)
	}
}

func TestCheckH3RejectsAMissingSetting(t *testing.T) {
	c := perfectCapture()
	delete(c.HTTP3.Settings, strconv.FormatUint(quicprofile.H3SettingDatagram, 10))
	bad := failures(checkH3(c))
	var found bool
	for _, name := range bad {
		if strings.Contains(name, "H3_DATAGRAM") {
			found = true
		}
	}
	if !found {
		t.Errorf("a missing SETTINGS entry was accepted (failures: %v)", bad)
	}
}

// TestCheckH3RejectsASilentControlStream is the one this command exists for.
//
// The frames after SETTINGS are ignorable by any peer, so dropping them breaks
// nothing and fails no test anywhere else in the tree. A live server that
// reports what it received is the only thing that can notice.
func TestCheckH3RejectsASilentControlStream(t *testing.T) {
	c := perfectCapture()
	c.HTTP3.Frames = []string{"SETTINGS"}
	bad := failures(checkH3(c))
	if len(bad) == 0 {
		t.Fatal("a control stream that stopped at SETTINGS was accepted")
	}
	var found bool
	for _, name := range bad {
		if strings.HasPrefix(name, "http3.frames") {
			found = true
		}
	}
	if !found {
		t.Errorf("the missing frame was not named (failures: %v)", bad)
	}
}

func TestCheckH3RejectsAReorderedHeaderList(t *testing.T) {
	c := perfectCapture()
	// Swap the first two regular headers, which is what any implementation
	// iterating a Go map produces sooner or later.
	n := len(quicprofile.Chrome151H3.PseudoHeaderOrder)
	c.Headers[n], c.Headers[n+1] = c.Headers[n+1], c.Headers[n]
	if bad := failures(checkH3(c)); !contains(bad, "http3.header_order") {
		t.Errorf("a reordered header list was accepted (failures: %v)", bad)
	}
}

func TestCheckH3RejectsAReorderedPseudoHeaderList(t *testing.T) {
	c := perfectCapture()
	c.Headers[0], c.Headers[1] = c.Headers[1], c.Headers[0]
	if bad := failures(checkH3(c)); !contains(bad, "http3.pseudo_header_order") {
		t.Errorf("a reordered pseudo-header list was accepted (failures: %v)", bad)
	}
}

// TestCheckH3SkipsRatherThanPassesWhatItCannotSee keeps an endpoint that
// reports less than browserleaks from reading as a green run.
//
// A skipped check prints as skipped and a missing field is not a passing one;
// the distinction is the difference between "this client is correct" and
// "nobody looked".
func TestCheckH3SkipsRatherThanPassesWhatItCannotSee(t *testing.T) {
	var empty h3Capture
	checks := checkH3(empty)
	if len(checks) == 0 {
		t.Fatal("an empty capture produced no checks at all")
	}
	for _, c := range checks {
		if !c.skipped {
			t.Errorf("check %q was not skipped against an endpoint that reported nothing", c.name)
		}
		if c.note == "" {
			t.Errorf("check %q was skipped without saying why", c.name)
		}
	}
}

// TestPriorityUpdateIsRecognisedByName covers the reporting side rather than
// the client: services name the frame rather than numbering it, and a checker
// that only matched the number would report a missing frame that was sent.
func TestPriorityUpdateIsRecognisedByName(t *testing.T) {
	for _, form := range []string{
		strconv.FormatUint(quicprofile.H3FramePriorityUpdate, 10),
		"0xf0700",
		"PRIORITY_UPDATE",
		"priority_update",
	} {
		if !containsFrame([]string{form}, quicprofile.H3FramePriorityUpdate) {
			t.Errorf("PRIORITY_UPDATE reported as %q was not recognised", form)
		}
	}
	if containsFrame([]string{"SETTINGS", "GOAWAY"}, quicprofile.H3FramePriorityUpdate) {
		t.Error("PRIORITY_UPDATE was found in a list that does not contain it")
	}
}
