package main

import (
	"strconv"
	"strings"
	"testing"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
	quicprofile "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quic"
)

// checkH3 is what turns the pinned profile into PASS/FAIL lines, so the thing
// worth testing is that it fails when it should.
//
// A checker that reported PASS for a capture that did not match would be worse
// than no checker: it is the one thing in the tree meant to catch the client
// drifting, and a green tick from it is the reason nobody looks further.

// perfectCapture is what a correct client should produce, in the shape a live
// run actually returned: flat fields, and the HTTP/3 fingerprint as one string.
func perfectCapture() h3Capture {
	return h3Capture{
		UserAgent: gofire.ReferenceFor(gofire.Chrome151).UserAgent,
		JA4:       quicprofile.Chrome151QUIC.JA4,
		JA4R:      quicprofile.Chrome151QUIC.JA4R,
		H3Text:    quicprofile.Chrome151H3.Fingerprint,
	}
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
	c.JA4 = "q13d0311h3_0000000000_0000000000"
	if bad := failures(checkH3(c)); !contains(bad, "quic.ja4") {
		t.Errorf("a changed QUIC JA4 was accepted (failures: %v)", bad)
	}
}

func TestCheckH3RejectsAChangedSetting(t *testing.T) {
	c := perfectCapture()
	// The QPACK table capacity dropping to zero is the exact regression that
	// would follow from reverting internal/qpack's dynamic table, and it would
	// leave everything else about the connection working.
	c.H3Text = strings.Replace(c.H3Text, "1:65536", "1:0", 1)
	if bad := failures(checkH3(c)); !contains(bad, "http3.settings") {
		t.Errorf("a changed SETTINGS value was accepted (failures: %v)", bad)
	}
}

func TestCheckH3RejectsAMissingSetting(t *testing.T) {
	c := perfectCapture()
	c.H3Text = strings.Replace(c.H3Text, ";51:1", "", 1)
	if bad := failures(checkH3(c)); !contains(bad, "http3.settings") {
		t.Errorf("a missing SETTINGS entry was accepted (failures: %v)", bad)
	}
}

// TestCheckH3RejectsAMissingPriorityUpdate is the regression this whole file
// exists for, and it is the one that actually happened.
//
// The client sent a byte-correct PRIORITY_UPDATE at connection setup naming
// element 0. Every offline test passed. A live service reported the string
// below — three fields instead of four, the frame simply absent — because a
// frame about a stream that does not exist is not one anyone records.
func TestCheckH3RejectsAMissingPriorityUpdate(t *testing.T) {
	c := perfectCapture()
	c.H3Text = "1:65536;6:262144;7:100;51:1;GREASE|GREASE|m,a,s,p"

	bad := failures(checkH3(c))
	var found bool
	for _, name := range bad {
		if strings.HasPrefix(name, "http3.frames") {
			found = true
		}
	}
	if !found {
		t.Errorf("the fingerprint a client with no PRIORITY_UPDATE produces was "+
			"accepted (failures: %v)", bad)
	}
}

// TestSplitH3TextSurvivesAMissingFrame is why the parser does not index
// positionally.
//
// The frame list collapses when it is empty rather than coming through as an
// empty field, so the string has three parts instead of four. Reading part 3 as
// the frame list would then read the pseudo-header order as a frame and report
// a difference in the wrong place — sending you to look at the wrong layer.
func TestSplitH3TextSurvivesAMissingFrame(t *testing.T) {
	full, ok := splitH3Text("1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p")
	if !ok {
		t.Fatal("a four-field fingerprint did not parse")
	}
	if full.pseudo != "m,a,s,p" {
		t.Errorf("pseudo-header order = %q", full.pseudo)
	}
	if !contains(full.frames, "984832") {
		t.Errorf("frames = %v, want 984832", full.frames)
	}

	short, ok := splitH3Text("1:65536;6:262144;7:100;51:1;GREASE|GREASE|m,a,s,p")
	if !ok {
		t.Fatal("a three-field fingerprint did not parse")
	}
	if short.pseudo != "m,a,s,p" {
		t.Errorf("pseudo-header order = %q; a positional read would put a frame here",
			short.pseudo)
	}
	if len(short.frames) != 0 {
		t.Errorf("frames = %v, want none", short.frames)
	}
	if short.reserved != "GREASE" {
		t.Errorf("reserved frame = %q", short.reserved)
	}

	// And neither frame: two fields. This is what a silent control stream looks
	// like, and it has to read as a fingerprint rather than as a service that
	// reported nothing.
	bare, ok := splitH3Text("1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p")
	if !ok {
		t.Fatal("a two-field fingerprint did not parse")
	}
	if bare.pseudo != "m,a,s,p" || bare.settings == "" {
		t.Errorf("two-field fingerprint parsed as %+v", bare)
	}
	if bare.reserved != "" || len(bare.frames) != 0 {
		t.Errorf("two-field fingerprint invented frames: %+v", bare)
	}

	if _, ok := splitH3Text("nonsense"); ok {
		t.Error("a string with no fields parsed")
	}
}

// TestCheckH3RejectsASilentControlStream is the one this command exists for.
//
// The frames after SETTINGS are ignorable by any peer, so dropping them breaks
// nothing and fails no test anywhere else in the tree. A live server that
// reports what it received is the only thing that can notice.
func TestCheckH3RejectsASilentControlStream(t *testing.T) {
	c := perfectCapture()
	// Neither frame after SETTINGS: two fields, not four. A client that sent a
	// clean SETTINGS frame and nothing else produces exactly this.
	c.H3Text = "1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p"
	bad := failures(checkH3(c))
	if len(bad) == 0 {
		t.Fatal("a control stream that stopped at SETTINGS was accepted")
	}
	if !contains(bad, "http3.reserved_frame") {
		t.Errorf("the missing reserved frame was not named (failures: %v)", bad)
	}
	var sawFrame bool
	for _, name := range bad {
		if strings.HasPrefix(name, "http3.frames") {
			sawFrame = true
		}
	}
	if !sawFrame {
		t.Errorf("the missing PRIORITY_UPDATE was not named (failures: %v)", bad)
	}
}

func TestCheckH3RejectsAReorderedPseudoHeaderList(t *testing.T) {
	c := perfectCapture()
	// a,m,s,p rather than m,a,s,p — what an implementation emitting the
	// pseudo-headers in RFC order, or in upstream's, produces.
	c.H3Text = strings.Replace(c.H3Text, "m,a,s,p", "a,m,s,p", 1)
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
	if len(checks) < 3 {
		t.Errorf("only %d checks were reported against an empty capture; a run that "+
			"looked at nothing should say so about everything", len(checks))
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
