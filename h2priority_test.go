package gofire

import (
	"testing"

	http2 "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/http2"
)

// TestNoRFC7540PrioritiesImpliesNoHeaderPriority pins a consistency rule that
// spans two settings which are easy to change independently.
//
// A client that advertises SETTINGS_NO_RFC7540_PRIORITIES=1 has told the server
// it does not use RFC 7540 priority signals; sending stream dependency and
// weight in every HEADERS frame afterwards contradicts that in the same
// connection. Whether the flag appears at all is decided by PriorityParam.IsZero
// in the frame writer, so a non-zero weight is the whole mechanism — which makes
// this cheap to get wrong and invisible in the Akamai fingerprint, since that
// string records standalone PRIORITY frames rather than the HEADERS flag.
//
// Safari's side is pinned to an iPhone 13 / Safari 26.5.2 capture whose HEADERS
// frame carries EndStream and EndHeaders only.
func TestNoRFC7540PrioritiesImpliesNoHeaderPriority(t *testing.T) {
	profiles := map[string]H2Profile{
		"safari": SafariIOS18H2Profile(),
		"chrome": Chrome146H2Profile(),
	}

	for name, p := range profiles {
		param := http2.PriorityParam{
			Weight:    p.PriorityWeight,
			Exclusive: p.PriorityExclusive,
		}
		declaresNo7540 := p.Settings.NoRFC7540Priorities == 1
		sendsPriority := !param.IsZero()

		if declaresNo7540 && sendsPriority {
			t.Errorf("%s: advertises NO_RFC7540_PRIORITIES=1 but puts RFC 7540 "+
				"priority (weight=%d exclusive=%v) in every HEADERS frame",
				name, p.PriorityWeight, p.PriorityExclusive)
		}
	}
}

// TestSafariHeadersCarryNoPriorityFlag states the capture-backed expectation
// directly, so a change to Safari's profile fails here even if the settings
// table changes alongside it and keeps the pair above self-consistent.
func TestSafariHeadersCarryNoPriorityFlag(t *testing.T) {
	p := SafariIOS18H2Profile()
	param := http2.PriorityParam{
		Weight:    p.PriorityWeight,
		Exclusive: p.PriorityExclusive,
	}
	if !param.IsZero() {
		t.Errorf("Safari HEADERS would carry the Priority flag (weight=%d, "+
			"exclusive=%v); the real device sends EndStream+EndHeaders only",
			p.PriorityWeight, p.PriorityExclusive)
	}
	if p.Settings.NoRFC7540Priorities != 1 {
		t.Error("Safari no longer advertises NO_RFC7540_PRIORITIES=1; the real " +
			"device does, and its Akamai fingerprint pins 9:1")
	}
}

// TestChromeHeadersCarryCapturedPriority pins the other direction.
//
// Chrome does not advertise NO_RFC7540_PRIORITIES, and a real Chrome 150 on
// Windows does send the HEADERS priority flag: weight 256, depends_on 0,
// exclusive. Nothing else in the suite covers these values, so without this a
// change that zeroed them — the same edit Safari legitimately needed — would
// pass silently and drop a field real Chrome sends on every request.
//
// The wire encoding is weight-minus-one (RFC 7540 §5.3.2), so the captured
// weight of 256 is stored as 255.
func TestChromeHeadersCarryCapturedPriority(t *testing.T) {
	p := Chrome146H2Profile()

	param := http2.PriorityParam{
		Weight:    p.PriorityWeight,
		Exclusive: p.PriorityExclusive,
	}
	if param.IsZero() {
		t.Fatal("Chrome HEADERS would carry no Priority flag; the real device " +
			"sends weight 256, depends_on 0, exclusive")
	}
	if p.PriorityWeight != 255 {
		t.Errorf("PriorityWeight = %d, want 255 (wire encoding of weight 256)", p.PriorityWeight)
	}
	if !p.PriorityExclusive {
		t.Error("PriorityExclusive = false; the captured frame sets exclusive=1")
	}
	if param.StreamDep != 0 {
		t.Errorf("StreamDep = %d, want 0 (captured depends_on)", param.StreamDep)
	}
	if p.Settings.NoRFC7540Priorities != 0 {
		t.Error("Chrome advertises NO_RFC7540_PRIORITIES; the real device does not, " +
			"and doing so would contradict the priority it sends in every HEADERS frame")
	}
}
