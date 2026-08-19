package http2

import (
	"net/http"
	"testing"
)

// The fork's local changes, pinned as properties rather than as a file list.
//
// FORK.md records what differs from upstream so a version bump knows what to
// re-apply, and it is a document — it was already wrong once, listing six files
// when seven differ. What it describes cannot be checked by reading it, so the
// changes that matter are checked here instead: an upstream re-apply that
// silently drops one fails a test rather than a code review.

// profileRequestHeaders is every header name the client's browser profiles put
// on a request. It is written out rather than imported because this package
// cannot see the parent one, and that separation is the point — a header added
// to a profile has to be added here too, which is the moment to add it to the
// common table as well.
var profileRequestHeaders = []string{
	"Accept",
	"Accept-Encoding",
	"Accept-Language",
	"Content-Length",
	"Content-Type",
	"Cookie",
	"Origin",
	"Priority",
	"Referer",
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile",
	"Sec-Ch-Ua-Platform",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
	"Sec-Fetch-User",
	"Upgrade-Insecure-Requests",
	"User-Agent",
}

// Every header the client sends on every request has to be in the common table.
//
// A name that misses it takes asciiToLower — a strings.ToLower and an
// allocation, per header, per request — so the cost lands on exactly the
// requests this package exists to make. Go's table predates Client Hints and
// Sec-Fetch, so nine of these are the fork's own addition and would be lost by
// an upstream re-apply that took headermap.go wholesale.
func TestCommonHeaderTableCoversTheProfileHeaders(t *testing.T) {
	buildCommonHeaderMapsOnce()

	var missing []string
	for _, h := range profileRequestHeaders {
		if _, ok := commonLowerHeader[h]; !ok {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		t.Errorf("these headers are sent on every request but miss the common table, "+
			"so each one costs a ToLower and an allocation per request: %v", missing)
	}
}

// lowerHeader has to answer from the table, not from the fallback, for the
// names above — and the ascii flag has to stay true either way.
func TestLowerHeaderUsesTheTable(t *testing.T) {
	buildCommonHeaderMapsOnce()

	for _, h := range profileRequestHeaders {
		lower, ascii := lowerHeader(h)
		if !ascii {
			t.Errorf("lowerHeader(%q) reported non-ascii", h)
		}
		if want := http.CanonicalHeaderKey(h); commonLowerHeader[want] != lower {
			t.Errorf("lowerHeader(%q) = %q, which did not come from the common table", h, lower)
		}
	}
}

// Safari's SETTINGS_NO_RFC7540_PRIORITIES is in the Akamai fingerprint, and the
// identifier is the fork's — upstream x/net/http2 at v0.33.0 does not define it.
// A re-apply that dropped it would not compile, but a re-apply that redefined it
// to another number would, and the fingerprint would move by one digit.
func TestNoRFC7540PrioritiesSettingID(t *testing.T) {
	if got := SettingNoRFC7540Priorities; got != 0x9 {
		t.Errorf("SETTINGS_NO_RFC7540_PRIORITIES = %#x, want 0x9 — the value Safari sends "+
			"and the Akamai string records as \"9:1\"", uint16(got))
	}
	if got := SettingNoRFC7540Priorities.String(); got == "" {
		t.Error("the setting has no name, so frame dumps will not show it")
	}
}

// The connection pool must not de-duplicate concurrent dials.
//
// Upstream allows one in-flight dial per address, so a pool starting cold grows
// one connection at a time however many workers are waiting — the throughput
// ceiling the fork exists to remove. The field upstream uses for that
// bookkeeping is gone here; this fails if it comes back.
func TestConnPoolDoesNotSerialiseDials(t *testing.T) {
	p := &clientConnPool{}
	if p.dialing != nil {
		t.Fatal("the pool has a dialing map again: concurrent dials to one host are " +
			"being de-duplicated, which caps pool growth at one connection at a time")
	}
}
