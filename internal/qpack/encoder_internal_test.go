package qpack

import (
	"fmt"
	"io"
	"testing"
)

// TestIndexMapsDoNotOutliveTheirEntries covers the one thing in the encoder
// that is not a correctness rule and would therefore never fail a round trip.
//
// The encoder keeps two maps from header field to absolute index so it can find
// what is already in the table. Every lookup re-checks the table, so a stale
// entry is harmless to the wire — deleting the cleanup on eviction broke no
// test, which is how this gap was found. What it is not harmless to is memory:
// without the cleanup the maps grow for the life of the connection while the
// table they index stays the same handful of entries, and a long-lived
// connection making varied requests leaks steadily.
func TestIndexMapsDoNotOutliveTheirEntries(t *testing.T) {
	// Room for about six entries.
	tbl := NewEncoderTable(io.Discard, 220, 100)

	const requests = 2000
	for i := 0; i < requests; i++ {
		id := uint64(i) * 4
		if _, err := tbl.EncodeHeaderBlock(id, []HeaderField{
			{Name: "x-request-id", Value: fmt.Sprintf("%d", i)},
		}); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		// Release the section so the next request may evict.
		tbl.CancelStream(id)
	}

	tbl.mu.Lock()
	entries := len(tbl.table.entries)
	fields, names := len(tbl.byField), len(tbl.byName)
	tbl.mu.Unlock()

	// The maps index the table, so they cannot be far larger than it. byName is
	// keyed by name alone and this test uses one name, so it holds at most one.
	if fields > entries {
		t.Errorf("byField holds %d indices for a table of %d entries after %d requests",
			fields, entries, requests)
	}
	if names > entries {
		t.Errorf("byName holds %d indices for a table of %d entries after %d requests",
			names, entries, requests)
	}
	if entries == 0 {
		t.Fatal("the table ended up empty; this test is not exercising eviction")
	}
}
