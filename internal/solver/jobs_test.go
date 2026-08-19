package solver

import (
	"strings"
	"testing"
)

func TestNewBatchValidates(t *testing.T) {
	if _, err := NewBatch(nil, 2); err == nil {
		t.Error("an empty exit list was accepted")
	}

	// A missing id gets its index, so a caller that supplies none still gets
	// results it can tell apart.
	b, err := NewBatch([]Exit{{Proxy: ""}, {Proxy: ""}}, 2)
	if err != nil {
		t.Fatalf("NewBatch: %v", err)
	}
	if b.Exits[0].ID != "0" || b.Exits[1].ID != "1" {
		t.Errorf("ids = %q, %q; want the indices", b.Exits[0].ID, b.Exits[1].ID)
	}

	// The caller keys results by id, so an ambiguity here would land on a cookie.
	_, err = NewBatch([]Exit{{ID: "a"}, {ID: "a"}}, 1)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate ids = %v, want a refusal", err)
	}

	// A malformed proxy is caught before a browser is launched, and named with
	// the exit it belongs to rather than left to strand the exits behind it.
	_, err = NewBatch([]Exit{{ID: "good"}, {ID: "bad", Proxy: "http://nohost"}}, 1)
	if err == nil || !strings.Contains(err.Error(), "exit bad") {
		t.Errorf("malformed proxy = %v, want it named with its exit", err)
	}
}

// A batch shares one browser, so this bounds how many tabs run Cloudflare's
// JavaScript at once rather than how many browsers are up.
func TestBatchParallelIsClamped(t *testing.T) {
	exits := []Exit{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	cases := []struct{ requested, want int }{
		{0, 1}, {-5, 1}, {1, 1}, {2, 2}, {3, 3},
		{99, 3}, // never more workers than there is work
	}
	for _, tc := range cases {
		b, err := NewBatch(exits, tc.requested)
		if err != nil {
			t.Fatalf("NewBatch: %v", err)
		}
		if b.Parallel != tc.want {
			t.Errorf("parallel %d clamped to %d, want %d", tc.requested, b.Parallel, tc.want)
		}
	}
}
