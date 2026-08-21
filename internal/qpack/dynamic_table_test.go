package qpack

import (
	"testing"
)

// The index arithmetic, tested against its own definition rather than against
// a round trip.
//
// A round trip through this package's own encoder and decoder would agree with
// itself however the indices were computed, so it cannot catch a consistent
// misreading. What can is stating the invariant separately from the code that
// maintains it: an entry's absolute index is fixed at insertion and is
// dropped+position for as long as the entry exists, whatever has been evicted
// since.

func TestAbsoluteIndicesSurviveEviction(t *testing.T) {
	// Room for exactly two of these: each is 1+1+32 = 34 bytes.
	var tbl dynamicTable
	tbl.setCapacity(68)

	insert := func(name, value string) {
		t.Helper()
		if err := tbl.insert(HeaderField{Name: name, Value: value}); err != nil {
			t.Fatalf("insert %q: %v", name, err)
		}
	}

	insert("a", "1") // absolute 0
	insert("b", "2") // absolute 1
	if got := tbl.insertCount(); got != 2 {
		t.Fatalf("insert count = %d, want 2", got)
	}
	insert("c", "3") // absolute 2, evicting absolute 0

	if got := tbl.insertCount(); got != 3 {
		t.Errorf("insert count = %d, want 3; eviction must not move it", got)
	}
	if _, err := tbl.at(0); err == nil {
		t.Error("absolute index 0 still resolves after being evicted")
	}
	for abs, want := range map[uint64]string{1: "b", 2: "c"} {
		hf, err := tbl.at(abs)
		if err != nil {
			t.Errorf("absolute %d: %v", abs, err)
			continue
		}
		if hf.Name != want {
			t.Errorf("absolute %d = %q, want %q", abs, hf.Name, want)
		}
	}
}

func TestRelativeAndPostBaseIndices(t *testing.T) {
	var tbl dynamicTable
	tbl.setCapacity(4096)
	for _, n := range []string{"a", "b", "c", "d"} { // absolutes 0..3
		if err := tbl.insert(HeaderField{Name: n}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// On the encoder stream, relative 0 is the newest entry.
	for rel, want := range map[uint64]string{0: "d", 1: "c", 2: "b", 3: "a"} {
		hf, err := tbl.atRelativeToInsertCount(rel)
		if err != nil {
			t.Errorf("encoder-stream relative %d: %v", rel, err)
			continue
		}
		if hf.Name != want {
			t.Errorf("encoder-stream relative %d = %q, want %q", rel, hf.Name, want)
		}
	}
	if _, err := tbl.atRelativeToInsertCount(4); err == nil {
		t.Error("encoder-stream relative index past the oldest entry resolved")
	}

	// On a request stream, relative 0 is the entry before Base. With Base 3
	// that is absolute 2, not the newest entry — which is the distinction the
	// whole Base mechanism exists to make.
	for rel, want := range map[uint64]string{0: "c", 1: "b", 2: "a"} {
		hf, err := tbl.atRelativeToBase(3, rel)
		if err != nil {
			t.Errorf("request-stream relative %d: %v", rel, err)
			continue
		}
		if hf.Name != want {
			t.Errorf("request-stream relative %d against base 3 = %q, want %q", rel, hf.Name, want)
		}
	}
	if _, err := tbl.atRelativeToBase(3, 3); err == nil {
		t.Error("request-stream relative index reached past Base")
	}

	// Post-base counts forward from Base instead, which is how a block reaches
	// entries inserted while it was being encoded.
	hf, err := tbl.atPostBase(3, 0)
	if err != nil {
		t.Fatalf("post-base 0 against base 3: %v", err)
	}
	if hf.Name != "d" {
		t.Errorf("post-base 0 against base 3 = %q, want d", hf.Name)
	}
	if _, err := tbl.atPostBase(3, 1); err == nil {
		t.Error("post-base index past the newest entry resolved")
	}
}

func TestEntryLargerThanTheTableIsRejected(t *testing.T) {
	var tbl dynamicTable
	tbl.setCapacity(64)
	err := tbl.insert(HeaderField{Name: "name", Value: string(make([]byte, 64))})
	if err == nil {
		t.Fatal("an entry larger than the table was accepted")
	}
	if tbl.insertCount() != 0 {
		t.Errorf("insert count moved to %d on a rejected insert", tbl.insertCount())
	}
}

func TestShrinkingTheCapacityEvicts(t *testing.T) {
	var tbl dynamicTable
	tbl.setCapacity(4096)
	for _, n := range []string{"a", "b", "c"} {
		if err := tbl.insert(HeaderField{Name: n}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	tbl.setCapacity(33) // room for one 1+0+32 entry
	if got := len(tbl.entries); got != 1 {
		t.Errorf("%d entries survived a shrink to one entry's worth", got)
	}
	if hf, err := tbl.at(2); err != nil || hf.Name != "c" {
		t.Errorf("the newest entry did not survive: %v %q", err, hf.Name)
	}
	tbl.setCapacity(0)
	if tbl.insertCount() != 3 {
		t.Errorf("insert count = %d after emptying the table, want 3", tbl.insertCount())
	}
	if len(tbl.entries) != 0 {
		t.Errorf("%d entries survived a capacity of zero", len(tbl.entries))
	}
}

// TestInsertCountSurvivesWraparound is the one piece of QPACK arithmetic that
// cannot be checked by inspection, and the one implementations get wrong.
//
// The Required Insert Count is not sent as itself. It is folded modulo twice
// the table's maximum entry count so the prefix stays short over a long
// connection, and the decoder recovers it from its own progress.
//
// It recovers it only inside a window, and getting that window right is most of
// the point. The first version of this test walked the decoder from "exactly
// caught up" to "maxEntries ahead" and failed at the far end — correctly, as it
// turned out. The recoverable range is
//
//	requiredInsertCount ∈ (totalInserts - maxEntries, totalInserts + maxEntries]
//
// which is a window of exactly fullRange, so rearranged for a fixed required
// count the decoder may be behind by up to maxEntries and ahead by at most
// maxEntries-1. One further and two candidates are equally valid and the
// decoder picks the larger, which is the right answer to a question this test
// was asking wrongly.
//
// Being behind is not an error, and that is worth stating: it means the
// encoder referenced entries whose insertions have not arrived yet, which is
// exactly what a blocked stream is and what SETTINGS_QPACK_BLOCKED_STREAMS
// budgets for.
func TestInsertCountSurvivesWraparound(t *testing.T) {
	const capacity = 220 // maxEntries = 6, so the values repeat every 12
	me := maxEntries(capacity)
	if me == 0 {
		t.Fatal("test capacity is too small to have a wraparound")
	}

	for req := uint64(1); req <= 5*2*me; req++ {
		encoded := encodeInsertCount(req, capacity)

		lo := uint64(0)
		if req > me {
			lo = req - me
		}
		for total := lo; total < req+me; total++ {
			got, err := decodeInsertCount(encoded, total, capacity)
			if err != nil {
				t.Fatalf("required %d encoded as %d, decoder at %d: %v", req, encoded, total, err)
			}
			if got != req {
				t.Fatalf("required %d encoded as %d, decoder at %d: decoded %d",
					req, encoded, total, got)
			}
		}
	}
}

func TestInsertCountZeroMeansNoDynamicReferences(t *testing.T) {
	if got := encodeInsertCount(0, 4096); got != 0 {
		t.Errorf("encodeInsertCount(0) = %d, want 0", got)
	}
	got, err := decodeInsertCount(0, 17, 4096)
	if err != nil {
		t.Fatalf("decodeInsertCount(0): %v", err)
	}
	if got != 0 {
		t.Errorf("decodeInsertCount(0) = %d, want 0", got)
	}
}

func TestInsertCountRejectsAnImpossibleValue(t *testing.T) {
	const capacity = 220 // maxEntries 6, full range 12
	if _, err := decodeInsertCount(13, 100, capacity); err == nil {
		t.Error("an encoded insert count past the full range was accepted")
	}
	if _, err := decodeInsertCount(1, 0, 0); err == nil {
		t.Error("a dynamic reference was accepted against a table of zero capacity")
	}
}
