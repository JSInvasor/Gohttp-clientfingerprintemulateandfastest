package qpack

import (
	"errors"
	"fmt"
)

// FORK DELTA. Not present upstream.
//
// QPACK's dynamic table (RFC 9204 section 3.2), and the index arithmetic that
// goes with it.
//
// There are two of these on a connection and they are not the same table. One
// holds what the peer's encoder has inserted, and this endpoint's decoder reads
// from it; the other holds what this endpoint's encoder has inserted, and the
// peer's decoder reads from it. They are filled by different streams, evicted
// under different rules — an encoder may not evict an entry the peer has not
// acknowledged, a decoder has nothing to acknowledge — and they drift apart in
// content. The type is shared because the storage and the indexing are the same;
// the rules that differ live with the code that applies them.
//
// The indexing is where implementations go wrong, so it is worth stating once
// rather than at each use:
//
//   - An entry's absolute index never changes. The first entry ever inserted is
//     0, and the count of insertions is therefore also the absolute index the
//     next insertion will take.
//   - On the encoder stream, a relative index counts back from the newest
//     entry: absolute = insertCount - 1 - relative.
//   - On a request stream, a relative index counts back from Base, which the
//     header block prefix carries: absolute = base - 1 - relative. Base is not
//     usually the insert count, which is the whole reason it is sent.
//   - A post-base index counts forward from Base instead:
//     absolute = base + postBase. It exists so that a header block can reference
//     entries the encoder inserted while it was encoding that very block.

// entryOverhead is what RFC 9204 section 3.2.1 adds to a name and value when
// accounting for the size of a table entry. It is an allowance for the
// implementation's own bookkeeping rather than anything on the wire, which is
// why the same 32 appears in HPACK and in HTTP/3's field-list size limit.
const entryOverhead = 32

var (
	errEntryTooLarge = errors.New("qpack: table entry larger than the table capacity")
	errNoSuchEntry   = errors.New("qpack: reference to a dynamic table entry that is not there")
)

// dynamicTable is a FIFO of header fields with a byte budget.
type dynamicTable struct {
	// entries is oldest first. The newest is the one most recently inserted,
	// and the oldest is the next to be evicted.
	entries []HeaderField

	// size is the sum of the entries' sizes, each including entryOverhead.
	size uint64

	capacity uint64

	// dropped is how many entries have been evicted over the life of the
	// table. It is what turns a position in entries into an absolute index:
	// entries[i] is absolute index dropped+i.
	dropped uint64
}

func entrySize(hf HeaderField) uint64 {
	return uint64(len(hf.Name)) + uint64(len(hf.Value)) + entryOverhead
}

// insertCount is the number of entries ever inserted, which is also the
// absolute index the next insertion will take.
func (t *dynamicTable) insertCount() uint64 {
	return t.dropped + uint64(len(t.entries))
}

// setCapacity resizes the table, evicting whatever no longer fits.
//
// RFC 9204 section 3.2.3 lets the encoder change the capacity at any time, up
// to the limit the decoder advertised in SETTINGS. Enforcing that limit is the
// caller's job, because only the caller knows what it advertised.
func (t *dynamicTable) setCapacity(c uint64) {
	t.capacity = c
	t.evictTo(c)
}

// insert adds an entry, evicting from the oldest end to make room.
func (t *dynamicTable) insert(hf HeaderField) error {
	sz := entrySize(hf)
	if sz > t.capacity {
		// RFC 9204 section 3.2.2 makes this an error rather than a silent
		// flush: an encoder that tries it has lost track of the capacity, and
		// every index it sends afterwards will be against a table this endpoint
		// does not have.
		return fmt.Errorf("%w: %d bytes into %d", errEntryTooLarge, sz, t.capacity)
	}
	t.evictTo(t.capacity - sz)
	t.entries = append(t.entries, hf)
	t.size += sz
	return nil
}

// evictTo drops entries from the oldest end until the table fits in size bytes.
func (t *dynamicTable) evictTo(size uint64) {
	for t.size > size && len(t.entries) > 0 {
		t.size -= entrySize(t.entries[0])
		t.entries = t.entries[1:]
		t.dropped++
	}
	if len(t.entries) == 0 {
		// Reclaim the backing array rather than letting the slice header walk
		// off the end of it forever.
		t.entries = nil
		t.size = 0
	}
}

// at returns the entry with the given absolute index.
func (t *dynamicTable) at(abs uint64) (HeaderField, error) {
	if abs < t.dropped || abs >= t.insertCount() {
		return HeaderField{}, fmt.Errorf("%w: absolute index %d, table holds %d to %d",
			errNoSuchEntry, abs, t.dropped, t.insertCount())
	}
	return t.entries[abs-t.dropped], nil
}

// atRelativeToInsertCount resolves an encoder-stream index, which counts back
// from the newest entry.
func (t *dynamicTable) atRelativeToInsertCount(rel uint64) (HeaderField, error) {
	ic := t.insertCount()
	if rel >= ic {
		return HeaderField{}, fmt.Errorf("%w: relative index %d with %d insertions",
			errNoSuchEntry, rel, ic)
	}
	return t.at(ic - 1 - rel)
}

// atRelativeToBase resolves a request-stream index, which counts back from Base.
func (t *dynamicTable) atRelativeToBase(base, rel uint64) (HeaderField, error) {
	if rel >= base {
		return HeaderField{}, fmt.Errorf("%w: relative index %d against base %d",
			errNoSuchEntry, rel, base)
	}
	return t.at(base - 1 - rel)
}

// atPostBase resolves a post-base index, which counts forward from Base.
func (t *dynamicTable) atPostBase(base, post uint64) (HeaderField, error) {
	return t.at(base + post)
}

// maxEntries is the most entries a table of this capacity could hold, which is
// what it would hold if every name and value were empty.
//
// It is not a limit on anything. RFC 9204 section 4.5.1.1 uses it as the
// modulus for encoding the Required Insert Count, so it has to be computed the
// same way on both sides or the two will disagree about which of several
// possible insert counts a header block meant.
func maxEntries(capacity uint64) uint64 { return capacity / entryOverhead }

// encodeInsertCount folds a Required Insert Count into the small number that
// goes in a header block prefix (RFC 9204 section 4.5.1.1).
//
// The count grows without bound over a connection's life, and sending it whole
// would mean a growing prefix on every request. Instead it is sent modulo twice
// the table's maximum entry count, which is unambiguous because the decoder
// knows how many insertions it has processed and the true value cannot be more
// than maxEntries away from that.
func encodeInsertCount(reqInsertCount, capacity uint64) uint64 {
	if reqInsertCount == 0 {
		return 0
	}
	return reqInsertCount%(2*maxEntries(capacity)) + 1
}

// decodeInsertCount is the inverse, and needs to know how many insertions this
// decoder has actually processed to pick the right one of the candidates.
func decodeInsertCount(encoded, totalInserts, capacity uint64) (uint64, error) {
	if encoded == 0 {
		return 0, nil
	}
	me := maxEntries(capacity)
	if me == 0 {
		return 0, errors.New("qpack: a header block references the dynamic table, but its capacity is zero")
	}
	fullRange := 2 * me
	if encoded > fullRange {
		return 0, fmt.Errorf("qpack: encoded insert count %d is outside the range 1 to %d", encoded, fullRange)
	}
	maxValue := totalInserts + me
	maxWrapped := (maxValue / fullRange) * fullRange
	req := maxWrapped + encoded - 1
	if req > maxValue {
		if req <= fullRange {
			return 0, fmt.Errorf("qpack: encoded insert count %d underflows", encoded)
		}
		req -= fullRange
	}
	if req == 0 {
		return 0, errors.New("qpack: encoded insert count resolved to zero")
	}
	return req, nil
}
