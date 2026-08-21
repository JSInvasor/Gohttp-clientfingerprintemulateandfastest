# internal/qpack — vendored fork of github.com/quic-go/qpack

## Base

- **Upstream:** `github.com/quic-go/qpack`
- **Version:** `v0.6.0`
- **Licence:** MIT, carried verbatim in `LICENSE.md`

As with `internal/http2` and `internal/quicgo`, the version is recorded here
because nothing else records it: the code is vendored, so `go.mod` says nothing
about which release this came from.

## What was vendored, and what was left behind

Kept: `header_field.go`, `varint.go`, `encoder.go`, `decoder.go` and
`static_table.go` — the whole of the package, about 620 lines.

Dropped: every `_test.go` file, and `example/`, `fuzzing/` and `interop/`. The
tests need `testify`; the interop suite needs a git submodule of QIF files that
is not checked out here. What replaces them is in `internal/qpack`'s own tests,
which is the better trade in this case rather than merely the cheaper one: the
upstream tests cover a decoder that rejects the dynamic table, and this fork
exists to add one.

No import path rewriting was needed. The package imports only the standard
library and `golang.org/x/net/http2/hpack`, which this repository already
depends on.

## Verifying it is still a clean copy

At the vendoring commit every file was byte-identical to upstream. It is worth
re-checking after any change:

```sh
Q=$(go env GOMODCACHE)/github.com/quic-go/qpack@v0.6.0
for f in internal/qpack/*.go; do
  rel=$(basename "$f")
  [ -f "$Q/$rel" ] || { echo "NEW:     $rel"; continue; }
  diff "$f" "$Q/$rel" >/dev/null || echo "DELTA:   $rel"
done
```

Anything that prints is a delta, and every delta belongs in the list below.

## Deltas

### 1. The decoding half of the dynamic table

Three files added and one changed. `header_field.go`, `varint.go` and
`static_table.go` are untouched.

**`dynamic_table.go` (new).** The table itself and the index arithmetic. There
are two tables on a connection and they are not the same table — one holds what
the peer inserted and this endpoint reads, the other holds what this endpoint
inserted and the peer reads — so the type is shared and the rules that differ
live with the code that applies them.

Also the Required Insert Count encoding (RFC 9204 sections 4.5.1.1 and
4.5.1.2), which is the piece of QPACK that is easy to get subtly wrong: the
count is sent modulo twice the table's maximum entry count so the prefix stays
short, and recovering it needs the decoder's own progress to pick between
candidates.

**`instructions.go` (new).** The encoder and decoder streams (sections 4.3 and
4.4). Upstream needs neither: with no dynamic table there is nothing to insert
and nothing to acknowledge, so a header block is a pure function and the
connection carries no QPACK state. Everything here separates "not enough bytes
yet" from "these bytes are wrong", because a stream delivers instructions in
arbitrary chunks and treating the first as the second closes working
connections at packet boundaries.

**`decoder_dynamic.go` (new).** The connection-level state: the peer's
insertions, the waiting a blocked header block has to do, and the
acknowledgements that go back. The acknowledgements are not optional
bookkeeping — they are what lets the peer's encoder evict, and a decoder that
never sends them stalls the peer rather than itself.

**`decoder.go` (changed).** The prefix is decoded rather than required to be
zero, and the four representations that can name a dynamic entry are
implemented: indexed and literal with a name reference relative to Base, and
the two post-base forms upstream rejects as an unexpected type byte.
`readString`'s body moved to `instructions.go` so the encoder-stream parser and
the header-block parser share one copy.

`NewDecoder` still returns a decoder with no dynamic table, and every path
above is guarded on that, so a caller that has not opted in gets upstream's
behaviour including its errors.

### 2. The encoding half

**`encoder_dynamic.go` (new).** This endpoint's own table, the insertions it
announces on its encoder stream, and the peer's acknowledgements that say what
may be evicted. `encoder.go` is untouched.

It is a whole-block API — `EncoderTable.EncodeHeaderBlock` — rather than an
extension of upstream's field-at-a-time `Encoder`, and that is forced rather
than chosen: a header block's prefix carries the Required Insert Count and Base,
and neither is known until every field has been encoded and it is settled which
entries were referenced. Upstream can write its prefix first because for a
static-only encoder both are always zero. The side effect is worth having on its
own — `encoder.go` stays byte-identical to upstream.

Two rules constrain what may enter the table, and both are enforced by declining
rather than failing, because an encoder is always free to spell a field out:

- An entry may not be evicted while a header block that referenced it is
  unacknowledged, or the peer resolves an index against something that is gone.
- Referencing an entry the peer has not inserted yet blocks that stream, and
  `SETTINGS_QPACK_BLOCKED_STREAMS` caps how many may be blocked at once.

Locking is split — `writeMu` around a whole encoding including the write to the
encoder stream, `mu` only while the table is touched. That is not tidiness: the
peer answers an insertion on its decoder stream, which comes straight back into
this type, so a lock held across the write deadlocks a caller that wires the two
streams together. The first version did exactly that.

### Not yet delta'd

Nothing in QPACK itself. What remains is above this package: `internal/http3`
has to open the two unidirectional streams, hand them to the types here, and
send SETTINGS that match what they were configured with.

## How this is checked, and where the evidence is weakest

Three ways, in descending order of how much they are worth:

1. **Interop with upstream** (`interop_test.go`). `github.com/quic-go/qpack` is
   still a dependency of this module, so the fork and the original can be
   imported side by side and made to read each other. This pins the static
   table, the literal representations, Huffman coding, the varint prefixes and
   the zero-dynamic prefix against an implementation nobody here wrote. One of
   those tests is stricter than a round trip: the two encoders have to produce
   the same bytes, because a fork that encoded differently but validly would
   pass a round trip and still be a different fingerprint.
2. **Arithmetic invariants** (`dynamic_table_test.go`). Absolute indices
   surviving eviction, the three kinds of relative index, and the Required
   Insert Count walked through several full wraparound cycles against every
   decoder position in the recoverable window.
3. **Wire-level decoding** (`decoder_dynamic_test.go`). Header blocks written
   out byte by byte with each byte decomposed in a comment, rather than
   produced by this package's own encoder, so that at least the bit layouts get
   a second look.
4. **Churn** (`encoder_dynamic_test.go`). A few thousand requests over small
   tables with values that change, streams that are cancelled, and
   acknowledgements that sometimes never come. State bugs here surface hundreds
   of requests after the mistake, which is why the scripted tests above cannot
   find them and this one did — twice.

Every rule in this package was checked by deliberately breaking it and
confirming a test noticed. Three did not, first time round, and each gap was
worth the trouble:

- The post-base arithmetic was duplicated in `decoder.go` instead of calling the
  table, so breaking the table failed only the table's own test. It calls the
  table now.
- The "do not evict what an unacknowledged block referenced" rule was masked in
  every test, because repeating header names meant each new block re-protected
  the entries it looked up. `TestEntriesSurviveUntilTheirBlockIsDecoded` uses
  header names that are disjoint between requests, which is the only shape where
  the rule is the thing standing in the way.
- Cleaning up the encoder's index maps on eviction is not a correctness rule at
  all — every lookup re-checks the table — so no round trip could fail without
  it. It is a leak, and `encoder_internal_test.go` measures it as one.

The gap is that (3) is not interop. **RFC 9204's Appendix B carries worked
examples with exact bytes**, and they would be a better check than anything
above, because they are an outside party's account of the same wire format.
They are not here: the RFC could not be fetched from the environment this was
written in, and transcribing hex from memory into a test would enshrine a
misremembering as a pinned constant. Adding them is the outstanding piece of
evidence for this package, in the same way `cmd/fpcheck -h3` is the outstanding
piece for `internal/quic/http3.go`.

## Why it is forked

Upstream says so itself, in its README: *"it does not support the dynamic table
and relies solely on the static table and string literals"*. That is a
reasonable place for a general-purpose library to stop. It is not a place this
client can stop, for two separate reasons, and it is worth keeping them apart
because only one of them is about fingerprints.

**The first is correctness, and it is not optional.** Chrome's HTTP/3 SETTINGS
carry `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 65536` and
`SETTINGS_QPACK_BLOCKED_STREAMS = 100` — see `internal/quic/http3.go`. Those are
not requests; they are promises about what this endpoint's *decoder* will
accept. A server that believes them may encode a response against the dynamic
table, and upstream's decoder rejects a non-zero Required Insert Count outright:

```go
if requiredInsertCount != 0 {
    return HeaderField{}, errors.New("expected Required Insert Count to be zero")
}
```

So sending Chrome's numbers on top of upstream's decoder is not a small
infidelity that shows up in a fingerprint. It is a connection that works against
servers which happen not to use the dynamic table and fails against those that
do, which is worse than either being honest or being correct.

The alternative was to advertise zeroes, which is coherent and safe, and which
puts `1:0;6:262144;7:0` on the first frame of the control stream where Chrome
puts `1:65536;6:262144;7:100`. That is a difference visible before a single
request is made, and it cannot be split: the promise and the capability are the
same thing.

**The second is the fingerprint, and it follows from the first.** An encoder
that has a dynamic table available and never uses it leaves its encoder stream
silent, which is its own signal. Chrome's is not.
