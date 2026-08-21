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

None yet. This commit is the unchanged copy, so that the diff which follows is
readable as a diff.

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
