# internal/http2 — vendored fork of golang.org/x/net/http2

## Base

- **Upstream:** `golang.org/x/net/http2`
- **Version:** `v0.33.0`

This is recorded here because it is not derivable from anywhere else. The code
is vendored, so the `golang.org/x/net` requirement in `go.mod` says nothing
about it — the two happen to match today and can drift apart at any bump.

Verified by diffing every non-test file against
`$(go env GOMODCACHE)/golang.org/x/net@v0.33.0/http2`: the file sets are
identical and 17 of the 23 files are byte-for-byte unchanged.

To re-check after any upstream bump:

```sh
UP=$(go env GOMODCACHE)/golang.org/x/net@v0.33.0/http2
for f in internal/http2/*.go; do
  b=$(basename "$f")
  [ -f "$UP/$b" ] && diff -q "$UP/$b" "$f"
done
```

## Why it is forked

The HTTP/2 fingerprint (Akamai hash) is made of things `x/net/http2` does not
expose: the SETTINGS frame contents and their order, the WINDOW_UPDATE value,
the pseudo-header order, and the header order inside HEADERS frames. Emulating
a browser at that layer requires editing the transport, not configuring it.

## Local changes

Seven files differ from upstream. Anything not listed here is unmodified, so an
upstream bump only needs these to be re-applied.

| File | Change |
| --- | --- |
| `frame.go`, `server.go`, `write.go` | Import path only: `golang.org/x/net/http2/hpack` → the vendored `internal/http2/hpack`. |
| `headermap.go` | Adds the nine request headers this client sends that Go's table predates — the `sec-ch-ua*`, `sec-fetch-*`, `upgrade-insecure-requests` and `priority` names. A name missing from the table takes `asciiToLower`, which is a `strings.ToLower` and an allocation per header per request, so without this the profile the package exists to emit is also the one it encodes slowest. `TestCommonHeaderTableCoversTheProfileHeaders` fails if a re-apply drops them. |
| `http2.go` | Adds `SettingNoRFC7540Priorities` (0x9). Safari sends it, and the Akamai fingerprint includes it. |
| `client_conn_pool.go` | `getStartDialLocked` no longer de-duplicates concurrent dials to the same host. Upstream allows one in-flight dial per address, which caps connection-pool growth at one connection at a time and is the main throughput ceiling when thousands of workers start together. |
| `transport.go` | The bulk of the fork (~228 diff lines): configurable SETTINGS and their emission order, per-profile initial WINDOW_UPDATE, pseudo-header order, `HeaderOrder` for HEADERS frames, and `MaxStreamsPerConn`. |

`server.go` is carried unmodified apart from the import path. It is not used by
this client and exists only so the package compiles as a whole; deleting it is
possible but would enlarge the diff against upstream for no functional gain.

## Maintenance

Upstream security fixes do **not** arrive through `go get`. When
`golang.org/x/net` publishes an advisory affecting `http2`, the patch has to be
backported here by hand. Check the upstream diff for the affected files, apply
it, then re-run the verification command above and update the version recorded
at the top of this file.
