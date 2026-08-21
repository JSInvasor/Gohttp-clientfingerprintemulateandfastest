# internal/quicgo — vendored fork of github.com/quic-go/quic-go

## Base

- **Upstream:** `github.com/quic-go/quic-go`
- **Version:** `v0.59.1`
- **Licence:** MIT, carried verbatim in `LICENSE`

As with `internal/http2`, the version is recorded here because nothing else
records it: the code is vendored, so `go.mod` says nothing about which release
this came from.

### Why v0.59.1 rather than the latest

v0.60.0 and v0.61.0 declare `go 1.25.0`. This repository is on `go 1.24`, and
bumping the language version to pick up a dependency is a change to everything
in the tree rather than to this fork. v0.59.1 is the newest release that
declares `go 1.24`, so it is the base until the repository moves.

That is the whole reason. If the repository goes to 1.25, rebasing onto v0.61
or later is a mechanical step, and the delta this fork carries is small enough
(see below) that it should stay mechanical.

## What was vendored, and what was left behind

Kept: the root package, `internal/`, `quicvarint/`, `http3/`, `qlog/`,
`qlogwriter/` and `metrics/`.

Dropped:

- `example/`, `fuzzing/`, `integrationtests/`, `interop/`, `testutils/` — none
  of it is reachable from the client, and all of it pulls in dependencies this
  repository does not otherwise carry.
- Every `_test.go` file, and the generated `mock_*.go` files beside them. They
  need `testify` and `go.uber.org/mock`; the tests that matter here are the
  ones in `internal/quic` and `internal/ctls`, which exercise this fork through
  the client rather than in isolation.
- `internal/synctest`. It is test-only scaffolding around `testing/synctest`,
  which is a Go 1.25 package: keeping it would have reintroduced the version
  constraint that chose v0.59.1 in the first place.

## Verifying it is still a clean copy

Every vendored file is byte-identical to upstream once the import path rewrite
is undone. At the vendoring commit that was 173 files and zero differences, and
it is worth re-checking after any change:

```sh
Q=$(go env GOMODCACHE)/github.com/quic-go/quic-go@v0.59.1
M=github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest
for f in $(find internal/quicgo -name '*.go'); do
  rel=${f#internal/quicgo/}
  diff <(sed "s|$M/internal/quicgo|github.com/quic-go/quic-go|g" "$f") "$Q/$rel" \
    >/dev/null || echo "DIFFERS: $rel"
done
```

Anything that prints is a delta, and every delta belongs in the list below.

## Deltas

### 1. Import paths

Every `github.com/quic-go/quic-go` import is rewritten to
`github.com/JSInvasor/.../internal/quicgo`. Mechanical, applies to every file,
and reversed by the check above.

### 2. The TLS stack, on the client side only

Two files added and one changed, out of 173.

**`internal/handshake/ctls_adapter.go` (new).** quic-go talks to `crypto/tls`
through eight methods on `*tls.QUICConn`. This names them as an interface —
which `*tls.QUICConn` satisfies as written — and adds one implementation beside
it that drives `internal/ctls`. The translation is nearly one to one because
`internal/ctls`'s QUIC API was written against `crypto/tls`'s on purpose.

Two places where the two lifecycles genuinely differ, and both are handled here
rather than by bending either side:

- `crypto/tls` takes its transport parameters after construction and
  `internal/ctls` takes them at construction, so they are held until `Start`.
- The peer's transport parameters arrive in EncryptedExtensions.
  `internal/ctls` exposes them as state; quic-go expects an event. The
  transition is synthesised once, ahead of the next write, because quic-go
  needs them before it can use the connection.

**`internal/handshake/crypto_setup.go` (changed).** Two edits: the `conn` field
becomes the interface instead of `*tls.QUICConn`, and the client constructor
calls `newCTLSClient` instead of `tls.QUICClient`. Nothing else in the file
moves.

**`ctls_adapter_test.go` (new).** A whole connection over a real UDP socket
against an upstream quic-go server on `crypto/tls`, plus a test that records
the datagrams leaving the machine and decodes them with `internal/quic` to
confirm the ClientHello on the wire carries Chrome's JA4.

The server path is untouched and still runs on `crypto/tls`. This is a client
library; a server here has no fingerprint to emulate, and forking a second code
path to gain nothing would pay the rebase cost twice.

### 3. The client's transport parameters

Both halves, because either alone would be incoherent: a transport parameter is
a promise about what this endpoint accepts, and quic-go enforces the same fields
internally for flow control. Advertising Chrome's numbers while keeping its own
would tell the peer one thing and do another.

**`internal/wire/chrome_transport_parameters.go` (new).** The encoding. Four
things differ from upstream's `Marshal`, all measured against the captures:

- The parameters are shuffled. Upstream emits a fixed order with its greased
  value always first, which is a constant on the wire; three captures of Chrome
  produced three unrelated orders.
- `version_information` (0x11) is sent, with QUIC v1 and one reserved version in
  an order that also moves. Upstream does not send it at all.
- `google_connection_options` (0x3128) is sent, with the short `ORIG` value a
  first connection carries.
- Four parameters upstream sends are omitted because Chrome omits them:
  `ack_delay_exponent`, `max_ack_delay`, `disable_active_migration` and
  `active_connection_id_limit`. Each falls back to the RFC's default, which is
  what a peer applies to Chrome today.

The GREASE parameter stays but is reshaped: upstream's one-byte multiplier and
sub-16 length give a short id and often an empty value, where Chrome's is an
eight-byte varint id with eleven to fifteen bytes of value.

**`internal/wire/transport_parameters.go` (changed).** One branch at the top of
`Marshal`: the client goes to the above, the server stays upstream's.

**`connection.go` (changed).** The client's limits become Chrome's — 6 MiB
stream windows, 15 MiB connection window, 100 bidi and 103 uni streams, a 30
second idle timeout, a 1472-byte max UDP payload — and the four parameters
Chrome omits are left at their zero values so the encoder drops them. The
datagram parameter is now sent unconditionally, because Chrome always sends it
and because it is the transport half of a pair: Chrome's HTTP/3 SETTINGS carry
`H3_DATAGRAM=1`, and advertising one without the other announces a capability at
one layer and denies it at the next.

**`internal/wire/datagram_frame.go` (changed).** `MaxDatagramSize` goes from
upstream's 16383 to Chrome's 65536. The value is enforced in both directions and
raising it keeps them honest: `Conn.handleDatagramFrame` closes the connection on
anything larger, so advertising 65536 while accepting 16383 would promise a size
this endpoint then treats as a protocol violation. The send side is bounded
separately by the peer's own advertised limit and the path MTU, so this does not
make the client send larger datagrams than a peer asked for.

### 4. The shape of the first flight

Everything a QUIC client sends before the handshake completes is readable to
anyone on the path: an Initial packet is protected under keys derived from a
salt published in RFC 9001. So the arrangement of the first flight is a
fingerprint in its own right, separate from the ClientHello inside it, and it is
one two stacks can differ on while agreeing on every byte of the hello.

**`chrome_initial.go` (new).** All of it, so that the four files it changes
carry a few lines each. The distribution is not here either: cutting well took
four corrections against the captures, so there is one copy of it, in
`internal/quic/chaos.go`, and both this and the standalone builder call it.

What differs from upstream, all measured off the socket by
`ctls_adapter_test.go` rather than asserted:

- **Datagram size.** 1250 bytes, Chrome's, against upstream's 1280 and the RFC's
  floor of 1200. `connection.go` replaces the default only — a caller that set
  `InitialPacketSize` asked for a size, and path MTU is a reason to override this
  that has nothing to do with fingerprints.
- **The Destination Connection ID.** Eight bytes. Upstream draws the length
  uniformly from 8 to 20, which is legal and which nothing else does; only the
  length is pinned, since the value is what the Initial keys come from.
- **The ClientHello's framing.** Cut into eight to twenty pieces, shuffled, with
  PING frames among them and padding in several runs rather than one stretch
  before the frames.

The last of those replaces something, rather than adding to nothing. quic-go
v0.59 has its own ClientHello scrambling — `crypto_stream.go` cuts the hello in
at most two places, at the SNI and at the ECH extension. That is a smaller and
far more regular signature than Chrome's, and being the only stack that produces
it is worse than sending one plain CRYPTO frame.
`QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING` still turns the whole thing off, which
is worth keeping: a way to send the flight plainly is how you tell a transport
bug from a fingerprint one.

The four changed files: `crypto_stream.go` routes the client's initial stream
through it, `packet_packer.go` counts the PINGs against the same budget as the
fragments and breaks up the padding after the frames are shuffled, `client.go`
generates the connection ID, and `connection.go` sets the datagram size.

Loss recovery is untouched, and that is why this is wired in rather than handed
over: `internal/quic/packet.go` builds whole datagrams, but a CRYPTO frame
quic-go did not create is one it cannot retransmit. The fragments are real
`wire.CryptoFrame`s with the packer's own handler, so a lost Initial is
recovered the way upstream recovers it.

### Not yet delta'd

ACK policy, pacing and congestion control, as below. Two smaller ones worth
naming because they are visible and currently upstream's:

- 0-RTT. The shape is pinned in `internal/quic/reference.go`
  (`Chrome151QUICResumed`) but `internal/ctls` has no QUIC ticket store, so
  `ctls_adapter.go`'s `StoreSession` refuses rather than pretending.
- HelloRetryRequest over QUIC. `internal/ctls` returns a named error instead of
  half an implementation. The chaos protector already falls back to plain
  framing for a second flight, so this is the TLS side only.

## Why it is forked

The same reason `internal/http2` is: the QUIC and HTTP/3 fingerprints are made
of things the library does not expose, and cannot be made to expose without
being a different library.

The TLS ClientHello is the sharp end of it. quic-go drives `crypto/tls`'s QUIC
API, and `tls.QUICConn` is a concrete type rather than an interface — there is
no seam to pass a different TLS implementation through. The call sites are all
in `internal/handshake/crypto_setup.go`, which is under `internal/` and so
unreachable from outside the module even if there were.

That was measured rather than assumed before any of this was copied: across the
whole tree, `tls.QUICClient`, `tls.QUICConn` and `tls.QUICEvent` appear in
exactly one non-test file. The fork is 33,000 lines so that one file can change.

What the fork is for, in the order the work goes:

- **The TLS layer.** `internal/ctls` replaces `crypto/tls`, so the ClientHello
  is Chrome's rather than Go's. The two disagree about almost everything
  visible — see `internal/ctls/quic_hello.go` for the six differences and
  `internal/quic/reference.go` for what they are checked against.
- **Initial packet construction.** Chrome pads to 1250 bytes where the RFC
  requires 1200, uses an eight-byte connection ID where upstream draws a random
  length, and does not send its ClientHello as one CRYPTO frame: Google's chaos
  protector cuts it into shuffled fragments interleaved with PING and PADDING.
  `internal/quic/chaos.go` decides the shape; delta 4 above puts quic-go's own
  packets in it.
- **Transport parameter encoding.** The set, the values, the reserved
  parameter, and the fact that the order is shuffled per connection.
  `internal/quic/transportparams.go`.

Deliberately not changed, for now: ACK policy, pacing and congestion control.
These are observable — a stack that acknowledges on a schedule Chrome does not
use is distinguishable to anyone looking closely — but they are second-order
next to the ClientHello and the first flight, and keeping them upstream is what
makes the rebase story above credible.
