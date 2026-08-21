# HTTP/3, and the identity it carries

Chrome, on its second visit to a Cloudflare-fronted host, reads `Alt-Svc: h3`
and moves to QUIC. This client never did. That was not a missing feature so
much as a standing signal: a connection that claims Chrome's ClientHello and
Chrome's HTTP/2 SETTINGS, and then declines h3 across ten thousand requests,
behaves like nothing that ships on a desktop.

It does now, and by the same route — a TCP request, an `Alt-Svc` header on the
response, and QUIC from the next request on. The route matters as much as the
bytes: a client whose first packet to an unknown host is a QUIC Initial is doing
something no browser does, however good that Initial looks.

The second reason is quieter and probably worth more. QUIC's fingerprint
surface is scored by far fewer stacks today than TLS-over-TCP is. Going there
is both the more faithful path and, for now, the cleaner one.

## Where the fingerprint actually lives

Everything a server can read about our identity before a single response byte
comes back is in four places, and all four are ours to control byte for byte:

1. **The Initial datagram.** Long header: version, DCID/SCID lengths and
   values, token, packet-number length. Then the frame layout — CRYPTO,
   PADDING, whether a PING rides along — and the padding, which turned out to be
   to 1250 rather than the RFC's 1200. Chrome has a particular shape here and it
   is observable without decrypting anything, because Initial packet protection
   uses a published salt and the DCID from the clear header.

   The connection ID length belongs here too, and was not on this list until a
   test went looking: quic-go draws it at random between 8 and 20 bytes, which is
   legal and which nothing else does. Chrome's is always 8.
2. **The ClientHello inside the CRYPTO frame.** Cipher list, GREASE positions,
   key shares, extension set. This is `internal/ctls` again, with ALPN `h3`
   and one extension it has never had to emit: `quic_transport_parameters`
   (0x0039).
3. **The transport parameters in that extension.** The set and the values:
   `initial_max_data`, the three `initial_max_stream_data_*`, the stream
   limits, `max_udp_payload_size`, `max_idle_timeout`,
   `max_datagram_frame_size`, `initial_source_connection_id`,
   `version_information`, Google's `0x3128`, and one GREASE parameter.

   Their **order is not part of it**, and that correction is a measurement
   rather than a reading of the spec: this file first said the order was worth
   pinning, and the capture disproved it. Chrome shuffles the parameters per
   connection, exactly as it shuffles the ClientHello extensions. Emitting a
   fixed order is the distinguishable behaviour. See `reference.go`.
4. **HTTP/3 SETTINGS and QPACK.** The settings ids, their values, the order
   they are sent in, the reserved setting that rides along, and the reserved
   *frame* that follows on the control stream before any request. Then the
   pseudo-header order and the request header order, and QPACK's own indexing
   policy — which headers get inserted into the dynamic table and which go
   literal. That last one is the QUIC analogue of the HPACK policy leak on the
   h2 path: the library's default is not the browser's.

   All of it except the QPACK policy is now measured and pinned in `http3.go`.
   The GREASE that the QUIC ClientHello does *not* carry reappears here, which
   is the thing an implementation gets wrong by omission: a control stream that
   sends a clean SETTINGS frame and then goes quiet is distinguishable from
   Chrome before a single request byte is written.

   The QPACK policy turned out not to be a policy question at first. Two of the
   settings promise a 64 KiB dynamic table, and the library everyone uses does
   not implement one — so the choice was never "which headers to insert" but
   "implement the table or advertise zeroes and be a different fingerprint on
   the first frame". See `internal/qpack/FORK.md`.

Numbers 1 through 3 come out of one artifact — the raw bytes of Chrome's first
Initial datagram, which `tools/capture` collects from a real Windows machine.

Number 4 could not come from there: SETTINGS travels in 1-RTT packets and needs
the traffic keys. It came instead from a server that reports what it received —
`quic.browserleaks.com` — which turned out to be the better source anyway. A
capture is the browser's own account of itself; a report from the far end is
what the far end actually saw, and this project's whole argument is that the
second kind of evidence is worth more.

That source also settled something a single decoder cannot: it recomputed the
QUIC JA4 independently and produced the same string this package derives from
the raw bytes. A bug in the decoder would otherwise have been invisible, since
`reference.go` and the tests both descend from it.

Same rule as `internal/ctls/reference.go`: the values get pinned against a
device capture and a test fails when they drift. Evidence, not assertion.

## Three layers

### `internal/quicgo` — a fork of quic-go

Vendored the way `internal/http2` vendors `golang.org/x/net/http2`, with a
`FORK.md` pinning every delta against upstream so the next rebase is a diff
rather than an archaeology exercise.

The base is **v0.59.1**, not the v0.61.0 this file first named: v0.60 and v0.61
declare `go 1.25` and this repository is on 1.24, and bumping the language
version to pick up a dependency is a change to everything in the tree rather
than to one fork. The reasoning is in `FORK.md` so it can be revisited when the
repository moves.

The package is `internal/quicgo` rather than `internal/quic` because
`internal/quic` already existed and does something else: it is the reference and
the decoder — the half that *reads* Chrome's bytes, which is what everything
else is checked against.

Writing a QUIC transport from nothing is loss recovery, congestion control,
ACK range management, flow control, stream state machines, key updates, path
validation, and version negotiation — the parts where the bugs live, and none
of them is where the fingerprint is. The fork buys all of that and leaves the
four surfaces above fully under our control.

What the fork changes:

- The TLS layer. quic-go drives `crypto/tls`'s QUIC API (`tls.QUICConn`); it
  gets `internal/ctls` instead, so the ClientHello is ours.
- Initial packet construction: the datagram size, the connection ID length, and
  the chaos protector's shuffled CRYPTO fragments among PING and PADDING. This
  one replaced something rather than adding to nothing — quic-go v0.59 has its
  own ClientHello scrambling, and being the only stack that produces *that*
  shape is worse than sending one plain frame.
- Transport parameter encoding: the set, the values, the reserved parameter,
  and the fact that the order is shuffled per connection.
- The HTTP/3 layer, which is in the same fork under `http3/`.

What it deliberately does not change, yet: ACK policy, pacing and congestion
control. These are observable too — a stack that acknowledges on a different
schedule than Chrome is distinguishable to anyone looking — but they are
second-order next to the four surfaces above, and they are the part a fork
lets us come back to later without having paid for it up front.

### `internal/ctls` — a QUIC handshake mode

This is the interesting half, and it is smaller than it looks, because the
package is already factored along the line QUIC needs.

`crypto.go`'s `tlsKeySchedule` is the TLS 1.3 key schedule and nothing else —
HKDF-Extract, `hkdfExpandLabel`, `deriveHandshakeSecrets`,
`deriveMasterSecrets`. QUIC uses that schedule unchanged; it only takes the
traffic secrets somewhere else. What is needed is accessors, not new
derivation.

`handshakeReader` is already a message-layer reassembler with no knowledge of
records: `add(data []byte)` takes payload bytes, `next()` yields one complete
handshake message. That is precisely the shape a CRYPTO frame stream wants.

`hello.go` and `chrome_hello.go` emit ClientHello bytes and take their
extensions as data. Adding 0x0039 is additive, and it goes through the same
per-connection shuffle the other Chrome extensions do.

So the split is:

- Lift the message-processing loop out of `handshakeState.run()` so it reads
  from `handshakeReader` and writes outbound handshake messages to a sink,
  rather than reading and writing records on a `net.Conn`.
- Publish traffic secrets per encryption level as they are derived, which is
  what QUIC's packet protection consumes.
- Skip ChangeCipherSpec — RFC 9001 forbids it.
- Report fatal alerts as `CONNECTION_CLOSE` with error `0x0100 + alert` rather
  than as an alert record. The reasoning in `handshake()`'s doc comment carries
  over unchanged: a browser says why before it leaves.

The TCP path keeps the record layer it has. Nothing about `Conn` changes.

### `internal/quicgo/http3` and `internal/qpack`

Control stream, QPACK encoder/decoder streams, SETTINGS, request/response
framing.

This was going to be a new `internal/http3`, and is not: quic-go ships an
`http3` package and vendoring it separately would have meant a second copy of
the same 5000 lines with the same import rewriting. It is a delta on the fork
instead.

`github.com/quic-go/qpack` is vendored alongside as `internal/qpack`, for a
stronger reason than the one this file first gave. The insertion policy is
indeed part of the fingerprint — but upstream has no dynamic table at all, and
the SETTINGS this profile sends promise one. That makes the fork a correctness
requirement rather than a fidelity one, which is the difference between a
client that looks slightly wrong and one that fails against any server taking
its word.

## Order of work

1. ~~`tools/capture` output → decode the Initial, write
   `internal/quic/reference.go` with the transport parameters, the H3 settings
   and the JA4 for `q13…`, and the tests that pin them.~~ Done, across
   `initial.go`, `clienthello.go`, `reference.go` and `http3.go`, with three
   captures under `testdata` and 35 tests. Three corrections came out of it and
   are recorded where they belong: the transport parameter order is shuffled
   rather than stable, `0x3127` is `initial_rtt` and therefore a path
   measurement that must never be pinned, and `google_connection_options` is
   per-origin rather than per-client.
2. ~~`internal/ctls` QUIC handshake mode, tested offline against the captured
   ClientHello bytes before anything is dialled.~~ Done: `quic_hello.go` and
   `quic_handshake.go`, with the six differences from the TCP hello written
   down where they are made. Two things the offline tests could not have found
   turned up as soon as a socket was involved — a server sends its session
   tickets immediately, and our hello does not fit in one datagram.
3. ~~Vendor quic-go + qpack, wire in `ctls`, get one handshake to complete.~~
   Done for quic-go: `internal/quicgo`, four deltas over 173 files, all of them
   listed in `FORK.md`. A whole connection now completes over a real UDP socket
   against an upstream quic-go server, and the datagrams that leave the socket
   are decoded by this package and held to `reference.go` — the hello's JA4, the
   transport parameters and their moving order, the datagram size, the
   connection ID lengths, and the fragment/PING/PADDING shape of the flight.
   And for qpack: `internal/qpack`, which had to grow a dynamic table because
   this profile's SETTINGS promise one — see its `FORK.md` for why that is a
   correctness problem rather than a fidelity one.
4. ~~The HTTP/3 layer and one GET. The control stream, the QPACK streams, and
   SETTINGS **plus the reserved frame and the PRIORITY_UPDATE that follow
   it**.~~ Done, as a delta on the vendored `internal/quicgo/http3` rather than
   a new package: the import paths were already rewritten, so a second vendor
   step would have been a second copy of the same 5000 lines. A whole request
   now completes over a real UDP socket against an upstream quic-go server.
5. ~~`cmd/fpcheck -h3` — the same PASS/FAIL-per-layer report the TCP path
   gets.~~ Done. Two of its checks cannot be made any other way: the frames
   after SETTINGS exist to be ignored, so nothing fails when they stop being
   sent, and the header order is invisible to a handler because `net/http`
   gives it a map.
6. ~~`send -h3` / Alt-Svc discovery, then the load path.~~ Done, as `-http3`
   and `-no-http3`, with discovery the default: HTTP/3 is used once a host has
   offered it in Alt-Svc, which is how a browser gets there. A client whose
   first packet to an unknown host is a QUIC Initial is doing something no
   browser does, whatever that Initial looks like.

## What is still only text

`internal/quic/http3.go` is transcribed from one report of one Chrome session.
Everything else in this package was decoded from captured bytes and, for the
JA4, agreed with by a third party; the HTTP/3 half has this repository's tests
proving the client emits those values, which is circular. `cmd/fpcheck -h3`
against a live service is what breaks the circle, and it has not been run
against one from here — this environment has no egress to reach it.

The same applies, smaller, to `internal/qpack`: RFC 9204's Appendix B carries
worked examples with exact bytes and they are the check that package is missing.
See its `FORK.md`.

## Not first

0-RTT, connection migration, HelloRetryRequest over QUIC, and matching Chrome's
ACK and pacing behaviour. Each is real; none blocks a correct first handshake,
and taking them early would mean debugging them through a stack that does not
yet work at all.

Datagram support was on this list and came off it early, because it turned out
not to be a feature at all: `max_datagram_frame_size` is one of the transport
parameters Chrome sends, and its HTTP/3 SETTINGS carry `H3_DATAGRAM=1`.
Advertising one without the other announces a capability at one layer and denies
it at the next, which is more distinctive than either.
