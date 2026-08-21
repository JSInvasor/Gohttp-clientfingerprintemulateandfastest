# HTTP/3, and the identity it carries

Chrome, on its second visit to a Cloudflare-fronted host, reads `Alt-Svc: h3`
and moves to QUIC. This client never does. That is not a missing feature so
much as a standing signal: a connection that claims Chrome's ClientHello and
Chrome's HTTP/2 SETTINGS, and then declines h3 across ten thousand requests,
behaves like nothing that ships on a desktop.

The second reason is quieter and probably worth more. QUIC's fingerprint
surface is scored by far fewer stacks today than TLS-over-TCP is. Going there
is both the more faithful path and, for now, the cleaner one.

## Where the fingerprint actually lives

Everything a server can read about our identity before a single response byte
comes back is in four places, and all four are ours to control byte for byte:

1. **The Initial datagram.** Long header: version, DCID/SCID lengths and
   values, token, packet-number length. Then the frame layout — CRYPTO,
   PADDING, whether a PING rides along — and the padding to 1200. Chrome has a
   particular shape here and it is observable without decrypting anything,
   because Initial packet protection uses a published salt and the DCID from
   the clear header.
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
   they are sent in, the GREASE setting, and the order the control and QPACK
   encoder/decoder streams are opened in. Then the request header order, and
   QPACK's own indexing policy — which headers get inserted into the dynamic
   table and which go literal. That last one is the QUIC analogue of the HPACK
   policy leak on the h2 path: the library's default is not the browser's.

Numbers 1 through 3 come out of one artifact — the raw bytes of Chrome's first
Initial datagram, which `tools/capture` collects from a real Windows machine.
Number 4 comes from the same run's net-log, which reports SETTINGS and header
order semantically, and from the pcapng + keylog when we want the bytes.

Same rule as `internal/ctls/reference.go`: the values get pinned against a
device capture and a test fails when they drift. Evidence, not assertion.

## Three layers

### `internal/quic` — a fork of quic-go

Vendored the way `internal/http2` vendors `golang.org/x/net/http2`, with a
`FORK.md` pinning every delta against upstream so the next rebase is a diff
rather than an archaeology exercise. quic-go v0.61.0 is the base.

Writing a QUIC transport from nothing is loss recovery, congestion control,
ACK range management, flow control, stream state machines, key updates, path
validation, and version negotiation — the parts where the bugs live, and none
of them is where the fingerprint is. The fork buys all of that and leaves the
four surfaces above fully under our control.

What the fork changes:

- The TLS layer. quic-go drives `crypto/tls`'s QUIC API (`tls.QUICConn`); it
  gets `internal/ctls` instead, so the ClientHello is ours.
- Initial packet construction: padding, coalescing, connection-id lengths.
- Transport parameter encoding: order, and the GREASE entry.

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

### `internal/http3`

Control stream, QPACK encoder/decoder streams, SETTINGS, request/response
framing. `github.com/quic-go/qpack` gets vendored alongside for the same
reason `internal/http2/hpack` is vendored: the encoder's insertion policy is
part of the fingerprint, so it has to be ours to pin.

## Order of work

1. `tools/capture` output → decode the Initial, write `internal/quic/reference.go`
   with the transport parameters, the H3 settings and the JA4 for `q13…`, and
   the tests that pin them.
2. `internal/ctls` QUIC handshake mode, tested offline against the captured
   ClientHello bytes before anything is dialled.
3. Vendor quic-go + qpack, wire in `ctls`, get one handshake to complete
   against `cloudflare-quic.com`.
4. `internal/http3` and one GET.
5. `cmd/fpcheck -h3` — the same PASS/FAIL-per-layer report the TCP path gets,
   against a live server, so drift fails CI rather than going unnoticed.
6. `send -h3` / Alt-Svc discovery, then the load path.

## Not first

0-RTT, connection migration, datagram support, and matching Chrome's ACK and
pacing behaviour. Each is real; none blocks a correct first handshake, and
taking them early would mean debugging them through a stack that does not yet
work at all.
