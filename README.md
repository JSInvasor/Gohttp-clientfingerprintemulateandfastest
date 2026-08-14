# gofire

Ultra high-performance Go HTTP client with **Safari (iPhone)** and **Chrome 151 (Windows)** TLS fingerprint emulation. Designed for **200-300k+ RPS** with full JA3/JA4 + HTTP/2 + header fingerprint bypass.

Both profiles are verified against real devices via tls.peet.ws. The captures are
committed under `cmd/fpcheck/testdata` and re-checked on every `go test`, so the
reference values are evidence rather than assertion.

## Features

- **Safari TLS Fingerprint** — Exact JA3/JA4 via custom TLS 1.3 (cipher suites, GREASE at 6 positions, X25519MLKEM768 + X25519 key share, no padding)
- **Chrome 151 TLS Fingerprint** — Per-connection extension shuffle, ALPS, ECH GREASE, ML-DSA signature algorithms
- **Safari HTTP/2 Fingerprint** — SETTINGS (MAX_CONCURRENT_STREAMS=100, NO_RFC7540_PRIORITIES=1), WINDOW_UPDATE, pseudo-header order (m,s,a,p)
- **Safari Headers** — Correct order, Sec-Fetch-* (no Sec-Fetch-User), Priority
- **200-300k+ RPS** — Worker pool pipeline, connection pre-warming, DNS cache
- **Pipeline Mode** — Fixed worker pool for sustained max throughput
- **PreConnect** — Pre-warm TLS connections before first request
- **DNS Cache** — Round-robin IP selection, configurable TTL
- **TCP Tuning** — TCP_NODELAY, TCP_QUICKACK, 256KB buffers (Linux)
- **Auto Decompression** — gzip, brotli, deflate, zstd
- **Cookie Jar** — Automatic cookie management
- **Proxy Support** — HTTP/SOCKS5

## Install

```bash
go get github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

func main() {
    // Emulate Safari on iPhone - that's it!
    client, err := gofire.Emulate(gofire.SafariIOS18)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    resp, err := client.Get("https://tls.peet.ws/api/all")
    if err != nil {
        log.Fatal(err)
    }

    text, _ := resp.Text()
    fmt.Println(text) // Safari fingerprint verified
}
```

## Maximum RPS (Pipeline Mode)

```go
client, _ := gofire.Emulate(gofire.SafariIOS18,
    gofire.WithMaxIdleConnsPerHost(2000),
    gofire.WithMaxIdleConns(20000),
    gofire.WithDNSCacheTTL(10 * time.Minute),
    gofire.WithTimeout(10 * time.Second),
)

// Pre-warm connections
ctx := context.Background()
client.PreConnect(ctx, "https://target.com", 100)

// Create pipeline with 3000 workers
pipeline := client.NewPipeline(3000)
defer pipeline.Close()

// Spray 100k requests at max speed
result := pipeline.Spray(ctx, "GET", "https://target.com", 100000)
fmt.Printf("RPS: %.0f\n", result.RPS)

// Or fire-and-forget for absolute max throughput
for i := 0; i < 1000000; i++ {
    pipeline.FireAndForget(ctx, "GET", "https://target.com", nil, nil)
}
```

## API Reference

### Creating Clients

```go
// Recommended: Emulate a real browser
client, err := gofire.Emulate(gofire.SafariIOS18)
client, err := gofire.Emulate(gofire.Chrome151)
client, err := gofire.Emulate(gofire.SafariIOS18, gofire.WithProxy("socks5://..."))

// Or with NewClient (defaults to Safari)
client, err := gofire.NewClient(gofire.WithTimeout(5 * time.Second))
```

### HTTP Methods

```go
resp, err := client.Get("https://example.com")
resp, err := client.Post("https://example.com", body, headers)
resp, err := client.PostJSON("https://example.com", jsonBody)
resp, err := client.Put("https://example.com", body, headers)
resp, err := client.Delete("https://example.com")
resp, err := client.Head("https://example.com")
resp, err := client.Do("PATCH", "https://example.com", body, headers)
resp, err := client.DoWithContext(ctx, "GET", "https://example.com", nil, nil)
```

### Response

```go
resp.StatusCode()            // int
text, err := resp.Text()     // string (auto-decompresses)
data, err := resp.Bytes()    // []byte
err := resp.JSON(&result)    // JSON decode
resp.Headers()               // http.Header
resp.GetHeader("X-Custom")   // string
resp.GetCookies()            // []*http.Cookie
resp.Close()                 // release resources
```

### Builder Pattern

```go
resp, err := client.BuildRequest().
    Method("POST").
    URL("https://api.example.com/data").
    Body([]byte(`{"key":"value"}`)).
    Header("Content-Type", "application/json").
    Header("Authorization", "Bearer token").
    Context(ctx).
    Send()
```

### Pipeline (Max RPS)

```go
pipeline := client.NewPipeline(3000)  // 3000 workers
defer pipeline.Close()

// With result
ch := pipeline.Send(ctx, "GET", url, nil, nil)
result := <-ch  // result.Response, result.Err, result.Latency

// Fire and forget (fastest)
pipeline.FireAndForget(ctx, "GET", url, nil, nil)

// Spray N requests
sprayResult := pipeline.Spray(ctx, "GET", url, 100000)
// sprayResult.RPS, .Success, .Failed, .Duration

// Real-time stats
fmt.Println(pipeline.Stats.TotalSent.Load())
fmt.Println(pipeline.Stats.TotalOK.Load())
fmt.Println(pipeline.Stats.TotalErr.Load())
```

### Connection Pre-warming

```go
// Pre-establish 100 TLS connections
client.PreConnect(ctx, "https://target.com", 100)
```

`PreConnect` opens the sockets, runs the TLS handshake and exchanges HTTP/2
SETTINGS, then parks the connections — the same thing a browser's
`<link rel="preconnect">` does. It sends no HTTP request, so nothing appears in
the target's logs until you make one.

## Verifying the fingerprint

The tests check the bytes this client emits against fingerprints captured from
real devices, but they can only prove it still emits what it was written to
emit. To check what a server actually sees — including through a proxy — run:

```bash
go run ./cmd/fpcheck                    # both profiles against tls.peet.ws
go run ./cmd/fpcheck -profile chrome
go run ./cmd/fpcheck -proxy socks5://user:pass@host:1080
go run ./cmd/fpcheck -frames            # also print the HTTP/2 frames
go run ./cmd/fpcheck -via-chromium -profile chrome   # diff against the solver's real browser
```

Each layer is reported as PASS or FAIL against the reference values in
`reference.go`, and the exit status is non-zero if anything drifted, so it can
gate CI.

### Checking against the browser the solver drives

If you use `solver/` to earn `cf_clearance`, the browser it launches and the
client that replays the cookie have to be the same browser. Cloudflare binds the
cookie to the issuing session's (UA, JA3/JA4, IP), so a mismatch produces a
cookie that works once, dies within seconds under load, and looks exactly like a
solver bug. That agreement used to be maintained by hand — `index.js` pinned a
User-Agent in a comment and nothing checked it, which is how it ended up pinned
to Chrome 147 while the Go profile moved to 151.

```bash
cd solver && npm install && cd ..
go run ./cmd/fpcheck -via-chromium -profile chrome
```

This launches the solver's own Chromium — same `puppeteer-real-browser` build,
same flags, from `solver/profile.js` — sends it to the fingerprint endpoint, and
reports two things: the browser against the pinned reference, then this client
against that same browser, field by field.

If Chromium is not on the default path, set `CHROME_PATH` to the binary.

A version difference between the box's Chromium and the emulated Chrome is
reported, not failed: Chrome's TLS layer went unchanged across 146–151, so what
decides is the `chromium.ja4` line beneath it. Add `-save chromium.json` to keep
the capture — it is a device capture like any other and can become the reference.

### Refreshing a reference from a real device

Browsers ship every six weeks or so, and a fingerprint pinned to an old release
eventually becomes its own signal. To re-capture:

1. Open <https://tls.peet.ws/api/all> in the real browser — Safari on the
   iPhone, or Chrome on Windows — and save the JSON (`iphone.json` say).
2. Diff this client against it:

   ```bash
   go run ./cmd/fpcheck -profile safari -compare iphone.json
   ```

Everything that differs is listed with both values. The TLS half is then updated
in `internal/ctls/reference.go` plus the corresponding builder, and the HTTP/2
and header halves in `fingerprint.go` and `headers.go`.

Capture on the same OS you intend to emulate, over a normal Wi-Fi or cellular
connection, and in a fresh tab: a reloaded page resumes the TLS session and
carries `pre_shared_key`, which adds an extension and shifts JA4.

Both captures behind the current references are committed —
`cmd/fpcheck/testdata/iphone-ios26.json` (iPhone 13, iOS 26.5.2) and
`chrome151-windows.json` (Chrome 151, Windows) — and the same checker runs over
them on every `go test`. That is what makes these numbers evidence rather than
assertion. Two things in the profiles come directly from those frames: Safari's
HEADERS carries `EndStream|EndHeaders` and no `Priority`, while Chrome's carries
`Priority` with weight 256, depends_on 0, exclusive 1.

Chrome's `ja3_hash` is deliberately not pinned. The capture reports one, but it
is a single draw from the per-connection extension permutation and the next
connection yields another; `ja4_r` and `peetprint` are pinned instead, since
both sort the extension list before rendering and so survive the shuffle.

One thing the capture shows that is *not* a constant: `accept-language`. The
reference device sends `tr-TR,tr;q=0.9` because it is a Turkish phone. The
default here is `en-US,en;q=0.9`; set `WithAcceptLanguage` to match wherever
your proxies exit, since bot scoring compares the two.

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `WithTimeout` | 30s | Total request timeout |
| `WithProxy` | - | HTTP/SOCKS5 proxy URL (applied to `https://` and `http://` alike) |
| `WithInsecureSkipVerify` | false | Skip TLS cert verification |
| `WithMaxIdleConnsPerHost` | 1000 | Idle connections per host |
| `WithMaxIdleConns` | 10000 | Total idle connections |
| `WithMaxConnsPerHost` | 0 (unlimited) | Max connections per host |
| `WithForceHTTP1` | false | Force HTTP/1.1 |
| `WithDisableRedirects` | false | Disable auto-redirects |
| `WithMaxRedirects` | 10 | Max redirect hops |
| `WithDNSCacheTTL` | 5m | DNS cache TTL |
| `WithDialTimeout` | 10s | TCP dial timeout |
| `WithTLSHandshakeTimeout` | 10s | TLS handshake timeout |
| `WithIdleConnTimeout` | 90s | Idle connection TTL |
| `WithAcceptLanguage` | en-US,en;q=0.9 | Accept-Language header |
| `WithWriteBufferSize` | 64KB | Per-connection write buffer |
| `WithReadBufferSize` | 64KB | Per-connection read buffer |
| `WithTCPFastOpen` | off | TCP Fast Open on Linux — saves an RTT, but no browser uses it |
| `WithTLSSessionResumption` | off | Offer a cached TLS 1.3 ticket as `pre_shared_key` — see below |

### TLS session resumption

Off by default. Chrome resumes, and a client that opens hundreds of connections
to one host and resumes none of them shows a pattern no browser produces — that
is the case for the feature. The case against turning it on blind is that
offering a PSK **changes the ClientHello**: it adds a 17th counted extension and
moves JA4 from `t13d1516h2` to `t13d1517h2`, so connections 2..n present a
different fingerprint from connection 1. The resumed shape here has been checked
against a Go `crypto/tls` server, not against a capture of real Chrome resuming
against a real edge, so it is opt-in until you have measured it on your target:

```go
client, _ := gofire.Emulate(gofire.Chrome151, gofire.WithTLSSessionResumption())
```

Tickets are scoped to the egress that earned them, so this is safe to combine
with `-proxy-file` / `SetProxyRotator`. A ticket is a credential the server
issued to one peer; offering it from a different exit IP tells the target those
exits are one session, which is the correlation a rotator exists to prevent.

## Performance Tuning

```bash
# System-level (run before your app):
ulimit -n 1000000
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
```

```go
client, _ := gofire.Emulate(gofire.SafariIOS18,
    gofire.WithMaxIdleConnsPerHost(5000),
    gofire.WithMaxIdleConns(50000),
    gofire.WithDNSCacheTTL(30 * time.Minute),
    gofire.WithIdleConnTimeout(120 * time.Second),
    gofire.WithDisableRedirects(),
    gofire.WithWriteBufferSize(128 * 1024),
    gofire.WithReadBufferSize(128 * 1024),
)

// Pre-warm 500 connections
client.PreConnect(ctx, "https://target.com", 500)

// Pipeline with 5000 workers
pipeline := client.NewPipeline(5000)
```

## Safari Fingerprint Details

### TLS (JA3/JA4)

Verified against a real iPhone 13 on iOS 26.5.2 via tls.peet.ws, and pinned by
`internal/ctls/safari_hello_test.go`:

- JA3 hash: `ecdf4f49dd59effc439639da29186671`
- JA4: `t13d2013h2_a09f3c656075_7f0f34a4126d`
- peetprint hash: `62b834de729e78a9f0ebd1dd099314a7`

Structure:

- TLS 1.3 with TLS 1.2 fallback (TLS 1.0/1.1 removed — Apple dropped them in iOS 13)
- 20 cipher suites + GREASE prefix (includes 3DES legacy ciphers). The TLS 1.3
  suites lead with AES-256-GCM (`0x1302`), not AES-128-GCM — JA3 is order-sensitive
- GREASE values at 6 positions: ciphers, first/last extension, key_share, supported_groups, supported_versions
- 15 extensions on the wire (13 counted by JA4): SNI, extended_master_secret, renegotiation_info, supported_groups, ec_point_formats, ALPN(h2,http/1.1), status_request, signature_algorithms, SCT, key_share, psk_key_exchange_modes, supported_versions, compress_certificate(zlib), + 2 GREASE
- Supported groups: GREASE + X25519MLKEM768 + X25519 + P-256 + P-384 + P-521
- key_share: GREASE + X25519MLKEM768 + X25519 (Apple ships post-quantum)
- 10 signature algorithms — `rsa_pss_rsae_sha384` (`0x0805`) genuinely appears
  twice on the wire; do not deduplicate it
- No padding extension (the 1216-byte MLKEM key share puts the ClientHello well
  past the range BoringSSL pads)
- No ALPS, no ECH, no session_ticket, no delegated_credentials, no record_size_limit

Extension order is fixed — Apple does not permute it, unlike Chrome.

> Every browser on iOS emits this same TLS fingerprint. Chrome (`CriOS`) and the
> Google app (`GSA`) were captured byte-identical to Safari, because iOS forces
> all of them onto Apple's networking stack; only the User-Agent differs. Use the
> `Chrome150` profile only for desktop Chrome.

### HTTP/2 (Akamai)
- ENABLE_PUSH: 0
- MAX_CONCURRENT_STREAMS: 100
- INITIAL_WINDOW_SIZE: 2097152
- NO_RFC7540_PRIORITIES: 1
- Connection WINDOW_UPDATE: 10420225
- Pseudo-header order: :method :scheme :authority :path (m,s,a,p)
- Akamai fingerprint: `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`
- Akamai hash: `c52879e43202aeb92740be6e8c86ea96`
- HEADERS frames carry **no** priority block. `NO_RFC7540_PRIORITIES: 1` says
  Safari does not use the RFC 7540 priority scheme, so attaching one anyway
  would contradict its own SETTINGS on every request. Priority travels in the
  `priority` request header instead. (Chrome is the opposite — see below.)

### Headers
- Exact Safari header order
- `User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5.2 Mobile/15E148 Safari/604.1`
  — the `iPhone OS 18_7` token is frozen by Apple and is correct even on iOS 26;
  only `Version/` tracks the real release
- `sec-fetch-dest` before `user-agent` (unique to Safari)
- `accept-encoding` LAST (Firefox/Chrome place it earlier)
- `accept-encoding: gzip, deflate, br, zstd`
- No `Upgrade-Insecure-Requests`, no `Sec-Fetch-User`, no `Sec-Ch-Ua`, no `TE`
- On HTTP/1.1 the header order is restored on the wire (net/http sorts
  alphabetically with no hook to intervene) and `Connection: keep-alive` is
  emitted right after `Host`. Go omits it — HTTP/1.1 is keep-alive by default —
  but every browser sends it, and its absence is a cheap library-not-a-browser
  tell on any h1-only host.

## Chrome 151 Fingerprint Details

Verified against a real Chrome 151 on Windows via tls.peet.ws. The capture is
committed at `cmd/fpcheck/testdata/chrome151-windows.json` and checked on every
`go test`, alongside `internal/ctls/chrome_hello_test.go`:

- JA4: `t13d1516h2_8daaf6152771_806a8c22fdea`
- Akamai H2: `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
- Akamai hash: `52d84b11737d980aef856699f885ca86`

No reference JA3 is published for Chrome: BoringSSL permutes the extension order
on every connection, so a stable Chrome JA3 does not exist. A client that emits a
constant JA3 across connections is itself a bot signal. JA4 sorts before hashing
and is stable.

- 15 cipher suites + GREASE prefix, no 3DES and no ECDSA-CBC. TLS 1.3 suites lead
  with AES-128-GCM (`0x1301`) — the opposite of Safari
- 16 counted extensions, shuffled per connection via Fisher-Yates over
  `crypto/rand`, with GREASE pinned first and last
- Supported groups: GREASE + X25519MLKEM768 + X25519 + P-256 + P-384 (no P-521)
- key_share: GREASE + X25519MLKEM768 + X25519
- 11 signature algorithms led by ML-DSA (`0x0904`, `0x0905`, `0x0906`), no SHA1
- `compress_certificate`: brotli. Plus ALPS (`17613`, h2 only), ECH GREASE
  (`65037`), and `session_ticket` (`35`) — none of which Safari sends
- HEADERS frame carries the priority flag: weight 256, depends_on 0, exclusive.
  Chrome does not send `NO_RFC7540_PRIORITIES`, so unlike Safari it still speaks
  the RFC 7540 priority scheme
- `sec-ch-ua: "Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`
  — the greased brand's spelling, its version, and the order of the three
  entries all move between releases, and all three are scored against the UA's
  major version. This must change whenever the User-Agent does
- ECH GREASE payload length 208 bytes (`0x00d0`), measured against an
  11-character hostname; see Known gaps

## Sending requests from the CLI

`cmd/send` drives this client against a real target. It goes through `Emulate`
and the ordinary `Client` methods, so what it reports is what a program using
the library gets, not what a bespoke harness arranged to happen.

```bash
go run ./cmd/send -scout https://site.com             # look first, then say what to run
go run ./cmd/send https://site.com                    # one request, prints the response
go run ./cmd/send -p chrome -i https://site.com       # Chrome profile, with headers
go run ./cmd/send https://site.com 30s 100            # 30s, 100 threads
go run ./cmd/send https://site.com 30s 100 8 500      # ...8 clients, held at 500 rps
go run ./cmd/send https://site.com 1m 200 50 -proxy-file proxies.txt
go run ./cmd/send -n 50000 -c 300 -mode pipeline https://site.com
go run ./cmd/send -fingerprint -p chrome              # the profile's reference values
```

Running `send` with no arguments prints the usage, examples included.

### Asking the target what to run against it

Every flag below is a question about the target — does it challenge, does it
speak h2, does it set cookies, how far away is it — and the answers are all
observable. `-scout` goes and looks, then prints the command, with the
measurement behind each flag:

```bash
go run ./cmd/send -scout https://site.com
```

```
    seen from     this machine — no proxy, so this is what your own address sees
    answered      200 OK over HTTP/2.0
    edge          Cloudflare — cf-ray, cf-cache-status, server: cloudflare
    challenge     none from this address
    redirects     none
    cookies       __cf_bm
    page          142.3 KiB, gzip, 23 assets across 2 host(s)
    language      asking in ja-JP landed on https://site.com/?locale=ja
    round trip    44.4ms (median of 4), 319.6ms cold with the handshake

  suggested

    > send https://site.com -t 30s -c 9 -s 2 -warmup 1

    -mode client    the default: the target sets __cf_bm, and -mode fast has no
                    jar to keep it in
    -c 9            a thread carries ~23 req/s at 44.4ms, so 9 of them is about
                    200 req/s — and -c is the rate dial here, not -rps
    ...
```

It is a look rather than a run: a document fetch, a redirect walk, one request
in another language and four to time the link, most of them concurrent, so it
costs a handful of round trips whatever the target is.

What it deliberately does **not** do is find the rate limit. That is the one
answer you can only get by pushing someone's server until it pushes back, so
`-c` comes from the measured round trip and a rate you choose — arithmetic
rather than an experiment on a stranger. The reason line prints the working, so
any other rate reads straight off it.

It also reads `-proxy-file` and `-lang` when they are given, so it looks from an
exit rather than from here and plans for the run you actually meant.

A load run has four dials, and each has a positional form taken in this order
after the URL:

```
send URL [duration] [threads] [clients] [rate]
          -t         -c        -s        -rps
```

Giving the flag skips that slot, so `send URL 100 -t 30s` means 100 threads.
Anything the dials cannot place is reported rather than dropped — a dial that
shifts by one runs the wrong shape and still prints a confident summary.

A **client** is a separate `Client` — its own cookie jar, its own connection
pool, and its own pinned proxy when `-proxy-file` is set. One client with 200
threads is one browser making 200 parallel requests; 200 clients with 200
threads is 200 browsers making one each, and a target that scores per-identity
behaviour tells those apart.

`-mode` picks the entry point, and the guarantees drop as throughput rises:

| mode | path | gives up | measured¹ |
|---|---|---|---|
| `client` (default) | `Client.Do` | nothing | 34.9k req/s, 102 µs cpu/req |
| `fast` | `FastDo` on a prepared template | cookie jar, redirects, retries | **43.5k req/s, 73 µs cpu/req** |
| `pipeline` | the `Pipeline` worker pool | as `fast`, plus per-request submission control | 38.5k req/s, 100 µs cpu/req |

¹ 120k requests, 256 workers, one session, local HTTP/2 target, 4 cores. Client
and server share the box, so treat these as relative, not as a ceiling.

`pipeline` is **not** the fastest, which it used to claim to be — `fast` beat it
at 256, 1024 and 3000 workers, by 19%, 29% and 12%, at 20-30% less CPU per
request. A pipelined request carries two extra channel hops and a goroutine
handoff for the asynchronous body drain. What the pipeline buys is submission
control and per-request outcomes at high concurrency without a channel per
request; if you only want throughput, `fast` is the shorter path.

### Getting the rate up

Two dials matter more than the transport knobs, and both are easy to get wrong:

**`-s` is a throughput dial, not only an identity dial.** HTTP/2 puts every
stream on one connection, and the header block for each is encoded while holding
that connection's write lock — so all the threads in one session queue behind one
mutex. Measured on the same box, `fast` at 256 workers: `-s 1` → 43.5k req/s,
`-s 2` → 55.5k, `-s 4` → 53.6k. One extra session is worth ~28%; past the core
count it stops helping.

**`-c` should be about rate × round-trip time, not "as high as possible."** A
worker is one request in flight, so 50k RPS against a target 5ms away needs ~250
of them and the same rate at 100ms needs ~5000. Above that they are not in
flight, they are queued, and they cost scheduling and memory to sit there —
3000 workers against a local target measured *half* the throughput of 256 at
double the CPU.

Response bodies are always drained rather than abandoned. Closing an unfinished
body makes HTTP/2 emit RST_STREAM, which is the abusive-client signal this
package exists to avoid — measuring throughput must not be the thing that
produces it.

A run reports itself once a second, live, and the rate it prints is the one over
the second just ended rather than the running average — that is what shows a
target starting to throttle or a proxy pool going bad, neither of which is
visible in a number that keeps averaging in the healthy start:

```
$ go run ./cmd/send -t 60s -c 100 https://site.com
0:01  sent 22564  now 22.6k/s  avg 22.6k/s  ok 22564  failed 0  59s left
0:02  sent 47525  now 25.0k/s  avg 23.8k/s  ok 47526  failed 0  58s left
...
rps      avg 24.2k   peak 26.0k   low 22.6k   over 60 seconds
         ▇▇▇▇▇▇▇█▇▇▇▆▅▃▂▂▂▂▂▂
latency  min 80µs   p50 2.3ms   p90 4ms   p99 5.9ms   max 35.2ms
```

`-rps N` holds the run at a fixed rate instead of going flat out, `-json` prints
the summary — per-second series included — as JSON, and `send -h` lists the
transport knobs (`-max-streams`, `-idle-conns`, `-sockbuf`, `-tfo`, …).

### Getting past a Cloudflare challenge

`-solve` runs the browser in `solver/` first, then seeds what it earned into
every session before the run starts:

```bash
cd solver && npm install && cd ..

go run ./cmd/send -solve https://site.com                       # solve, then one request
go run ./cmd/send -solve https://site.com 30s 100                # solve, then a load run
go run ./cmd/send -solve -proxy socks5://host:1080 https://site.com
go run ./cmd/send -solve https://site.com 1m 100 8 -proxy-file proxies.txt
```

```
solving https://site.com with the browser in solver/ (direct, up to 1m15s)
solved in 9.4s, 1 attempt(s), 4 cookie(s), chromium Chrome/151.0.7204.50
cf_clearance issued for .site.com
```

Cloudflare binds `cf_clearance` to three things, and all three have to survive
the handover from the browser that earned it to the client that replays it:

| bound to | how it survives | what happens otherwise |
|---|---|---|
| User-Agent | the solver returns the UA it used, and the run is pinned to it | 403 on the first request |
| JA3/JA4 | `-solve` implies `-p chrome`, since a real Chromium earned the cookie | works once, dies under load |
| source IP | the exit is handed to the solver, so it solves through the address that will replay | 403 from the first replay |

The JA3/JA4 row has a second half the profile alone does not cover: Chrome's
ClientHello changes between majors, so a cookie earned by the Chromium that
happens to be installed and replayed as Chrome 151 is presented with a
fingerprint it was never issued to. The solver reports the browser it drove as
`chromium_major`, and `send` compares it to the version being replayed:

```
warning: the solver's Chromium is 141 but this client replays as Chrome 151 —
  the cookie is bound to the TLS fingerprint that earned it, and the ClientHello moves
  between majors, so it will work once and then stop under load.
```

Nothing else surfaces that. The UA is pinned by `solver/profile.js`, so a
Chromium 141 solving with a Chrome 151 identity looks correct in every header —
the version it actually shook hands with is the only tell, and it is now read
rather than printed and discarded. `fpcheck -via-chromium` still measures how far
apart the two really are.

The language travels with them. `send` hands the solver whatever the run will
replay with — `-lang`, or the library default — as `SOLVER_LANG`, and the solver
pins it with `--accept-lang` and `--lang`. Left to itself the browser used the
box's locale, so a localised image solved in one language and replayed in
another; worse, the `navigator.languages` shim asserted `["en-US", "en"]`
regardless, contradicting the browser's own header on any box that was not
already en-US.

The solver claims the OS it is actually running, which for most deployments is
Linux — `Chrome151LinuxUserAgent`, the same Chrome 151 identity with the Linux
OS token. Claiming Windows from a Linux box is a contradiction a JS challenge
reads directly out of `navigator.platform` and the installed font set, and no
page-level override fixes it honestly. The TLS layer does not move with the
platform: BoringSSL sends the same ClientHello everywhere, so the pinned JA4 and
Akamai fingerprint hold either way. `Sec-Ch-Ua-Platform` is derived from
whatever User-Agent the request ends up with, so `-ua` and `-solve` stay
self-consistent without a second knob.

None of those fail loudly. A mismatch produces a cookie that works for one
request and then stops, which looks exactly like the target simply blocking the
client — so `send` refuses the combinations it cannot make consistent (`-p
safari`) rather than letting them fail that way at runtime.

#### A proxy list

One solve earns one cookie bound to one IP, and a rotator hands each session a
different exit — so `-solve -proxy-file` solves the list rather than solving
once and hoping. One exit, one solve, one identity, kept paired all the way into
the session pool:

```
$ send -solve https://site.com 1m 100 4 -proxy-file proxies.txt
12 proxies loaded but only 4 session(s) — solving 4 of them; raise -s to spread the run across more exits
solving https://site.com through 4 exit(s), 2 at a time (up to 5m0s)
1.2.3.4:8080: solving https://site.com with the browser in solver/ (via 1.2.3.4:8080, up to 2m30s)
5.6.7.8:8080: solving https://site.com with the browser in solver/ (via 5.6.7.8:8080, up to 2m30s)
1.2.3.4:8080: solved in 1m4s, 1 attempt(s), 4 cookie(s), chromium Chrome/151.0.7922.108
1.2.3.4:8080: cf_clearance issued for .site.com
...
3 of 4 exits solved — the run uses those, and 4 session(s) share them
```

Three things keep the pairing honest:

- **only the exits a session will pin are solved.** Sessions take
  `proxies[i % len]`, so with `-s 4` the fifth proxy onward is never a session's
  own exit — solving it would buy a cookie nothing replays.
- **an exit that fails to solve is dropped from the list.** A proxy that cannot
  get past the challenge in a real browser will not get past it here either, and
  leaving it in spends a session's whole share of the run on 403s.
- **the surviving sessions stop failing over to each other.** Normally a session
  whose proxy is benched routes through a live sibling; with a solved cookie that
  would present it from an address it was never issued to, so the pin is hard
  (`ProxyRotator.PinnedOnly`) and a dead proxy fails its own session's dials
  instead. Loud beats silent — `-proxy-stats` names it.

Passwords are stripped from every line these print, so a `user:pass@host` list
does not end up in a terminal scrollback or a pasted log.

#### Why a hundred proxies is not a hundred solves

The cost is one challenge per exit, and at 65s each a hundred-entry list would be
the better part of an hour — longer than a `cf_clearance` usually lives, so the
exits solved first would be dead before the last one finished. That is not a
slow feature, it is a broken one.

What makes it work is that the cost is per **address**, not per line. A
hundred-entry list is usually a provider's gateway addressed a hundred ways: a
port range onto one pool, or a handful of exits repeated. Two entries that leave
from the same address are one identity to Cloudflare, so the second solve buys a
copy of the first cookie for another full challenge. So the exits are measured
before anything is solved:

```
checking where 100 proxies leave from (https://www.cloudflare.com/cdn-cgi/trace)
100 proxies resolve to 12 exit(s) in 6.1s, 74 sharing an address with one already counted, 9 unreachable, 5 rotating
solving https://site.com through 8 exit(s), 2 at a time (up to 20m0s)
```

One request per proxy, all at once, answering three questions at once:

- **which entries share an address** — the list collapses to the exits it really
  has, and they share a solve and a cache entry;
- **which entries are dead** — a second each here instead of a 150s solve
  timeout each;
- **which entries rotate** — and those are dropped, because per-exit solving
  cannot work through them at all. A backconnect gateway hands out a different
  address per connection: the cookie is bound to whichever one the browser got,
  every request after it leaves from somewhere else, the solve looks like it
  succeeded and the run 403s from the first request. Two reads over two
  connections is what tells a rotating gateway from a fixed one. If your provider
  offers sticky or session ports, that is what to point this at.

The check is Cloudflare's own `/cdn-cgi/trace`, which is the point: it reports
the address *as Cloudflare sees it*, which is the address `cf_clearance` gets
bound to. `-solve-ip-check` takes any URL that answers with an address (a bare
`1.2.3.4` body works too), and `-solve-ip-check ""` turns the whole thing off and
solves one per line as before.

#### One browser for the whole list

What is left after that is genuinely one challenge per identity — but it used to
be one *browser* per identity too, and only the challenge is unavoidable.
Chromium takes ~20s to come up under Xvfb on the kind of box this runs on, so a
hundred exits spent half an hour doing nothing but starting browsers that
differed only in which proxy they dialled.

Chrome takes a proxy per BrowserContext, not only on the command line, so one
browser serves every exit: a context each, with its own cookie jar, its own
storage and its own egress. Measured against this repo's own solver driving a
real Chromium — 8 exits through 8 local proxies:

| | per-exit browser | shared browser |
|---|---|---|
| opening one exit | 612 ms | 102–192 ms |
| 8 exits, 2 at a time | 28.5 s | 24.5 s |

The 4-second gap is exactly the launch cost times the seven exits that no longer
pay it, which is the whole mechanism — and on the small VPS the 20s figure comes
from, that same arithmetic is ~2.3 minutes on 8 exits and ~33 minutes on 100.
This box simply starts Chromium quickly.

It also changes what `-solve-parallel` costs. Four at a time used to mean four
Chromiums resident at once, which is what kept the default at 2; four contexts
in one browser is four tabs, so raise it much further than you would have.

Results stream back one line per exit as it finishes, so a batch that runs for
minutes reports as it goes — and one that dies partway has already handed over
the exits that solved. An exit the solver never mentions is treated as a
failure, not as a success with no cookie.

`-solve-isolate` goes back to a browser per exit. A context is Chrome's
incognito primitive: same process and same BoringSSL, so the JA3/JA4 the cookie
is bound to is identical either way — but the flag is there if a shared browser
ever turns out to measure differently on a real target.

The per-exit cache below is what makes the second run cheap — it is consulted
before anything is launched, so a fully cached list never starts a browser at
all — and `send` says so when a solve outlasted the cookies it was earning.

A solve is slow because most of it is Cloudflare's own challenge — its
JavaScript runs, the Turnstile widget executes, the edge decides. A real browser
pays that too, so there is nothing to optimise away; what there is, is not
paying it twice. The clearance is cached and reused while it is still valid:

```
$ send -solve https://site.com          # first run
solving https://site.com with the browser in solver/ (direct, up to 2m30s)
solved in 1m11s, 1 attempt(s), 1 cookie(s), chromium Chrome/151.0.7922.108

$ send -solve https://site.com          # every run after
reusing the solve from 2m14s ago (1 cookie(s), expires in 27m45s)
```

The entry is keyed by host **and** proxy, because `cf_clearance` is bound to the
IP that earned it — a run through a different exit gets a miss rather than a
dead cookie. That key is also what makes a proxy list affordable: each exit has
its own entry, so a second run through the same list starts from the cache
rather than paying twelve challenges again. `-solve-refresh` forces a new solve,
`-solve-max-age` caps how old
an entry may be (default 30m, since Cloudflare can invalidate server-side well
before the stated expiry), and `-solve-cache ""` turns it off. The file is
written 0600: it holds a bearer token for the origin.

`-solver-dir` points at a solver checkout somewhere else, and `-solve-timeout`
bounds the solve (default 150s). Browser startup comes out of that budget and
costs ~20s on a small VPS, twice if the first attempt is retried, so a small
timeout can leave a managed challenge no time to solve in — against a live UAM,
75s failed with no cookie at all while 150s cleared it on the first attempt in
71s. The solver reports `launch_ms` so the arithmetic is visible, and `send`
says so when startup ate most of the budget. A run continues even when no
`cf_clearance`
appears — a target behind Bot Fight Mode alone never issues one, and the
`__cf_bm` the solve did earn is what carries the session — but it says so.

## What happens when a handshake fails

How a client *fails* is part of its fingerprint, so the failure paths are
browser-shaped rather than "close the socket and return an error":

- **A fatal alert goes out before the connection is dropped**, with a
  description matched to the cause — `bad_certificate` / `unknown_ca` /
  `certificate_expired` for a chain that does not verify, `illegal_parameter`
  for a ServerHello field that is out of contract, `decrypt_error` for a bad
  signature or Finished MAC, `protocol_version` for a server that will not
  speak TLS 1.3. Once handshake keys exist the alert is encrypted, which is
  what a server holding those keys expects. A client that instead vanishes
  mid-handshake is doing something no shipping browser does, and the peer sees
  it. Failures that are the *connection* dying send nothing.
- **Alerts received are read per RFC 8446 §6.2**, where the level byte carries
  no meaning: everything except `close_notify` and `user_canceled` is fatal
  whatever level it arrives at. `close_notify` surfaces as `io.EOF` so
  connection-close-delimited bodies are not reported as truncated.
- **Errors name the alert.** `server alert: illegal_parameter (47)` rather than
  `server alert: 47` — for a fingerprint regression that name is usually the
  whole diagnosis.
- **The ServerHello is checked against the ClientHello that was sent**: the
  `legacy_session_id_echo` must match, `legacy_compression_method` must be null,
  the TLS 1.2/1.1 downgrade sentinels in `ServerHello.random` are rejected, no
  extension may appear twice, and extensions TLS 1.3 moved to
  EncryptedExtensions (or a `pre_shared_key` that was never offered) are
  refused. A negotiated ALPN that was not in the offer is rejected with
  `no_application_protocol`.
- **Every handshake is bounded in time.** `WithTLSHandshakeTimeout` is applied
  by this transport directly, because `net/http` only honours its own
  `TLSHandshakeTimeout` on the code path a custom TLS dialer replaces. A
  deadline on the request context still wins when it is sooner.

## What has actually been checked

The reference values in this repo are measurements, and two of them have now
been confirmed on hardware other than the one they were taken on:

- **The pinned Chrome fingerprints reproduce on a second device.** JA4, JA4_r,
  peetprint and the Akamai HTTP/2 fingerprint were captured from Chrome
  151.0.7922.108 on Linux x86_64 through `tls.peet.ws` and matched
  `internal/ctls/reference.go` byte for byte — despite those values having been
  taken from Chrome 151 on Windows. The OS token is the only thing a platform
  choice moves.
- **`fpcheck` passes for both profiles** against a live `tls.peet.ws` from a
  networked host, which is the check that the Go client emits what the reference
  says it should. It cannot run from a sandboxed environment, so it is worth
  re-running on your own box before relying on any of this.

What that does *not* cover, and what nothing here should be taken to claim: no
part of this has been measured against a live Cloudflare challenge end to end.
`-solve` earning a `cf_clearance` and a load run replaying it successfully is
a separate test, and it is the one left.

## Known gaps

The TLS, HTTP/2 and header layers match the reference devices. These do not, and
no amount of work inside this package closes them:

- **The TCP/IP layer says whatever OS you run on.** MSS, window scale and the
  order of TCP options in the SYN are set by the kernel, and a p0f-style
  classifier reads them. Initial TTL is *not* the tell people assume — iOS and
  Linux both start at 64, and the iPhone capture in
  `cmd/fpcheck/testdata` shows 48 after 16 hops, which a Linux host on the same
  path would also show. `tls.peet.ws` reports only TTL and a mid-stream window
  under `tcpip`, so it will not surface this either way; judging it needs a SYN
  capture. If your target scores it, run from the OS you are emulating — or
  behind a proxy running on it, since the exit host is what the origin measures.
- **TCP Fast Open is off by default** for the same reason: no browser uses it,
  so a SYN carrying payload contradicts the browser above it. `WithTCPFastOpen()`
  turns it back on when throughput matters more.
- **ECH GREASE payload length is a constant (208 bytes).** That value is
  measured — a real Chrome 151 against `tls.peet.ws`, an 11-character hostname,
  sends `payload_len = 0x00d0`, and 208 = 6*32 + 16 fits the ECH padding rule
  (pad the inner hello to a multiple of 32, add the 16-byte AEAD tag). But real
  Chrome derives it from the padded inner ClientHello, so it moves with the
  server name's length, and one data point cannot recover that relationship.
  JA3 and JA4 hash extension IDs only and cannot see it; a byte-level check on
  the raw ClientHello could. Captures against two or three more hostnames of
  different lengths would settle it.
- **The HTTP/2 transport pings an idle connection every 15s.** That keeps dead
  connections out of the pool, but browsers have no such fixed heartbeat. It only
  shows up on connections held open between requests, not on a single fetch.

## Performance claims

The "200-300k+ RPS" figure above is a design target, not a measured result.
There is no reproducible benchmark behind it: `benchmark_test.go` runs against a
local `httptest` server, which measures this client's own overhead rather than
what any real target will serve, and no hardware, concurrency level or endpoint
is recorded for the number. Treat it as an order-of-magnitude goal and measure
your own workload before relying on it.

## License

MIT — see [LICENSE](LICENSE).

`internal/http2` vendors a modified copy of `golang.org/x/net/http2` under the
Go project's BSD-3-Clause licence; see [internal/http2/FORK.md](internal/http2/FORK.md)
for the base version and the list of local changes.
