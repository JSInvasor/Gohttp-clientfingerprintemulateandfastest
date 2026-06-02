# gofire

Ultra high-performance Go HTTP client with **Safari iOS 18** TLS fingerprint emulation. Designed for **200-300k+ RPS** with full JA3/JA4 + HTTP/2 + header fingerprint bypass.

## Features

- **Safari iOS 18 TLS Fingerprint** — Exact JA3/JA4 via custom TLS 1.3 (cipher suites, GREASE, 512-byte padding, X25519 key share)
- **Safari iOS 18 HTTP/2 Fingerprint** — SETTINGS (MAX_CONCURRENT_STREAMS=100, NO_RFC7540_PRIORITIES=1), WINDOW_UPDATE, pseudo-header order (m,s,a,p)
- **Safari iOS 18 Headers** — Correct order, Sec-Fetch-* (no Sec-Fetch-User), Priority
- **200-300k+ RPS** — Worker pool pipeline, connection pre-warming, DNS cache
- **Pipeline Mode** — Fixed worker pool for sustained max throughput
- **PreConnect** — Pre-warm TLS connections before first request
- **DNS Cache** — Round-robin IP selection, configurable TTL
- **TCP Tuning** — TCP_NODELAY, TCP_QUICKACK, 256KB buffers (Linux)
- **Auto Decompression** — gzip, brotli, deflate
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
    // Emulate Safari iOS 18 - that's it!
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
    fmt.Println(text) // Safari iOS 18 fingerprint verified
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
// Recommended: Emulate Safari iOS 18
client, err := gofire.Emulate(gofire.SafariIOS18)
client, err := gofire.Emulate(gofire.SafariIOS18, gofire.WithProxy("socks5://..."))

// Or with NewClient (defaults to Safari iOS 18)
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

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `WithTimeout` | 30s | Total request timeout |
| `WithProxy` | - | HTTP/SOCKS5 proxy URL |
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

## Safari iOS 18 Fingerprint Details

### TLS (JA3/JA4)
- TLS 1.3 with TLS 1.2 fallback (TLS 1.0/1.1 removed — Apple dropped them in iOS 13)
- 20 cipher suites + GREASE prefix (includes 3DES legacy ciphers)
- GREASE values at 6 positions: ciphers, first/last extension, key_share, supported_groups, supported_versions
- 16 extensions: SNI, extended_master_secret, renegotiation_info, supported_groups, ec_point_formats, ALPN(h2,http/1.1), status_request, signature_algorithms, SCT, key_share, psk_key_exchange_modes, supported_versions, compress_certificate(zlib), padding
- Supported groups: GREASE + X25519 + P-256 + P-384 + P-521 (no post-quantum, no FFDHE)
- Only X25519 key share (no MLKEM, no P-256 key share)
- 9 unique signature algorithms (incl. rsa_pkcs1_sha1 for legacy compat)
- ClientHello padded to ~512 bytes
- No ALPS, no ECH, no delegated_credentials, no record_size_limit

### HTTP/2 (Akamai)
- ENABLE_PUSH: 0
- MAX_CONCURRENT_STREAMS: 100
- INITIAL_WINDOW_SIZE: 2097152
- NO_RFC7540_PRIORITIES: 1
- Connection WINDOW_UPDATE: 10420225
- Pseudo-header order: :method :scheme :authority :path (m,s,a,p)
- Akamai fingerprint: `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`
- Akamai hash: `c52879e43202aeb92740be6e8c86ea96`

### Headers
- Exact Safari iOS 18 header order
- `User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Mobile/15E148 Safari/604.1`
- `sec-fetch-dest` before `user-agent` (unique to Safari)
- `accept-encoding` LAST (Firefox/Chrome place it earlier)
- `accept-encoding: gzip, deflate, br` (no zstd — Safari only supports these three)
- No `Upgrade-Insecure-Requests`, no `Sec-Fetch-User`, no `Sec-Ch-Ua`, no `TE`

## License

MIT
