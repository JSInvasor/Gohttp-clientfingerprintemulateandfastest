# gofire

Ultra high-performance Go HTTP client with **Firefox 148** TLS fingerprint emulation. Designed for **200-300k+ RPS** with full JA3/JA4 + HTTP/2 + header fingerprint bypass.

## Features

- **Firefox 148 TLS Fingerprint** — Exact JA3/JA4 via uTLS (cipher suites, extensions, GREASE, ECH)
- **Firefox 148 HTTP/2 Fingerprint** — SETTINGS, WINDOW_UPDATE, pseudo-header order
- **Firefox 148 Headers** — Correct order, Sec-Fetch-*, DNT, Priority, TE
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
    // Emulate Firefox 148 - that's it!
    client, err := gofire.Emulate(gofire.Firefox148)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    resp, err := client.Get("https://tls.peet.ws/api/all")
    if err != nil {
        log.Fatal(err)
    }

    text, _ := resp.Text()
    fmt.Println(text) // Firefox 148 fingerprint verified
}
```

## Maximum RPS (Pipeline Mode)

```go
client, _ := gofire.Emulate(gofire.Firefox148,
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
// Recommended: Emulate a browser
client, err := gofire.Emulate(gofire.Firefox148)
client, err := gofire.Emulate(gofire.Firefox148, gofire.WithProxy("socks5://..."))

// Or with NewClient (defaults to Firefox 148)
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
| `WithAcceptLanguage` | en-US,en;q=0.5 | Accept-Language header |
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
client, _ := gofire.Emulate(gofire.Firefox148,
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

## Firefox 148 Fingerprint Details

### TLS (JA3/JA4)
- TLS 1.3 + TLS 1.2 fallback
- 14 cipher suites: AES-128-GCM, CHACHA20, AES-256-GCM + ECDHE variants
- 17 extensions: SNI, ALPN(h2,http/1.1), key_share(x25519,P-256), ECH GREASE, compress_certificate(zlib,brotli), delegated_credentials, record_size_limit
- Supported groups: x25519, P-256, P-384, P-521, ffdhe2048, ffdhe3072
- Signature algorithms: ECDSA(P256,P384,P521), PSS-RSAE(SHA256,384,512), PKCS1(SHA256,384,512)

### HTTP/2
- HEADER_TABLE_SIZE: 65536
- ENABLE_PUSH: 0
- INITIAL_WINDOW_SIZE: 131072
- MAX_FRAME_SIZE: 16384
- Connection WINDOW_UPDATE: 12517377
- Pseudo-header order: :method :path :authority :scheme

### Headers
- Exact Firefox 148 header order (22 headers tracked)
- `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0`
- Full Sec-Fetch-* suite
- DNT, Sec-GPC, Priority(u=0,i), TE(trailers)

## License

MIT
