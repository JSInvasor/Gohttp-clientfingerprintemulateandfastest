# gofire

Ultra high-performance Go HTTP client with **Firefox 148** TLS fingerprint emulation. Designed for **200-300k+ RPS** with full JA3/JA4 bypass.

## Features

- **Firefox 148 TLS Fingerprint** — Exact JA3/JA4 fingerprint match via uTLS
- **Firefox 148 HTTP/2 Fingerprint** — Correct SETTINGS, WINDOW_UPDATE, header order
- **200-300k+ RPS** — Aggressive connection pooling, DNS caching, zero-alloc hot paths
- **DNS Cache** — Built-in DNS cache to eliminate repeated lookups
- **TCP Tuning** — TCP_NODELAY, TCP_QUICKACK (Linux), optimized buffer sizes
- **Auto Decompression** — gzip, brotli, deflate, zstd
- **Cookie Jar** — Automatic cookie management
- **Proxy Support** — HTTP/SOCKS5 proxy support
- **Builder Pattern** — Fluent API for complex requests

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
    "time"

    gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

func main() {
    client, err := gofire.NewClient(
        gofire.WithTimeout(15 * time.Second),
        gofire.WithMaxIdleConnsPerHost(1000),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    resp, err := client.Get("https://tls.peet.ws/api/all")
    if err != nil {
        log.Fatal(err)
    }

    text, _ := resp.Text()
    fmt.Println(text) // Will show Firefox 148 fingerprint
}
```

## High RPS Usage

```go
client, _ := gofire.NewClient(
    gofire.WithMaxIdleConnsPerHost(2000),
    gofire.WithMaxIdleConns(20000),
    gofire.WithMaxConnsPerHost(0),        // unlimited
    gofire.WithDNSCacheTTL(10 * time.Minute),
    gofire.WithTimeout(10 * time.Second),
)

// Flood: send 10k concurrent requests
ctx := context.Background()
responses, errors := client.Flood(ctx, "GET", "https://target.com", 10000, 500)
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `WithTimeout` | 30s | Total request timeout |
| `WithProxy` | - | HTTP/SOCKS5 proxy URL |
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

## Performance Tuning

For maximum RPS:

```go
// System-level (run before your app):
// ulimit -n 1000000        # increase file descriptors
// sysctl -w net.core.somaxconn=65535
// sysctl -w net.ipv4.tcp_tw_reuse=1

client, _ := gofire.NewClient(
    gofire.WithMaxIdleConnsPerHost(2000),
    gofire.WithMaxIdleConns(50000),
    gofire.WithDNSCacheTTL(30 * time.Minute),
    gofire.WithIdleConnTimeout(120 * time.Second),
    gofire.WithDisableRedirects(),
)
```

## Fingerprint Details

### TLS (JA3)
- TLS 1.3 + TLS 1.2 fallback
- Cipher suites: AES-128-GCM, CHACHA20, AES-256-GCM, ECDHE variants
- Extensions: SNI, ALPN(h2,http/1.1), key_share(x25519,P-256), supported_versions, ECH GREASE, compress_certificate(zlib,brotli), delegated_credentials
- Supported groups: x25519, P-256, P-384, P-521, ffdhe2048, ffdhe3072

### HTTP/2
- HEADER_TABLE_SIZE: 65536
- ENABLE_PUSH: 0
- INITIAL_WINDOW_SIZE: 131072
- MAX_FRAME_SIZE: 16384
- Connection window: 12517377

### Headers
- Exact Firefox 148 header order
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0`
- Full Sec-Fetch-* headers
- DNT, Sec-GPC, Priority, TE headers

## License

MIT
