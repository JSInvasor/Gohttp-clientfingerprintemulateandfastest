package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

const version = "2.1.0"

const banner = `
   ██████╗  ██████╗ ███████╗██╗██████╗ ███████╗
  ██╔════╝ ██╔═══██╗██╔════╝██║██╔══██╗██╔════╝
  ██║  ███╗██║   ██║█████╗  ██║██████╔╝█████╗
  ██║   ██║██║   ██║██╔══╝  ██║██╔══██╗██╔══╝
  ╚██████╔╝╚██████╔╝██║     ██║██║  ██║███████╗
   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
`

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

func usage() {
	fmt.Printf("%s%s%s", colorCyan, banner, colorReset)
	fmt.Printf("  %sGofire[v%s]%s | Custom TLS 1.3 Firefox 148 Fingerprint\n\n", colorBold, version, colorReset)
	fmt.Printf("  %sUsage:%s  gofire <url> <duration_seconds> <threads> [streams_per_thread]\n", colorYellow, colorReset)
	fmt.Printf("  %sExample:%s ./gofire https://example.com 60 64 32\n\n", colorYellow, colorReset)
	fmt.Printf("  %sArguments:%s\n\n", colorGreen, colorReset)
	fmt.Printf("    %s<url>%s                 | Target URL (http:// or https://)\n", colorCyan, colorReset)
	fmt.Printf("    %s<duration_seconds>%s    | How long to run in seconds\n", colorCyan, colorReset)
	fmt.Printf("    %s<threads>%s             | Number of concurrent workers (connections)\n", colorCyan, colorReset)
	fmt.Printf("    %s[streams_per_thread]%s  | HTTP/2 concurrent streams per worker (default: 32)\n\n", colorCyan, colorReset)
	fmt.Printf("  %sFormula:%s threads × streams = eşzamanlı istek sayısı\n", colorGreen, colorReset)
	fmt.Printf("    64 × 32  = 2048 eşzamanlı → 50ms latency = ~40,000 RPS\n")
	fmt.Printf("    128 × 50 = 6400 eşzamanlı → 50ms latency = ~128,000 RPS\n\n")
	fmt.Printf("  %sFeatures:%s\n", colorGreen, colorReset)
	fmt.Printf("    • Custom TLS 1.3 implementation (no uTLS)\n")
	fmt.Printf("    • Firefox 148 exact ClientHello fingerprint (JA3/JA4)\n")
	fmt.Printf("    • X25519MLKEM768 post-quantum key share\n")
	fmt.Printf("    • HTTP/2 Akamai fingerprint: 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s\n")
	fmt.Printf("    • HTTP/2 stream multiplexing per worker\n")
	fmt.Printf("    • Connection pre-warming + keep-alive pool\n\n")
}

func main() {
	if len(os.Args) < 4 {
		usage()
		os.Exit(1)
	}

	rawURL := os.Args[1]
	durSec, err := strconv.Atoi(os.Args[2])
	if err != nil || durSec <= 0 {
		fatal("geçersiz süre: %s (pozitif tam sayı olmalı)", os.Args[2])
	}
	threads, err := strconv.Atoi(os.Args[3])
	if err != nil || threads <= 0 {
		fatal("geçersiz thread sayısı: %s (pozitif tam sayı olmalı)", os.Args[3])
	}

	streams := 32 // default streams per worker
	if len(os.Args) >= 5 {
		streams, err = strconv.Atoi(os.Args[4])
		if err != nil || streams <= 0 {
			fatal("geçersiz stream sayısı: %s (pozitif tam sayı olmalı)", os.Args[4])
		}
	}

	// Ensure URL has scheme
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	run(rawURL, durSec, threads, streams)
}

func run(targetURL string, durSec, threads, streams int) {
	fmt.Printf("%s%s%s", colorCyan, banner, colorReset)
	fmt.Printf("  %sGofire[v%s]%s | Custom TLS 1.3 | Firefox 148\n\n", colorBold, version, colorReset)

	// Total concurrency = threads × streams
	totalConcurrent := threads * streams

	// Pool must be >= total concurrent requests
	idlePerHost := totalConcurrent
	if idlePerHost < 256 {
		idlePerHost = 256
	}
	totalIdle := totalConcurrent * 2
	if totalIdle < 512 {
		totalIdle = 512
	}

	client, err := gofire.Emulate(gofire.Firefox148,
		gofire.WithTimeout(8*time.Second),
		gofire.WithTLSHandshakeTimeout(8*time.Second),
		gofire.WithMaxIdleConnsPerHost(idlePerHost),
		gofire.WithMaxIdleConns(totalIdle),
		gofire.WithMaxConnsPerHost(0), // unlimited
		gofire.WithDNSCacheTTL(30*time.Minute),
		gofire.WithIdleConnTimeout(120*time.Second),
		gofire.WithDisableRedirects(),
		gofire.WithWriteBufferSize(128*1024),
		gofire.WithReadBufferSize(128*1024),
	)
	if err != nil {
		fatal("client oluşturulamadı: %v", err)
	}
	defer client.Close()

	fmt.Printf("  %s[Target]%s      %s\n", colorYellow, colorReset, targetURL)
	fmt.Printf("  %s[Süre]%s        %ds\n", colorYellow, colorReset, durSec)
	fmt.Printf("  %s[Threads]%s     %d\n", colorYellow, colorReset, threads)
	fmt.Printf("  %s[Streams]%s     %d per worker\n", colorYellow, colorReset, streams)
	fmt.Printf("  %s[Eşzamanlı]%s   %d istek\n", colorYellow, colorReset, totalConcurrent)
	fmt.Printf("  %s[Pool]%s        %d idle/host | %d total\n", colorYellow, colorReset, idlePerHost, totalIdle)

	fmt.Printf("\n  %s[*]%s Bağlantılar ısıtılıyor...\n", colorCyan, colorReset)
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 10*time.Second)
	warmCount := threads
	if warmCount > 64 {
		warmCount = 64
	}
	client.PreConnect(warmCtx, targetURL, warmCount) //nolint
	warmCancel()

	// Setup context
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durSec)*time.Second)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n  %s[!]%s Durduruldu (CTRL+C)\n", colorRed, colorReset)
		cancel()
	}()

	// Stats counters
	var (
		totalSent    atomic.Int64
		totalSuccess atomic.Int64
		totalFailed  atomic.Int64
		statusCodes  sync.Map
	)

	startTime := time.Now()
	fmt.Printf("  %s[*]%s Başlıyor... (%d eşzamanlı istek)\n\n", colorCyan, colorReset, totalConcurrent)

	// Worker goroutines with per-worker semaphore for HTTP/2 stream multiplexing
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Semaphore: allows `streams` concurrent in-flight requests per worker
			sem := make(chan struct{}, streams)

			var innerWg sync.WaitGroup
			for {
				select {
				case <-ctx.Done():
					// Wait for all in-flight requests in this worker to finish
					innerWg.Wait()
					return
				default:
				}

				// Acquire semaphore slot (block if at max streams)
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					innerWg.Wait()
					return
				}

				reqURL := targetURL
				totalSent.Add(1)

				innerWg.Add(1)
				go func(url string) {
					defer func() {
						<-sem // Release semaphore slot
						innerWg.Done()
					}()

					resp, err := client.GetWithContext(ctx, url)
					if err != nil {
						totalFailed.Add(1)
						return
					}

					totalSuccess.Add(1)
					sc := resp.StatusCode()

					val, _ := statusCodes.LoadOrStore(sc, &atomic.Int64{})
					val.(*atomic.Int64).Add(1)

					resp.Close()
				}(reqURL)
			}
		}()
	}

	// Real-time stats printer
	go func() {
		statsTicker := time.NewTicker(1 * time.Second)
		defer statsTicker.Stop()
		lastSent := int64(0)

		for {
			select {
			case <-ctx.Done():
				return
			case <-statsTicker.C:
				sent := totalSent.Load()
				ok := totalSuccess.Load()
				fail := totalFailed.Load()
				elapsed := time.Since(startTime).Seconds()
				remaining := float64(durSec) - elapsed
				if remaining < 0 {
					remaining = 0
				}
				currentRPS := sent - lastSent
				lastSent = sent

				fmt.Printf("\r  %s[*]%s Gönderilen: %s%d%s | OK: %s%d%s | Fail: %s%d%s | RPS: %s%d%s | Süre: %s%.0fs%s | Kalan: %s%.0fs%s   ",
					colorCyan, colorReset,
					colorWhite, sent, colorReset,
					colorGreen, ok, colorReset,
					colorRed, fail, colorReset,
					colorYellow, currentRPS, colorReset,
					colorGray, elapsed, colorReset,
					colorGray, remaining, colorReset,
				)
			}
		}
	}()

	wg.Wait()
	endTime := time.Now()

	// Final stats
	totalDuration := endTime.Sub(startTime)
	sent := totalSent.Load()
	ok := totalSuccess.Load()
	fail := totalFailed.Load()
	avgRPS := float64(0)
	if totalDuration.Seconds() > 0 {
		avgRPS = float64(sent) / totalDuration.Seconds()
	}
	successRate := float64(0)
	if sent > 0 {
		successRate = float64(ok) / float64(sent) * 100
	}

	fmt.Printf("\n\n  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorGray, colorReset)
	fmt.Printf("  %s%s[SONUÇLAR]%s\n\n", colorBold, colorGreen, colorReset)
	fmt.Printf("    Toplam Gönderilen : %s%d%s\n", colorWhite, sent, colorReset)
	fmt.Printf("    Başarılı          : %s%d%s (%.1f%%)\n", colorGreen, ok, colorReset, successRate)
	fmt.Printf("    Başarısız         : %s%d%s\n", colorRed, fail, colorReset)
	fmt.Printf("    Süre              : %s%v%s\n", colorYellow, totalDuration.Round(time.Millisecond), colorReset)
	fmt.Printf("    Ortalama RPS      : %s%.0f%s req/s\n", colorCyan, avgRPS, colorReset)
	fmt.Printf("    Eşzamanlı İstek   : %s%d%s (%d threads × %d streams)\n", colorGray, totalConcurrent, colorReset, threads, streams)
	fmt.Printf("    Aktif Bağlantı    : %s%d%s\n", colorGray, client.ActiveConnections(), colorReset)

	hasStatusCodes := false
	statusCodes.Range(func(_, _ interface{}) bool {
		hasStatusCodes = true
		return false
	})
	if hasStatusCodes {
		fmt.Printf("\n    %sStatus Code Dağılımı:%s\n", colorYellow, colorReset)
		statusCodes.Range(func(key, value interface{}) bool {
			sc := key.(int)
			count := value.(*atomic.Int64).Load()
			color := colorGreen
			if sc >= 400 && sc < 500 {
				color = colorYellow
			} else if sc >= 500 {
				color = colorRed
			}
			fmt.Printf("      %s%d%s: %d\n", color, sc, colorReset, count)
			return true
		})
	}

	fmt.Printf("\n  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n", colorGray, colorReset)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "  %s[FATAL]%s %s\n", colorRed, colorReset, fmt.Sprintf(format, args...))
	os.Exit(1)
}
