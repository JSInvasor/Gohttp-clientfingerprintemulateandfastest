// Command send is a request sender for driving this client against a real
// target: one request with the response printed, or many with a latency and
// status summary.
//
// It exists to exercise the library the way a caller does — the same Emulate
// entry point, the same options, the same Response handling — so what it
// reports is what a program using gofire would get, not what a bespoke harness
// arranged to happen.
//
//	send https://example.com
//	send -i -b chrome https://example.com
//	send -n 5000 -c 200 https://example.com
//	send -X POST -H 'Content-Type: application/json' -d '{"a":1}' https://example.com/api
//	send -n 1000 -c 50 -proxy-file proxies.txt https://example.com
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// headerList collects repeated -H flags.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }

func (h *headerList) Set(v string) error {
	if !strings.Contains(v, ":") {
		return fmt.Errorf("header %q is not in 'Name: value' form", v)
	}
	*h = append(*h, v)
	return nil
}

type options struct {
	method      string
	headers     headerList
	body        string
	browser     string
	count       int
	concurrency int
	fast        bool
	proxy       string
	proxyFile   string
	timeout     time.Duration
	handshake   time.Duration
	forceH1     bool
	insecure    bool
	noRedirect  bool
	lang        string
	userAgent   string
	referer     string
	retries     int
	preconnect  int
	showHeaders bool
	outFile     string
	silent      bool
	asJSON      bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "send:", err)
		os.Exit(1)
	}
}

func run() error {
	var o options
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.StringVar(&o.method, "X", "GET", "HTTP method")
	fs.Var(&o.headers, "H", "extra header as 'Name: value' (repeatable)")
	fs.StringVar(&o.body, "d", "", "request body; @path reads it from a file")
	fs.StringVar(&o.browser, "b", "safari", "browser profile to emulate: safari | chrome")
	fs.IntVar(&o.count, "n", 1, "number of requests to send")
	fs.IntVar(&o.concurrency, "c", 0, "concurrent workers (default: min(n, 50))")
	fs.BoolVar(&o.fast, "fast", false, "use the FastDo path: no cookie jar, no redirects, no retries")
	fs.StringVar(&o.proxy, "proxy", "", "proxy URL, e.g. http://user:pass@host:port or socks5://host:port")
	fs.StringVar(&o.proxyFile, "proxy-file", "", "file of proxies to rotate, one per line")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "total per-request timeout")
	fs.DurationVar(&o.handshake, "handshake-timeout", 10*time.Second, "TLS handshake timeout per attempt")
	fs.BoolVar(&o.forceH1, "http1", false, "force HTTP/1.1 instead of negotiating h2")
	fs.BoolVar(&o.insecure, "insecure", false, "skip TLS certificate verification")
	fs.BoolVar(&o.noRedirect, "no-redirect", false, "do not follow redirects")
	fs.StringVar(&o.lang, "lang", "", "Accept-Language; match it to where your exit IPs are")
	fs.StringVar(&o.userAgent, "ua", "", "override the profile's User-Agent")
	fs.StringVar(&o.referer, "referer", "", "Referer header to send")
	fs.IntVar(&o.retries, "retry", 0, "retry attempts on network errors and 429/502/503/504")
	fs.IntVar(&o.preconnect, "preconnect", 0, "pre-warm this many TLS connections before starting")
	fs.BoolVar(&o.showHeaders, "i", false, "print response headers (single request only)")
	fs.StringVar(&o.outFile, "o", "", "write the response body to a file instead of stdout")
	fs.BoolVar(&o.silent, "s", false, "suppress the response body")
	fs.BoolVar(&o.asJSON, "json", false, "print the run summary as JSON")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: send [flags] URL\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("exactly one URL is required")
	}
	target := fs.Arg(0)
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}

	if o.count < 1 {
		return fmt.Errorf("-n must be at least 1, got %d", o.count)
	}
	if o.concurrency < 0 {
		return fmt.Errorf("-c cannot be negative, got %d", o.concurrency)
	}
	if o.concurrency == 0 {
		o.concurrency = min(o.count, 50)
	}
	if o.concurrency > o.count {
		o.concurrency = o.count
	}

	body, err := requestBody(o.body)
	if err != nil {
		return err
	}
	headers, err := parseHeaders(o.headers)
	if err != nil {
		return err
	}
	profile, err := parseProfile(o.browser)
	if err != nil {
		return err
	}

	client, err := newClient(o, profile)
	if err != nil {
		return err
	}
	defer client.Close()

	// Ctrl-C stops the run and still prints whatever was collected, which is
	// the point of interrupting a long one.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if o.preconnect > 0 {
		if err := client.PreConnect(ctx, target, o.preconnect); err != nil {
			fmt.Fprintf(os.Stderr, "preconnect: %v\n", err)
		}
	}

	if o.count == 1 {
		return sendOne(ctx, client, o, target, body, headers)
	}
	return sendMany(ctx, client, o, target, body, headers)
}

func newClient(o options, profile gofire.BrowserProfile) (*gofire.Client, error) {
	opts := []gofire.Option{
		gofire.WithTimeout(o.timeout),
		gofire.WithTLSHandshakeTimeout(o.handshake),
	}
	if o.proxy != "" {
		opts = append(opts, gofire.WithProxy(o.proxy))
	}
	if o.forceH1 {
		opts = append(opts, gofire.WithForceHTTP1())
	}
	if o.insecure {
		opts = append(opts, gofire.WithInsecureSkipVerify())
	}
	if o.noRedirect {
		opts = append(opts, gofire.WithDisableRedirects())
	}
	if o.lang != "" {
		opts = append(opts, gofire.WithAcceptLanguage(o.lang))
	}
	if o.userAgent != "" {
		opts = append(opts, gofire.WithUserAgent(o.userAgent))
	}
	if o.referer != "" {
		opts = append(opts, gofire.WithReferer(o.referer))
	}
	if o.retries > 0 {
		opts = append(opts, gofire.WithRetry(o.retries, 200*time.Millisecond, 429, 502, 503, 504))
	}

	client, err := gofire.Emulate(profile, opts...)
	if err != nil {
		return nil, err
	}

	if o.proxyFile != "" {
		rotator, err := gofire.NewProxyRotatorFromFile(o.proxyFile)
		if err != nil {
			return nil, fmt.Errorf("proxy file: %w", err)
		}
		client.SetProxyRotator(rotator)
		fmt.Fprintf(os.Stderr, "rotating %d proxies\n", rotator.Count())
	}
	return client, nil
}

// sendOne performs a single request and prints the result, splitting the timing
// into headers and body. The two are measured separately rather than reported
// as one number because they fail for different reasons: a slow header phase is
// the connection or the origin thinking, a slow body phase is transfer.
func sendOne(ctx context.Context, client *gofire.Client, o options, target string, body []byte, headers map[string]string) error {
	start := time.Now()
	resp, err := client.DoWithContext(ctx, o.method, target, body, headers)
	if err != nil {
		return err
	}
	defer resp.Close()
	headerTime := time.Since(start)

	bodyStart := time.Now()
	data, bodyErr := resp.Bytes()
	bodyTime := time.Since(bodyStart)

	fmt.Fprintf(os.Stderr, "%s %d %s  headers %s  body %s  %d bytes\n",
		resp.Proto, resp.StatusCode(), statusText(resp.StatusCode()),
		round(headerTime), round(bodyTime), len(data))

	if o.showHeaders {
		names := make([]string, 0, len(resp.Header))
		for name := range resp.Header {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, v := range resp.Header[name] {
				fmt.Fprintf(os.Stderr, "%s: %s\n", name, v)
			}
		}
		fmt.Fprintln(os.Stderr)
	}

	if bodyErr != nil {
		return fmt.Errorf("read body: %w", bodyErr)
	}

	switch {
	case o.outFile != "":
		if err := os.WriteFile(o.outFile, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", o.outFile, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(data), o.outFile)
	case !o.silent:
		os.Stdout.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			fmt.Println()
		}
	}
	return nil
}

// stats accumulates the outcome of a multi-request run.
type stats struct {
	mu       sync.Mutex
	statuses map[int]int
	failures map[string]int

	sent      atomic.Int64
	ok        atomic.Int64
	failed    atomic.Int64
	bodyBytes atomic.Int64

	// latencies holds a strided sample of per-request durations so a very large
	// run cannot turn percentile collection into the run's memory ceiling. The
	// stride is uniform over request index, so the sample is not biased toward
	// the start of the run the way a "keep the first N" cap would be.
	latencies []time.Duration
	stride    int64
}

const maxLatencySamples = 1 << 21 // ~2M samples, 16 MiB

func newStats(n int) *stats {
	stride := int64(1)
	if int64(n) > maxLatencySamples {
		stride = int64(n) / maxLatencySamples
	}
	return &stats{
		statuses: make(map[int]int),
		failures: make(map[string]int),
		stride:   stride,
	}
}

func (s *stats) record(index int64, d time.Duration, code int, err error) {
	s.sent.Add(1)
	if index%s.stride == 0 {
		s.mu.Lock()
		s.latencies = append(s.latencies, d)
		s.mu.Unlock()
	}

	if err != nil {
		s.failed.Add(1)
		s.mu.Lock()
		// Distinct error strings are unbounded — every one can carry a
		// different port or address — so the tail is folded into one bucket
		// rather than letting the map grow with the run.
		if len(s.failures) >= 24 {
			if _, known := s.failures[classify(err)]; !known {
				s.failures["other"]++
				s.mu.Unlock()
				return
			}
		}
		s.failures[classify(err)]++
		s.mu.Unlock()
		return
	}

	s.ok.Add(1)
	s.mu.Lock()
	s.statuses[code]++
	s.mu.Unlock()
}

// classify trims the per-request noise out of an error so the summary groups by
// cause instead of listing one line per ephemeral port.
func classify(err error) string {
	msg := err.Error()
	for _, marker := range []string{
		"tls handshake:", "proxy", "context deadline exceeded",
		"connection refused", "connection reset", "no such host",
		"i/o timeout", "EOF",
	} {
		if strings.Contains(msg, marker) {
			return marker
		}
	}
	if len(msg) > 80 {
		return msg[:80]
	}
	return msg
}

func sendMany(ctx context.Context, client *gofire.Client, o options, target string, body []byte, headers map[string]string) error {
	st := newStats(o.count)

	// The fast path skips the cookie jar, redirect handling and retries, so the
	// template is built once and replayed. It is the throughput path the README
	// documents; the ordinary path is what an application actually uses, so it
	// stays the default.
	var template *http.Request
	if o.fast {
		t, err := newFastTemplate(client, o.method, target, headers, body)
		if err != nil {
			return err
		}
		template = t
	}

	fmt.Fprintf(os.Stderr, "sending %d requests to %s with %d workers\n", o.count, target, o.concurrency)

	var index atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()

	for w := 0; w < o.concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := index.Add(1) - 1
				if i >= int64(o.count) {
					return
				}
				if ctx.Err() != nil {
					return
				}

				reqStart := time.Now()
				var (
					resp *gofire.Response
					err  error
				)
				if template != nil {
					// FastDo makes its own shallow copy and pulls a fresh body
					// from GetBody, so one template serves every worker.
					resp, err = client.FastDo(ctx, template)
				} else {
					resp, err = client.DoWithContext(ctx, o.method, target, body, headers)
				}
				if err != nil {
					st.record(i, time.Since(reqStart), 0, err)
					continue
				}

				// Drain rather than decode: the body is not wanted here, and a
				// full drain is what ends the HTTP/2 stream with END_STREAM.
				// Abandoning it would make the transport emit RST_STREAM, which
				// is the abusive-client signal the whole package avoids.
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				st.bodyBytes.Add(n)
				st.record(i, time.Since(reqStart), resp.StatusCode(), nil)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	// Progress while the run is in flight, so a long or stalled run is visible
	// rather than silent. It is redrawn in place, which only works on a
	// terminal — piped into a file or another program the carriage returns and
	// the erase sequence are literal bytes in the output, so there it is simply
	// not drawn.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	progress := !o.asJSON && isTerminal(os.Stderr)
	drew := false
loop:
	for {
		select {
		case <-done:
			break loop
		case <-ticker.C:
			if progress {
				sent := st.sent.Load()
				fmt.Fprintf(os.Stderr, "\r%d/%d  %.0f req/s  %d failed   ",
					sent, o.count, float64(sent)/time.Since(start).Seconds(), st.failed.Load())
				drew = true
			}
		}
	}
	// Only erase a line that was actually drawn; otherwise the escape sequence
	// is the one piece of noise in an otherwise clean report.
	if drew {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}

	elapsed := time.Since(start)
	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "interrupted after %d requests\n", st.sent.Load())
	}
	return report(st, elapsed, client.ActiveConnections(), o.asJSON)
}

// newFastTemplate builds the request FastDo replays.
//
// A body has to arrive as GetBody rather than as Body: the shallow copy FastDo
// makes shares the single reader, which is consumed after the first send, so a
// template carrying only Body would produce one real POST and then a stream of
// empty ones.
func newFastTemplate(client *gofire.Client, method, target string, headers map[string]string, body []byte) (*http.Request, error) {
	req, err := client.PrepareRequest(method, target)
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	return req, nil
}

func report(st *stats, elapsed time.Duration, conns int64, asJSON bool) error {
	st.mu.Lock()
	lat := append([]time.Duration(nil), st.latencies...)
	statuses := make(map[int]int, len(st.statuses))
	for k, v := range st.statuses {
		statuses[k] = v
	}
	failures := make(map[string]int, len(st.failures))
	for k, v := range st.failures {
		failures[k] = v
	}
	st.mu.Unlock()

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })

	sent := st.sent.Load()
	rps := 0.0
	if elapsed > 0 {
		rps = float64(sent) / elapsed.Seconds()
	}

	if asJSON {
		out := map[string]any{
			"sent":        sent,
			"ok":          st.ok.Load(),
			"failed":      st.failed.Load(),
			"elapsed_ms":  elapsed.Milliseconds(),
			"rps":         rps,
			"body_bytes":  st.bodyBytes.Load(),
			"connections": conns,
			"statuses":    statuses,
			"failures":    failures,
			"latency_ms": map[string]float64{
				"min": ms(percentile(lat, 0)),
				"p50": ms(percentile(lat, 50)),
				"p90": ms(percentile(lat, 90)),
				"p99": ms(percentile(lat, 99)),
				"max": ms(percentile(lat, 100)),
			},
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Fprintf(os.Stderr, "\n%d requests in %s — %.0f req/s\n", sent, round(elapsed), rps)
	fmt.Fprintf(os.Stderr, "ok %d   failed %d   tls connections %d   body %s\n",
		st.ok.Load(), st.failed.Load(), conns, humanBytes(st.bodyBytes.Load()))

	if len(lat) > 0 {
		fmt.Fprintf(os.Stderr, "latency  min %s   p50 %s   p90 %s   p99 %s   max %s\n",
			round(percentile(lat, 0)), round(percentile(lat, 50)), round(percentile(lat, 90)),
			round(percentile(lat, 99)), round(percentile(lat, 100)))
	}

	if len(statuses) > 0 {
		codes := make([]int, 0, len(statuses))
		for code := range statuses {
			codes = append(codes, code)
		}
		sort.Ints(codes)
		fmt.Fprintln(os.Stderr, "\nstatus")
		for _, code := range codes {
			fmt.Fprintf(os.Stderr, "  %d %-24s %d\n", code, statusText(code), statuses[code])
		}
	}

	if len(failures) > 0 {
		type kv struct {
			reason string
			n      int
		}
		list := make([]kv, 0, len(failures))
		for reason, n := range failures {
			list = append(list, kv{reason, n})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
		fmt.Fprintln(os.Stderr, "\nfailures")
		for _, e := range list {
			fmt.Fprintf(os.Stderr, "  %-40s %d\n", e.reason, e.n)
		}
	}
	return nil
}

// percentile returns the p-th percentile of a sorted slice. p is 0-100.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	// Nearest-rank: the smallest value at or above which p% of samples fall.
	idx := (p*len(sorted) + 99) / 100
	if idx > 0 {
		idx--
	}
	return sorted[idx]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// round trims a duration to a readable precision — nanoseconds in a latency
// report are noise.
func round(d time.Duration) time.Duration {
	switch {
	case d >= time.Second:
		return d.Round(10 * time.Millisecond)
	case d >= time.Millisecond:
		return d.Round(100 * time.Microsecond)
	default:
		return d.Round(time.Microsecond)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

func requestBody(spec string) ([]byte, error) {
	if spec == "" {
		return nil, nil
	}
	if strings.HasPrefix(spec, "@") {
		path := spec[1:]
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read body file %s: %w", path, err)
		}
		return data, nil
	}
	return []byte(spec), nil
}

func parseHeaders(list headerList) (map[string]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(list))
	for _, h := range list {
		name, value, _ := strings.Cut(h, ":")
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("header %q has an empty name", h)
		}
		out[name] = strings.TrimSpace(value)
	}
	return out, nil
}

// isTerminal reports whether f is a character device, which is the difference
// between redrawing a progress line in place and writing carriage returns into
// somebody's log file.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// statusText names a status code, falling back to its class for codes net/http
// does not know — a WAF answering 418 or a vendor-specific 5xx should still read
// as something rather than as a bare number.
func statusText(code int) string {
	if text := http.StatusText(code); text != "" {
		return text
	}
	switch {
	case code >= 500:
		return "server error"
	case code >= 400:
		return "client error"
	case code >= 300:
		return "redirect"
	case code >= 200:
		return "success"
	default:
		return "unknown"
	}
}

func parseProfile(name string) (gofire.BrowserProfile, error) {
	switch strings.ToLower(name) {
	case "safari", "safari-ios", "ios":
		return gofire.SafariIOS18, nil
	case "chrome", "chrome151":
		return gofire.Chrome151, nil
	default:
		return 0, fmt.Errorf("unknown browser profile %q (want safari or chrome)", name)
	}
}
