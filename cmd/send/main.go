// Command send drives this client against a real target: one request with the
// response printed, or a load run bounded by a request count or a duration.
//
// It goes through Emulate and the ordinary Client methods rather than a bespoke
// harness, so what it reports is what a program using this library gets.
//
// A run has three dials — how long, how wide, and how many identities:
//
//	-t   how long to keep going (or -n for a fixed count)
//	-c   how many requests are in flight at once
//	-s   how many independent sessions those workers are spread across
//
// A session is a separate Client: its own cookie jar, its own connection pool,
// and — when a proxy list is loaded — its own pinned proxy. One session with
// 200 workers is one browser making 200 parallel requests; 200 sessions with
// 200 workers is 200 browsers making one each, and a target that scores
// per-identity behaviour can tell those apart.
//
//	send https://site.com
//	send -p chrome -i https://site.com
//	send -t 30s -c 100 https://site.com
//	send -n 50000 -c 300 -mode pipeline https://site.com
//	send -t 1m -c 200 -s 50 -proxy-file proxies.txt https://site.com
//	send -X POST -H 'Content-Type: application/json' -d '{"a":1}' https://site.com/api
//
// A target behind a Cloudflare challenge needs the cookie before the run: -solve
// earns one with the real browser in solver/ and seeds it into every session.
//
//	send -solve https://site.com
//	send -solve -t 30s -c 100 -proxy socks5://host:1080 https://site.com
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

// cookieList collects repeated -cookie flags.
type cookieList []string

func (c *cookieList) String() string { return strings.Join(*c, "; ") }

func (c *cookieList) Set(v string) error {
	if !strings.Contains(v, "=") {
		return fmt.Errorf("cookie %q is not in 'name=value' form", v)
	}
	*c = append(*c, v)
	return nil
}

// Send modes. Each is a different entry point into the library, and they are
// not interchangeable: the guarantees drop as the throughput rises.
const (
	// modeClient is Client.DoWithContext — cookie jar, redirects, retries.
	// What an application actually calls.
	modeClient = "client"
	// modeFast is PrepareRequest + FastDo: one prepared template replayed
	// straight into the transport. No jar, no redirects, no retries.
	modeFast = "fast"
	// modePipeline is the Pipeline worker pool with FireAndForget and an
	// OnResult callback, which is the highest-throughput path that still
	// reports per-request outcomes. Bodies drain in the pipeline's own pool.
	modePipeline = "pipeline"
)

type options struct {
	// Request
	method  string
	headers headerList
	body    string
	cookies cookieList

	// Load shape
	count       int
	duration    time.Duration
	concurrency int
	sessions    int
	rate        int
	mode        string
	warmup      int

	// Identity
	profile    string
	profileSet bool // -p was given explicitly, so -solve must not override it
	userAgent  string
	lang       string
	accept     string
	referer    string

	// Challenge solving
	solve        bool
	solverDir    string
	solveTimeout time.Duration

	// Proxy
	proxy         string
	proxyFile     string
	proxyCooldown time.Duration
	proxyFails    int
	proxyStats    bool

	// Network
	timeout       time.Duration
	handshake     time.Duration
	dialTimeout   time.Duration
	headerTimeout time.Duration
	writeTimeout  time.Duration
	dnsTTL        time.Duration
	forceH1       bool
	insecure      bool
	noRedirect    bool
	maxRedirects  int
	retries       int
	noKeepAlive   bool
	maxStreams    int
	idleConns     int
	idlePerHost   int
	connsPerHost  int
	sockBuf       int
	fastOpen      bool
	maxBody       int64

	// Output
	showHeaders bool
	outFile     string
	silent      bool
	asJSON      bool
	fingerprint bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "send:", err)
		os.Exit(1)
	}
}

func run() error {
	o, target, err := parseFlags(os.Args[1:])
	if err != nil {
		return err
	}

	profile, err := parseProfile(o.profile)
	if err != nil {
		return err
	}
	if o.fingerprint {
		printReference(profile)
		if target == "" {
			return nil
		}
	}
	if target == "" {
		return errors.New("exactly one URL is required")
	}

	body, err := requestBody(o.body)
	if err != nil {
		return err
	}
	headers, err := parseHeaders(o.headers)
	if err != nil {
		return err
	}

	// Ctrl-C stops the run and still prints what was collected, which is the
	// point of interrupting a long one. Installed before the solve so a slow
	// challenge can be interrupted too.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Solve before the sessions are built: the cookies and the UA it returns go
	// in through the same options -cookie and -ua use, so every session is
	// seeded at construction rather than patched afterwards.
	if o.solve {
		if profile != gofire.Chrome151 {
			return fmt.Errorf("-solve needs -p chrome: the solver earns the cookie with a real "+
				"Chromium, and %s replays it with a TLS fingerprint the cookie was never issued to", profile)
		}
		if err := solveAndSeed(ctx, o, profile, target); err != nil {
			return err
		}
	}

	pool, err := newSessionPool(o, profile, target)
	if err != nil {
		return err
	}
	defer pool.Close()

	if o.warmup > 0 {
		pool.warm(ctx, target, o.warmup)
	}

	if o.singleShot() {
		return sendOne(ctx, pool.sessions[0].client, o, target, body, headers)
	}
	return sendLoad(ctx, pool, o, target, body, headers)
}

// singleShot reports whether this is the plain one-request invocation, which
// prints the response instead of a summary.
func (o *options) singleShot() bool {
	return o.count == 1 && o.duration == 0
}

func parseFlags(args []string) (*options, string, error) {
	o := &options{}
	fs := flag.NewFlagSet("send", flag.ContinueOnError)

	// Request
	fs.StringVar(&o.method, "X", "GET", "")
	fs.Var(&o.headers, "H", "")
	fs.StringVar(&o.body, "d", "", "")
	fs.Var(&o.cookies, "cookie", "")

	// Load shape
	fs.IntVar(&o.count, "n", 1, "")
	fs.DurationVar(&o.duration, "t", 0, "")
	fs.IntVar(&o.concurrency, "c", 0, "")
	fs.IntVar(&o.sessions, "s", 1, "")
	fs.IntVar(&o.rate, "rate", 0, "")
	fs.IntVar(&o.rate, "rps", 0, "")
	fs.StringVar(&o.mode, "mode", modeClient, "")
	fs.IntVar(&o.warmup, "warmup", 0, "")

	// Identity
	fs.StringVar(&o.profile, "p", "safari", "")
	fs.StringVar(&o.profile, "profile", "safari", "")
	fs.StringVar(&o.userAgent, "ua", "", "")
	fs.StringVar(&o.lang, "lang", "", "")
	fs.StringVar(&o.accept, "accept", "", "")
	fs.StringVar(&o.referer, "referer", "", "")

	// Challenge solving
	fs.BoolVar(&o.solve, "solve", false, "")
	fs.StringVar(&o.solverDir, "solver-dir", "solver", "")
	fs.DurationVar(&o.solveTimeout, "solve-timeout", 75*time.Second, "")

	// Proxy
	fs.StringVar(&o.proxy, "proxy", "", "")
	fs.StringVar(&o.proxyFile, "proxy-file", "", "")
	fs.DurationVar(&o.proxyCooldown, "proxy-cooldown", 0, "")
	fs.IntVar(&o.proxyFails, "proxy-fails", 0, "")
	fs.BoolVar(&o.proxyStats, "proxy-stats", false, "")

	// Network
	fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "")
	fs.DurationVar(&o.handshake, "handshake-timeout", 10*time.Second, "")
	fs.DurationVar(&o.dialTimeout, "dial-timeout", 0, "")
	fs.DurationVar(&o.headerTimeout, "header-timeout", 0, "")
	fs.DurationVar(&o.writeTimeout, "write-timeout", 0, "")
	fs.DurationVar(&o.dnsTTL, "dns-ttl", 0, "")
	fs.BoolVar(&o.forceH1, "http1", false, "")
	fs.BoolVar(&o.insecure, "insecure", false, "")
	fs.BoolVar(&o.noRedirect, "no-redirect", false, "")
	fs.IntVar(&o.maxRedirects, "max-redirects", 0, "")
	fs.IntVar(&o.retries, "retry", 0, "")
	fs.BoolVar(&o.noKeepAlive, "no-keepalive", false, "")
	fs.IntVar(&o.maxStreams, "max-streams", 0, "")
	fs.IntVar(&o.idleConns, "idle-conns", 0, "")
	fs.IntVar(&o.idlePerHost, "idle-per-host", 0, "")
	fs.IntVar(&o.connsPerHost, "conns-per-host", 0, "")
	fs.IntVar(&o.sockBuf, "sockbuf", 0, "")
	fs.BoolVar(&o.fastOpen, "tfo", false, "")
	fs.Int64Var(&o.maxBody, "max-body", -1, "")

	// Output
	fs.BoolVar(&o.showHeaders, "i", false, "")
	fs.StringVar(&o.outFile, "o", "", "")
	fs.BoolVar(&o.silent, "silent", false, "")
	fs.BoolVar(&o.asJSON, "json", false, "")
	fs.BoolVar(&o.fingerprint, "fingerprint", false, "")

	posArgs, flagArgs := splitArgs(args)

	fs.Usage = func() { printUsage(fs.Output()) }
	if err := fs.Parse(flagArgs); err != nil {
		return nil, "", err
	}

	// Whether -p was actually typed decides what -solve is allowed to do with
	// it: defaulting a profile the user never chose is helpful, overriding one
	// they did choose would hide the mismatch that breaks the cookie.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "p" || f.Name == "profile" {
			o.profileSet = true
		}
	})

	target := ""
	if len(posArgs) >= 1 {
		target = posArgs[0]
		if !strings.Contains(target, "://") {
			target = "https://" + target
		}

		argIdx := 1

		// Positional Arg 1: Duration (e.g. 60 or 60s)
		if argIdx < len(posArgs) && o.duration == 0 {
			val := posArgs[argIdx]
			if d, err := time.ParseDuration(val); err == nil && d > 0 {
				o.duration = d
				argIdx++
			} else if sec, err := strconv.Atoi(val); err == nil && sec > 0 {
				o.duration = time.Duration(sec) * time.Second
				argIdx++
			}
		}

		// Positional Arg 2: Concurrency / Threads (-c)
		if argIdx < len(posArgs) && o.concurrency == 0 {
			val := posArgs[argIdx]
			if c, err := strconv.Atoi(val); err == nil && c > 0 {
				o.concurrency = c
				argIdx++
			}
		}

		// Positional Arg 3: Rate / RPS (-rate / -rps)
		if argIdx < len(posArgs) && o.rate == 0 {
			val := posArgs[argIdx]
			if r, err := strconv.Atoi(val); err == nil && r > 0 {
				o.rate = r
				argIdx++
			}
		}
	}

	if target == "" && !o.fingerprint {
		printUsage(os.Stderr)
		return nil, "", errors.New("exactly one URL is required")
	}

	if err := o.normalize(); err != nil {
		return nil, "", err
	}
	return o, target, nil
}

// normalize validates the flags against each other and fills in the defaults
// that depend on other flags.
func (o *options) normalize() error {
	switch o.mode {
	case modeClient, modeFast, modePipeline:
	default:
		return fmt.Errorf("unknown -mode %q (want %s, %s or %s)", o.mode, modeClient, modeFast, modePipeline)
	}
	if o.duration < 0 {
		return fmt.Errorf("-t cannot be negative, got %s", o.duration)
	}
	if o.count < 1 {
		return fmt.Errorf("-n must be at least 1, got %d", o.count)
	}
	if o.sessions < 1 {
		return fmt.Errorf("-s must be at least 1, got %d", o.sessions)
	}
	if o.concurrency < 0 {
		return fmt.Errorf("-c cannot be negative, got %d", o.concurrency)
	}
	if o.rate < 0 {
		return fmt.Errorf("-rate cannot be negative, got %d", o.rate)
	}

	if o.solve {
		// Launching Chromium under Xvfb costs several seconds before the first
		// byte of the challenge is fetched, and the solver's own watchdog only
		// fires at timeout+30s — so a budget too small to launch in does not
		// fail fast, it fails slowly and blames the watchdog. The floor is well
		// under any workable value and only rejects the nonsensical ones.
		if o.solveTimeout < minSolveTimeout {
			return fmt.Errorf("-solve-timeout %s is below the %s a browser launch needs",
				o.solveTimeout, minSolveTimeout)
		}
		// One solve produces one cookie bound to one IP. A rotator hands each
		// session a different exit, so all but the one that happened to match
		// would replay a cookie issued to an address they are not using —
		// which looks like the target blocking the client, not like a config
		// error. Solving per session is a different design, not a flag.
		if o.proxyFile != "" {
			return errors.New("-solve cannot be combined with -proxy-file: cf_clearance is bound " +
				"to the IP that earned it, and a rotator gives each session a different one. " +
				"Use -proxy to solve and replay through a single exit")
		}
		// The solver drives a real Chromium, so the cookie is issued to a Chrome
		// TLS fingerprint. Replaying it from the Safari profile presents a JA4
		// the cookie was never issued to.
		if !o.profileSet {
			o.profile = "chrome"
		}
	}

	// A duration run has no count to bound it, so -n is ignored rather than
	// silently cutting the run short at its default of 1.
	if o.duration > 0 {
		o.count = 0
	}

	if o.concurrency == 0 {
		switch {
		case o.duration > 0:
			o.concurrency = 50
		case o.count == 1:
			o.concurrency = 1
		default:
			o.concurrency = min(o.count, 50)
		}
	}
	if o.count > 0 && o.concurrency > o.count {
		o.concurrency = o.count
	}

	// Every session needs at least one worker, or it would be created, dial
	// its proxy, and then never be used.
	if o.sessions > o.concurrency {
		return fmt.Errorf("-s %d exceeds -c %d: each session needs at least one worker", o.sessions, o.concurrency)
	}
	return nil
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `usage: send [flags] URL

A single request prints the response. Adding -n or -t turns it into a load run
and prints a summary instead.

load shape
  -n int          number of requests (default 1)
  -t duration     run for this long instead of a fixed count, e.g. 30s, 5m
  -c int          concurrent requests in flight (default 50 for a load run)
  -s int          independent sessions to spread the workers across (default 1).
                  Each is its own Client: own cookie jar, own connection pool,
                  and own pinned proxy when -proxy-file is set
  -rps int        hold the whole run at this many requests per second
                  (0 = as fast as it will go). -rate is the same flag

  -mode string    client | fast | pipeline (default client)
                    client   Client.Do — cookie jar, redirects, retries
                    fast     FastDo on a prepared template — none of the above
                    pipeline the Pipeline worker pool, highest throughput
  -warmup int     pre-warm this many TLS connections per session before starting

identity
  -p string       browser profile: safari | chrome (default safari)
  -ua string      override the profile's User-Agent
  -lang string    Accept-Language; match it to where your exit IPs are
  -accept string  override the Accept header
  -referer string Referer header to send
  -cookie k=v     seed a cookie into every session (repeatable)
  -fingerprint    print the profile's reference fingerprint and continue

cloudflare
  -solve                earn a cf_clearance with the real browser in solver/ and
                        seed it into every session before the run. Implies
                        -p chrome unless -p was given: the cookie is bound to the
                        UA and TLS fingerprint that earned it, and the solver
                        drives a real Chromium. Needs npm install in solver/
  -solver-dir path      where index.js and node_modules live (default solver)
  -solve-timeout dur    how long the solve may take (default 75s)

                        -solve routes through -proxy when one is set, because
                        the cookie is bound to the issuing IP too. It cannot be
                        combined with -proxy-file: one solve covers one exit

request
  -X string       HTTP method (default GET)
  -H 'K: v'       extra header (repeatable)
  -d string       request body; @path reads it from a file

proxy
  -proxy url            single proxy, e.g. http://user:pass@host:port or socks5://host:port
  -proxy-file path      file of proxies to rotate, one per line
  -proxy-cooldown dur   how long a failing proxy sits out
  -proxy-fails int      consecutive failures before a proxy is benched
  -proxy-stats          print per-proxy usage after the run

network
  -timeout dur          total per-request timeout (default 30s)
  -handshake-timeout    TLS handshake timeout per attempt (default 10s)
  -dial-timeout dur     TCP dial timeout
  -header-timeout dur   response header timeout
  -write-timeout dur    HTTP/2 frame write timeout
  -dns-ttl dur          DNS cache TTL
  -http1                force HTTP/1.1 instead of negotiating h2
  -insecure             skip TLS certificate verification
  -no-redirect          do not follow redirects
  -max-redirects int    redirect limit
  -retry int            retry attempts on network errors and 429/502/503/504
  -no-keepalive         close connections after each request
  -max-streams int      HTTP/2 streams per connection before it is cycled
  -idle-conns int       total idle connection pool size
  -idle-per-host int    idle connections kept per host
  -conns-per-host int   hard cap on connections per host
  -sockbuf bytes        SO_RCVBUF / SO_SNDBUF size (Linux)
  -tfo                  enable TCP Fast Open (Linux; no browser does this)
  -max-body bytes       response body ceiling, 0 for unlimited

output
  -i              print response headers (single request only)
  -o path         write the response body to a file
  -silent         suppress the response body
  -json           print the run summary as JSON
`)
}

func printReference(profile gofire.BrowserProfile) {
	ref := gofire.ReferenceFor(profile)
	fmt.Fprintf(os.Stderr, "profile        %s\n", ref.Profile)
	fmt.Fprintf(os.Stderr, "captured from  %s\n", ref.Device)
	fmt.Fprintf(os.Stderr, "user-agent     %s\n", ref.UserAgent)
	if ref.JA3Hash != "" {
		fmt.Fprintf(os.Stderr, "ja3            %s\n", ref.JA3Hash)
	} else {
		// Chrome permutes its extension order per connection, so a JA3 is a
		// different value every time by design and there is nothing to pin.
		fmt.Fprintf(os.Stderr, "ja3            (per-connection, extension order is permuted)\n")
	}
	fmt.Fprintf(os.Stderr, "ja4            %s\n", ref.JA4)
	if ref.PeetPrintHash != "" {
		fmt.Fprintf(os.Stderr, "peetprint      %s\n", ref.PeetPrintHash)
	}
	fmt.Fprintf(os.Stderr, "akamai h2      %s\n", ref.AkamaiHash)
	fmt.Fprintf(os.Stderr, "pseudo-headers %s\n", strings.Join(ref.PseudoHeaderOrder, ","))
	fmt.Fprintln(os.Stderr)
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

// splitArgs separates positional arguments from flag options so that positional
// parameters like URL, duration, concurrency, and rate can be given first before flags.
func splitArgs(args []string) (posArgs []string, flagArgs []string) {
	// Every boolean flag has to be listed here. A bool takes no value, so one
	// that is missing swallows whatever follows it — `send -solve https://site`
	// would consume the URL as -solve's argument and then report that no URL was
	// given. There is no way to derive this from the FlagSet at this point,
	// because the split has to happen before Parse.
	boolFlags := map[string]bool{
		"-proxy-stats":  true,
		"-http1":        true,
		"-insecure":     true,
		"-no-redirect":  true,
		"-no-keepalive": true,
		"-tfo":          true,
		"-i":            true,
		"-silent":       true,
		"-json":         true,
		"-fingerprint":  true,
		"-solve":        true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			flagName := strings.TrimLeft(arg, "-")
			if !boolFlags["-"+flagName] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	return posArgs, flagArgs
}
