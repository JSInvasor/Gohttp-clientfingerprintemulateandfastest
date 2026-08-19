// Command send drives this client against a real target: one request with the
// response printed, or a load run bounded by a request count or a duration.
//
// It goes through Emulate and the ordinary Client methods rather than a bespoke
// harness, so what it reports is what a program using this library gets.
//
// A run has four dials, each with a positional form taken in this order after
// the URL:
//
//	send URL [duration] [threads] [clients] [rate]
//
//	-t    duration  how long to keep going (or -n for a fixed count)
//	-c    threads   how many requests are in flight at once
//	-s    clients   how many independent sessions those threads spread across
//	-rps  rate      hold the whole run at this many requests per second
//
// Giving the flag skips that slot, so `send URL 100 -t 30s` means 100 threads.
// Anything the dials cannot place is reported rather than dropped, because a
// dial that shifts by one runs the wrong shape and still prints a summary.
//
// A client is a separate Client: its own cookie jar, its own connection pool,
// and — when a proxy list is loaded — its own pinned proxy. One client with
// 200 threads is one browser making 200 parallel requests; 200 clients with
// 200 threads is 200 browsers making one each, and a target that scores
// per-identity behaviour can tell those apart.
//
//	send https://site.com
//	send -p chrome -i https://site.com
//	send https://site.com 30s 100
//	send https://site.com 30s 100 8 500
//	send https://site.com 1m 200 50 -proxy-file proxies.txt
//	send -n 50000 -c 300 -mode pipeline https://site.com
//	send -X POST -H 'Content-Type: application/json' -d '{"a":1}' https://site.com/api
//
// Which dials to use is itself a question about the target, and -scout answers
// it by going and looking — who is in front, whether it challenges, what it
// sets, how far away it is — and then printing the command with the measurement
// behind every flag in it. It does not look for the rate ceiling: -c is the
// measured round trip times a rate you pick, not something discovered by
// pushing until the target pushes back.
//
//	send -scout https://site.com
//	send -scout https://site.com -proxy-file proxies.txt
//
// A target behind a Cloudflare challenge needs the cookie before the run: -solve
// earns one with the real browser in solver/ and seeds it into every session.
//
//	send -solve https://site.com
//	send -solve https://site.com 30s 100 -proxy socks5://host:1080
//	send -solve https://site.com 1m 100 8 -proxy-file proxies.txt
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
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
	// OnResult callback. Bodies drain in the pipeline's own pool, which is what
	// it is for — submission control and per-request outcomes without a channel
	// per request. It is not the fastest: measured, fast beats it at every
	// concurrency tried, since the drain handoff costs two channel hops a
	// request.
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

	// Page shape
	assets        bool
	assetLimit    int
	assetParallel int

	// Challenge solving
	solve bool
	// chromePath is the browser to drive. Empty means discovery — see
	// solver.CheckBrowser. It replaced -solver-dir, which pointed at the Node
	// solver's script and its npm tree; the solver is compiled in now, so the
	// only thing left to point at is a browser.
	chromePath    string
	solveTimeout  time.Duration
	solveCache    string
	solveRefresh  bool
	solveMaxAge   time.Duration
	solveParallel int
	exitCheck     string
	solveIsolate  bool
	// solveReplay measures whether cookies already earned still work, instead of
	// making a run. See solvereplay.go.
	solveReplay bool
	// solveAllCookies seeds everything the solve captured, including Cloudflare's
	// per-session bookkeeping. Off by default — see splitSolvedCookies.
	solveAllCookies bool

	// solveSeeds is what -solve earned, one entry per exit, filled in before the
	// session pool is built. Empty when the run solves nothing or has a single
	// identity — that one goes into cookies and userAgent instead.
	solveSeeds []solveSeed

	// Proxy
	proxy         string
	proxyFile     string
	proxyCooldown time.Duration
	proxyFails    int
	proxyStats    bool

	// proxyList narrows proxyFile to the exits a solve actually earned a cookie
	// through. Empty means the file itself is the list.
	proxyList []string

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
	tlsResume     bool
	maxBody       int64

	// Output
	showHeaders bool
	outFile     string
	silent      bool
	asJSON      bool
	fingerprint bool
	scout       bool
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

	// -solve-replay is a measurement rather than a run: it asks whether a cookie
	// already earned still works, which is the question a 403 after a successful
	// solve leaves open. Nothing below it happens — there is no run to seed.
	if o.solveReplay {
		return runSolveReplay(ctx, o, target)
	}

	// -scout answers the questions the other flags ask, and then goes no
	// further: it is a handful of requests and a command to paste, not a run.
	// Nothing below it happens, because a solve or a session pool built on
	// settings the scout was about to argue with is the opposite of the point.
	if o.scout {
		report, err := scout(ctx, o, profile, target)
		if err != nil {
			return err
		}
		renderScout(os.Stdout, report, recommend(report, o))
		return nil
	}

	// Solve before the sessions are built: the cookies and the UA it returns go
	// in through the same options -cookie and -ua use, so every session is
	// seeded at construction rather than patched afterwards.
	if o.solve {
		if profile != gofire.Chrome151 {
			return fmt.Errorf("-solve needs -p chrome: the solver earns the cookie with a real "+
				"Chromium, and %s replays it with a TLS fingerprint the cookie was never issued to", profile)
		}
		// A list of exits is a list of identities: the cookie is bound to the IP
		// that earned it, so each one is solved and seeded separately rather
		// than sharing a single solve none of them would match.
		solve := solveAndSeed
		if o.proxyFile != "" {
			solve = solveAcrossProxies
		}
		if err := solve(ctx, o, profile, target); err != nil {
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

// newFlagSet declares every flag send accepts.
//
// Separate from parseFlags so the declarations have one home: splitArgs reads
// which of them are booleans straight off this set, and the tests walk it to
// check that none of them swallows the argument after it.
func newFlagSet(o *options) *flag.FlagSet {
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

	// Page shape
	fs.BoolVar(&o.assets, "assets", false, "")
	fs.IntVar(&o.assetLimit, "asset-limit", 25, "")
	fs.IntVar(&o.assetParallel, "asset-parallel", 6, "")

	fs.BoolVar(&o.solve, "solve", false, "")
	fs.StringVar(&o.chromePath, "chrome", "", "")
	fs.DurationVar(&o.solveTimeout, "solve-timeout", defaultSolveTimeout, "")
	fs.StringVar(&o.solveCache, "solve-cache", defaultSolveCachePath(), "")
	fs.BoolVar(&o.solveRefresh, "solve-refresh", false, "")
	fs.DurationVar(&o.solveMaxAge, "solve-max-age", 30*time.Minute, "")
	fs.IntVar(&o.solveParallel, "solve-parallel", 2, "")
	fs.StringVar(&o.exitCheck, "solve-ip-check", defaultExitCheck, "")
	fs.BoolVar(&o.solveIsolate, "solve-isolate", false, "")
	fs.BoolVar(&o.solveAllCookies, "solve-all-cookies", false, "")
	fs.BoolVar(&o.solveReplay, "solve-replay", false, "")

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
	fs.BoolVar(&o.tlsResume, "tls-resume", false, "")
	fs.Int64Var(&o.maxBody, "max-body", -1, "")

	// Output
	fs.BoolVar(&o.showHeaders, "i", false, "")
	fs.StringVar(&o.outFile, "o", "", "")
	fs.BoolVar(&o.silent, "silent", false, "")
	fs.BoolVar(&o.asJSON, "json", false, "")
	fs.BoolVar(&o.fingerprint, "fingerprint", false, "")
	fs.BoolVar(&o.scout, "scout", false, "")

	return fs
}

func parseFlags(args []string) (*options, string, error) {
	o := &options{}
	fs := newFlagSet(o)

	posArgs, flagArgs := splitArgs(fs, args)

	fs.Usage = func() { printUsage(fs.Output()) }
	if err := fs.Parse(flagArgs); err != nil {
		return nil, "", err
	}

	// Which flags were actually typed, rather than left at their default. A
	// positional must not overwrite a flag the user gave, and "was it given"
	// cannot be inferred from the value: -s defaults to 1, so a zero check
	// cannot tell `-s 1` from an -s that was never mentioned.
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	// -solve leaves an unset profile alone to default to chrome, but must not
	// override one the user chose: that would hide the mismatch that breaks the
	// cookie rather than surface it.
	o.profileSet = given["p"] || given["profile"]

	target := ""
	if len(posArgs) >= 1 {
		target = posArgs[0]
		if !strings.Contains(target, "://") {
			target = "https://" + target
		}

		rest, err := applyPositionalDials(o, posArgs[1:], given)
		if err != nil {
			return nil, "", err
		}
		if len(rest) > 0 {
			// Silently dropping these is how `URL 30s 100 8 500` used to run
			// with the wrong shape: the extra value landed nowhere and the run
			// started anyway, reporting numbers for settings nobody asked for.
			return nil, "", fmt.Errorf("unexpected argument %q — the positional dials are "+
				"URL [duration] [threads] [clients] [rate]", rest[0])
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
		// One solve produces one cookie bound to one IP, so a rotator needs one
		// per exit rather than one per run — see solvefleet.go. Which is a
		// browser launch and a challenge each, so the parallelism is a knob
		// rather than a constant.
		if o.solveParallel < 1 {
			return fmt.Errorf("-solve-parallel must be at least 1, got %d", o.solveParallel)
		}
		// The rotator wins at dial time, so -proxy would be solved through and
		// then never used — every session replaying a cookie earned at an
		// address it does not dial from. Ambiguity about which exit a cookie
		// belongs to is the one thing this must not have.
		if o.proxy != "" && o.proxyFile != "" {
			return errors.New("-solve takes -proxy or -proxy-file, not both: the list is what " +
				"the sessions dial through, so a cookie solved through -proxy would be replayed " +
				"from an exit it was never issued to")
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

// applyPositionalDials fills the load-shape dials from the arguments following
// the URL, in the order the usage text advertises:
//
//	URL [duration] [threads] [clients] [rate]
//
// It returns whatever it could not place, which the caller rejects. Each dial is
// skipped when the matching flag was given, so `-t 30s URL 100` means 100
// threads rather than a duration fighting with -t.
//
// A dial only consumes its argument when the value actually fits: anything that
// is not a positive number stops the walk and comes back as leftover, so a typo
// is reported rather than silently shifting every dial after it by one.
func applyPositionalDials(o *options, args []string, given map[string]bool) ([]string, error) {
	i := 0

	// Duration accepts both 30s and a bare count of seconds.
	if i < len(args) && !given["t"] {
		if d, err := time.ParseDuration(args[i]); err == nil && d > 0 {
			o.duration = d
			i++
		} else if sec, err := strconv.Atoi(args[i]); err == nil && sec > 0 {
			o.duration = time.Duration(sec) * time.Second
			i++
		}
	}

	// The remaining three are plain positive counts.
	dials := []struct {
		flags []string
		set   func(int)
	}{
		{[]string{"c"}, func(v int) { o.concurrency = v }},    // threads
		{[]string{"s"}, func(v int) { o.sessions = v }},       // clients
		{[]string{"rate", "rps"}, func(v int) { o.rate = v }}, // rate
	}
	for _, d := range dials {
		if i >= len(args) {
			break
		}
		if slices.ContainsFunc(d.flags, func(name string) bool { return given[name] }) {
			continue
		}
		v, err := strconv.Atoi(args[i])
		if err != nil || v <= 0 {
			break
		}
		d.set(v)
		i++
	}

	return args[i:], nil
}

// splitArgs separates positional arguments from flag options so that positional
// parameters like URL, duration, threads, clients and rate can be given before
// the flags.
//
// Which names are booleans comes from the FlagSet rather than from a list kept
// by hand. It matters because a bool takes no value, so one that is missing from
// such a list swallows whatever follows it — `send -solve https://site` would
// consume the URL as -solve's argument and then report that no URL was given.
//
// The list lived here because the split has to happen before Parse, and that is
// true; but registration is not parsing. Every flag is declared by the time this
// runs, so the FlagSet can simply be asked, and a bool added later cannot be
// forgotten.
func splitArgs(fs *flag.FlagSet, args []string) (posArgs []string, flagArgs []string) {
	isBool := func(name string) bool {
		f := fs.Lookup(name)
		if f == nil {
			return false
		}
		// The flag package marks value-less flags with this method, and reads it
		// the same way to decide whether -x consumes what follows it.
		bf, ok := f.Value.(interface{ IsBoolFlag() bool })
		return ok && bf.IsBoolFlag()
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			flagName := strings.TrimLeft(arg, "-")
			if !isBool(flagName) && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	return posArgs, flagArgs
}
