package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// What a solve actually costs is one challenge per address, not one per line in
// the proxy file — and those are rarely the same number.
//
// A hundred-entry list is usually a provider's gateway addressed a hundred ways:
// a port range onto one pool, or a handful of exits repeated. Cloudflare binds
// cf_clearance to the address it sees, so two entries that leave from the same
// address are one identity and one solve; solving both buys a second copy of the
// first cookie at the price of another full challenge. At 65s each, that is the
// difference between an hour and four minutes.
//
// So the exits are measured before anything is solved. One request per proxy,
// all of them at once, and it answers three questions for the price of one:
//
//   - which entries share an address, so the list collapses to the exits it
//     really has;
//   - which entries are dead, so they cost a second here instead of a 150s
//     solve timeout each;
//   - which entries are rotating, where per-exit solving cannot work at all.
//
// That last one is the reason this is not merely an optimisation. A backconnect
// gateway hands out a different address per connection: the cookie is bound to
// whichever one the browser happened to get, and every request after it leaves
// from somewhere else. The solve appears to succeed, the run 403s from the first
// request, and nothing in the output connects the two. Two probes over two
// connections is what tells them apart.

// defaultExitCheck is Cloudflare's own trace endpoint, which is the point: it
// reports the address as Cloudflare sees it, which is the address cf_clearance
// would be bound to. A generic "what is my IP" service answers a near-enough
// question; this one answers exactly the right one.
const defaultExitCheck = "https://www.cloudflare.com/cdn-cgi/trace"

// exitProbeParallel is how many proxies are measured at once. Far higher than
// -solve-parallel because a probe is one small request, not a browser.
const exitProbeParallel = 16

// exitProbeTimeout bounds one probe. A proxy slower than this is not one worth
// spending a challenge on.
const exitProbeTimeout = 15 * time.Second

// exit is one egress a solve can go out through: the proxy to dial, and the
// address it actually leaves from when that has been measured.
type exit struct {
	proxy string
	ip    string // "" when unmeasured, which is not the same as unknown-and-fine
}

// identity is what the cookie is bound to, and therefore what the cache is
// keyed by. The address when it is known, the proxy string when it is not —
// two entries sharing an address share a cached solve, which is the whole
// point of measuring.
func (e exit) identity() string {
	if e.ip != "" {
		return e.ip
	}
	return e.proxy
}

// label names this exit in output without leaking credentials.
func (e exit) label() string {
	if e.proxy == "" {
		return ""
	}
	if e.ip != "" {
		return fmt.Sprintf("%s (%s)", redactProxy(e.proxy), e.ip)
	}
	return redactProxy(e.proxy)
}

// probeResult is what one measurement found.
type probeResult struct {
	proxy string
	ip    string
	// second is the other address a rotating proxy answered with, kept so the
	// warning can show both rather than assert rotation without evidence.
	second   string
	rotating bool
	err      error
}

// resolveExits measures every proxy and returns one exit per distinct address,
// in the order the addresses were first seen.
//
// Entries that are dead, or that rotate, do not come back: a solve cannot be
// spent on the first and cannot be made to stick on the second.
func resolveExits(ctx context.Context, o *options, profile gofire.BrowserProfile, proxies []string) ([]exit, error) {
	if o.exitCheck == "" {
		// Measuring turned off: every entry is assumed to be its own exit, which
		// is the old behaviour and the old cost.
		exits := make([]exit, 0, len(proxies))
		for _, p := range proxies {
			exits = append(exits, exit{proxy: p})
		}
		return exits, nil
	}

	fmt.Fprintf(os.Stderr, "checking where %d proxies leave from (%s)\n", len(proxies), o.exitCheck)
	start := time.Now()
	results := probeAll(ctx, o, profile, proxies)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var (
		exits    []exit
		seen     = map[string]string{} // address -> the proxy already representing it
		dead     int
		rotating int
		shared   int
	)
	for _, r := range results {
		switch {
		case r.err != nil:
			dead++
			logSolve(r.proxy, "unreachable, dropping it before it costs a solve: %v", r.err)
		case r.rotating:
			rotating++
			logSolve(r.proxy, "hands out a different address per connection (%s then %s) — "+
				"a cf_clearance is bound to one address, so nothing solved here would survive "+
				"the next request. Ask the provider for a sticky or session port",
				r.ip, r.second)
		default:
			if _, ok := seen[r.ip]; ok {
				shared++
				continue
			}
			seen[r.ip] = r.proxy
			exits = append(exits, exit{proxy: r.proxy, ip: r.ip})
		}
	}

	fmt.Fprintf(os.Stderr, "%d proxies resolve to %d exit(s) in %s",
		len(proxies), len(exits), round(time.Since(start)))
	for _, note := range []struct {
		n    int
		what string
	}{
		{shared, "sharing an address with one already counted"},
		{dead, "unreachable"},
		{rotating, "rotating"},
	} {
		if note.n > 0 {
			fmt.Fprintf(os.Stderr, ", %d %s", note.n, note.what)
		}
	}
	fmt.Fprintln(os.Stderr)

	if len(exits) == 0 {
		return nil, fmt.Errorf("none of the %d proxies is a usable exit: %d unreachable, %d rotating. "+
			"Pass -solve-ip-check \"\" to solve through them anyway", len(proxies), dead, rotating)
	}
	return exits, nil
}

// probeAll measures every proxy, at most exitProbeParallel at a time, and
// returns the results in the order given.
func probeAll(ctx context.Context, o *options, profile gofire.BrowserProfile, proxies []string) []probeResult {
	results := make([]probeResult, len(proxies))
	slots := make(chan struct{}, exitProbeParallel)

	var wg sync.WaitGroup
	for i, proxy := range proxies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				results[i] = probeResult{proxy: proxy, err: ctx.Err()}
				return
			}
			results[i] = probeExit(ctx, o, profile, proxy)
		}()
	}
	wg.Wait()
	return results
}

// probeExit asks one proxy where it leaves from, more than once.
//
// More than once, over separate connections, because one answer cannot tell a
// fixed exit from a rotating one — and those need opposite handling. Keep-alives
// are off for exactly that reason: a reused connection would return the same
// address by construction and prove nothing.
//
// This is a filter, not a proof. A gateway rotating over a small pool can hand
// out the same address several times running, and no bounded number of samples
// rules that out — two samples miss a two-address pool half the time, which is
// not a rare enough shape to design around. Three is where the cost stops
// buying much: a rotating exit usually announces itself on the second read (the
// loop stops there), so the third is only paid by exits that look stable, and
// 200 of these took under a second against a hundred proxies. What survives an
// undetected rotation is a session that 403s, which the run's own failure tally
// shows — worse than catching it here, better than silence.
const exitProbeSamples = 3

func probeExit(ctx context.Context, o *options, profile gofire.BrowserProfile, proxy string) probeResult {
	var first string
	for i := 0; i < exitProbeSamples; i++ {
		ip, err := fetchExitIP(ctx, o, profile, proxy)
		if err != nil {
			if i == 0 {
				return probeResult{proxy: proxy, err: err}
			}
			// One answer is still worth having: the proxy works, and an exit
			// that failed a later read is more likely busy than rotating.
			// Calling that rotation would drop a working proxy on one timeout.
			break
		}
		if i == 0 {
			first = ip
			continue
		}
		if ip != first {
			return probeResult{proxy: proxy, ip: first, second: ip, rotating: true}
		}
	}
	return probeResult{proxy: proxy, ip: first}
}

// fetchExitIP performs one measurement through proxy.
//
// It goes through Emulate rather than net/http so the request that measures the
// exit is shaped like the ones that will use it — a proxy that only fails for
// this client is one worth finding out about here rather than mid-run.
func fetchExitIP(ctx context.Context, o *options, profile gofire.BrowserProfile, proxy string) (string, error) {
	opts := []gofire.Option{
		gofire.WithProxy(proxy),
		gofire.WithTimeout(exitProbeTimeout),
		gofire.WithTLSHandshakeTimeout(exitProbeTimeout),
		// A fresh connection per probe is the measurement: see probeExit.
		gofire.WithDisableKeepAlives(),
		gofire.WithAcceptLanguage(acceptLanguage(o)),
	}
	// -insecure is a decision the user already made about this run; a probe that
	// ignored it would reject the exits the run itself would have accepted.
	if o.insecure {
		opts = append(opts, gofire.WithInsecureSkipVerify())
	}

	client, err := gofire.Emulate(profile, opts...)
	if err != nil {
		return "", err
	}
	defer client.Close()

	probeCtx, cancel := context.WithTimeout(ctx, exitProbeTimeout)
	defer cancel()

	resp, err := client.DoWithContext(probeCtx, "GET", o.exitCheck, nil, nil)
	if err != nil {
		return "", err
	}
	defer resp.Close()

	body, err := resp.Bytes()
	if err != nil {
		return "", fmt.Errorf("read %s: %w", o.exitCheck, err)
	}
	ip := parseExitIP(string(body))
	if ip == "" {
		return "", fmt.Errorf("%s did not report an address", o.exitCheck)
	}
	return ip, nil
}

// parseExitIP reads the address out of what the check returned.
//
// Cloudflare's trace endpoint answers key=value lines, of which ip= is the one
// that matters. A body that is just an address — which is what every other
// what-is-my-ip service returns — is accepted too, so -solve-ip-check can point
// at one of those without needing a second parser.
func parseExitIP(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			return strings.TrimSpace(rest)
		}
	}
	trimmed := strings.TrimSpace(body)
	// Bare-address form. Bounded and single-line so an HTML error page is not
	// mistaken for an answer.
	if trimmed != "" && len(trimmed) <= 45 && !strings.ContainsAny(trimmed, " \t\n<") {
		return trimmed
	}
	return ""
}
