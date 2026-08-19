package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/solver"
)

// -solve-replay answers the question a 403 after a successful solve leaves open.
//
// Two very different things produce that symptom, and from outside they are
// identical — a fresh interstitial either way:
//
//  1. the client replaying the cookie does not look enough like the browser that
//     earned it, so the edge rejects a cookie that is otherwise fine; or
//  2. the clearance is not replayable at all — the zone re-scores every request,
//     the address is on a datacenter range, or the challenge bound the cookie to
//     the session that solved it.
//
// They have opposite answers. The first is fingerprint work in this repo; the
// second is not work at all, it is a different exit. So this takes the cookies a
// solve already earned, puts them in a fresh context of the same browser, and
// navigates from this same address — the challenge is not solved again, only its
// cookie presented.
//
// It lives in `send` rather than in a tool of its own because the cache it reads
// is this command's: solvecache.go wrote it, and reproducing the keying
// elsewhere is how the Node version ended up looking in ~/.cache on Windows
// while send wrote to %LocalAppData%.
func runSolveReplay(ctx context.Context, o *options, target string) error {
	entry, err := newestCachedSolve(o.solveCache, target)
	if err != nil {
		return err
	}

	cookies := make([]solver.Cookie, 0, len(entry.Cookies))
	for _, c := range entry.Cookies {
		cookies = append(cookies, solver.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Expires: c.Expires,
		})
	}

	fmt.Fprintf(os.Stderr, "replaying %d cookies earned %s ago through %s\n",
		len(cookies), time.Since(entry.SolvedAt).Round(time.Second),
		exitLabel(entry.Proxy))

	report, err := solver.Replay(ctx, solverOptions(o, target), entry.Proxy, cookies)
	if err != nil {
		return err
	}

	// The JSON on stdout, so it can be piped; the words on stderr, so they
	// cannot get into anything parsing it. This tool exists to say which case
	// you are in, and the Node version made you work that out from four nested
	// objects — which is exactly the kind of reading that produces a confident
	// wrong answer.
	out, err := json.Marshal(report)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	fmt.Fprintln(os.Stderr, "\n"+solver.Explain(report.Verdict))

	// A cookie that never went out cannot have been refused, and reporting it as
	// refused is the failure this check exists to catch.
	if report.Carried != nil && len(report.Carried.NotSent) > 0 {
		fmt.Fprintf(os.Stderr,
			"\nwarning: %v were never sent, so this attempt did not measure what it looks like it did\n",
			report.Carried.NotSent)
	}
	return nil
}

// newestCachedSolve finds the most recent cached solve for this target's host.
//
// The cache is keyed by a hash of host and proxy, and the proxy is not known
// here — a replay is asking about whatever was solved last. So every entry is
// read and the newest one for this host wins. There are only ever a handful.
func newestCachedSolve(dir, target string) (*solveCacheEntry, error) {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid url %q", target)
	}
	host := u.Hostname()

	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(names) == 0 {
		return nil, fmt.Errorf("no cached solve in %s — run `send -solve %s` first", dir, target)
	}
	sort.Strings(names)

	var newest *solveCacheEntry
	for _, name := range names {
		data, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		var entry solveCacheEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		// The cache keys on u.Host, which carries the port; the replay is asked
		// about a hostname. Match either way round so a cached
		// "example.com:8443" is still found for "https://example.com:8443/".
		if entry.Host != host && entry.Host != u.Host {
			continue
		}
		if len(entry.Cookies) == 0 {
			continue
		}
		if newest == nil || entry.SolvedAt.After(newest.SolvedAt) {
			e := entry
			newest = &e
		}
	}
	if newest == nil {
		return nil, fmt.Errorf("no cached solve for %s in %s — run `send -solve %s` first",
			host, dir, target)
	}
	return newest, nil
}

func exitLabel(proxy string) string {
	if proxy == "" {
		return "this address directly"
	}
	return redactProxy(proxy)
}
