package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cacheOptions(t *testing.T) *options {
	t.Helper()
	return &options{
		solverDir:    t.TempDir(),
		solveTimeout: 30 * time.Second,
		solveCache:   t.TempDir(),
		solveMaxAge:  30 * time.Minute,
	}
}

func clearance(value string, expires time.Time) solvedCookie {
	c := solvedCookie{Name: "cf_clearance", Value: value, Domain: ".site.test"}
	if !expires.IsZero() {
		c.Expires = float64(expires.Unix())
	}
	return c
}

func TestSolveCacheRoundTrip(t *testing.T) {
	o := cacheOptions(t)
	res := &solveResult{
		UserAgent:  "UA-151",
		CookieList: []solvedCookie{clearance("abc", time.Now().Add(time.Hour)), {Name: "__cf_bm", Value: "bm"}},
	}
	storeSolveCache(o.solveCache, "https://site.test/", "", res)

	e := loadSolveCache(o.solveCache, "https://site.test/", "", o.solveMaxAge)
	if e == nil {
		t.Fatal("a fresh entry did not load back")
	}
	if e.UserAgent != "UA-151" || len(e.Cookies) != 2 {
		t.Fatalf("entry = %+v", e)
	}

	seed := seedFromCache("", e, false)
	if seed.userAgent != "UA-151" {
		t.Errorf("userAgent = %q, want the solved one", seed.userAgent)
	}
	// The entry keeps everything the browser had; the seed takes only what
	// travels, so -solve-all-cookies can change its mind without a fresh solve.
	if len(seed.cookies) != 1 || seed.cookies[0] != "cf_clearance=abc" {
		t.Errorf("cookies = %v, want the clearance alone", seed.cookies)
	}
	if all := seedFromCache("", e, true); len(all.cookies) != 2 {
		t.Errorf("-solve-all-cookies gave %v, want both", all.cookies)
	}
}

// The language the cookie was earned under has to survive the cache, because
// session.go pins the replay to the seed's value only when it has one.
//
// It did not, so the first run replayed the header the browser actually sent and
// every run after it — the cached ones, which is most of them — fell through to
// -lang's raw value instead. Against a cookie earned under "de-DE,de;q=0.9" that
// is a replay advertising a bare "de-DE": the drift the fresh path exists to
// prevent, reappearing on the path taken by default.
func TestSolveCacheKeepsTheLanguageTheCookieWasEarnedUnder(t *testing.T) {
	o := cacheOptions(t)
	res := &solveResult{
		UserAgent:      "UA-151",
		AcceptLanguage: "de-DE,de;q=0.9",
		CookieList:     []solvedCookie{clearance("abc", time.Now().Add(time.Hour))},
	}
	storeSolveCache(o.solveCache, "https://site.test/", "", res)

	e := loadSolveCache(o.solveCache, "https://site.test/", "", o.solveMaxAge)
	if e == nil {
		t.Fatal("a fresh entry did not load back")
	}
	if e.AcceptLanguage != "de-DE,de;q=0.9" {
		t.Errorf("entry AcceptLanguage = %q, want the header the solve sent", e.AcceptLanguage)
	}
	if seed := seedFromCache("", e, false); seed.acceptLanguage != "de-DE,de;q=0.9" {
		t.Errorf("seed acceptLanguage = %q, want the header the solve sent", seed.acceptLanguage)
	}
}

// An entry written before the language was recorded still has to load, and to
// behave the way it always did rather than claiming a language it never saw.
func TestSolveCacheEntryWithoutALanguageStillLoads(t *testing.T) {
	o := cacheOptions(t)
	raw := `{"host":"site.test","proxy":"","user_agent":"UA-151",` +
		`"cookies":[{"name":"cf_clearance","value":"abc","domain":".site.test"}],` +
		`"solved_at":"` + time.Now().Format(time.RFC3339) + `"}`
	if err := os.MkdirAll(o.solveCache, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(o.solveCache, solveCacheKey("https://site.test/", "")+".json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	e := loadSolveCache(o.solveCache, "https://site.test/", "", o.solveMaxAge)
	if e == nil {
		t.Fatal("an entry without a language did not load")
	}
	if seed := seedFromCache("", e, false); seed.acceptLanguage != "" {
		t.Errorf("acceptLanguage = %q, want empty so session.go falls back as before", seed.acceptLanguage)
	}
}

// The cookie is only reusable by a run presenting the same identity, and the
// key is what enforces that. A different host or exit must miss.
func TestSolveCacheKeyedByHostAndProxy(t *testing.T) {
	o := cacheOptions(t)
	res := &solveResult{UserAgent: "UA", CookieList: []solvedCookie{clearance("abc", time.Now().Add(time.Hour))}}
	storeSolveCache(o.solveCache, "https://site.test/", "http://exit:8080", res)

	if loadSolveCache(o.solveCache, "https://other.test/", "http://exit:8080", o.solveMaxAge) != nil {
		t.Error("another host reused this host's clearance")
	}
	if loadSolveCache(o.solveCache, "https://site.test/", "", o.solveMaxAge) != nil {
		t.Error("a direct run reused a clearance earned through a proxy")
	}
	if loadSolveCache(o.solveCache, "https://site.test/", "http://other:8080", o.solveMaxAge) != nil {
		t.Error("another exit reused this exit's clearance")
	}
	if loadSolveCache(o.solveCache, "https://site.test/path?q=1", "http://exit:8080", o.solveMaxAge) == nil {
		t.Error("a different path on the same host missed; the key is the host")
	}
}

// Serving an expired clearance would replay a dead cookie and look exactly like
// the target blocking the client.
func TestSolveCacheRejectsExpired(t *testing.T) {
	o := cacheOptions(t)
	res := &solveResult{UserAgent: "UA", CookieList: []solvedCookie{clearance("abc", time.Now().Add(-time.Minute))}}
	storeSolveCache(o.solveCache, "https://site.test/", "", res)

	if loadSolveCache(o.solveCache, "https://site.test/", "", o.solveMaxAge) != nil {
		t.Error("an expired clearance was served from the cache")
	}
}

func TestSolveCacheRejectsTooOld(t *testing.T) {
	o := cacheOptions(t)
	// Long-lived cookie, but the entry itself is stale: Cloudflare can
	// invalidate server-side well before the stated expiry.
	res := &solveResult{UserAgent: "UA", CookieList: []solvedCookie{clearance("abc", time.Now().Add(365*24*time.Hour))}}
	storeSolveCache(o.solveCache, "https://site.test/", "", res)

	path := filepath.Join(o.solveCache, solveCacheKey("https://site.test/", "")+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	aged := strings.Replace(string(raw), time.Now().Format("2006"), "2020", 1)
	if err := os.WriteFile(path, []byte(aged), 0o600); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	if loadSolveCache(o.solveCache, "https://site.test/", "", 30*time.Minute) != nil {
		t.Error("an entry older than -solve-max-age was served")
	}
	if loadSolveCache(o.solveCache, "https://site.test/", "", 0) == nil {
		t.Error("-solve-max-age 0 should disable the age check, not everything")
	}
}

// A cache that cannot be read must cost a solve, never a run.
func TestSolveCacheTreatsGarbageAsMiss(t *testing.T) {
	o := cacheOptions(t)
	path := filepath.Join(o.solveCache, solveCacheKey("https://site.test/", "")+".json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if loadSolveCache(o.solveCache, "https://site.test/", "", o.solveMaxAge) != nil {
		t.Error("unparseable cache was used")
	}
	if loadSolveCache("", "https://site.test/", "", o.solveMaxAge) != nil {
		t.Error("an empty cache path should disable the cache")
	}
	if loadSolveCache(t.TempDir(), "https://site.test/", "", o.solveMaxAge) != nil {
		t.Error("an empty directory returned an entry")
	}
}

// An entry with no cookies is not a solve worth reusing.
func TestSolveCacheIgnoresEmptySolves(t *testing.T) {
	o := cacheOptions(t)
	storeSolveCache(o.solveCache, "https://site.test/", "", &solveResult{UserAgent: "UA"})
	if loadSolveCache(o.solveCache, "https://site.test/", "", o.solveMaxAge) != nil {
		t.Error("a cookieless solve was cached")
	}
}

// The file holds a bearer token for the origin.
func TestSolveCacheFileIsNotWorldReadable(t *testing.T) {
	o := cacheOptions(t)
	res := &solveResult{UserAgent: "UA", CookieList: []solvedCookie{clearance("abc", time.Now().Add(time.Hour))}}
	storeSolveCache(o.solveCache, "https://site.test/", "", res)

	info, err := os.Stat(filepath.Join(o.solveCache, solveCacheKey("https://site.test/", "")+".json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("cache file mode is %04o, want no group or other access", perm)
	}
}

// -solve-refresh is a bool; splitArgs must not swallow the URL after it.
func TestSolveRefreshParses(t *testing.T) {
	o, target, err := parseFlags([]string{"-solve", "-solve-refresh", "https://site.test"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if target != "https://site.test" {
		t.Errorf("target = %q", target)
	}
	if !o.solveRefresh {
		t.Error("-solve-refresh was not set")
	}
}
