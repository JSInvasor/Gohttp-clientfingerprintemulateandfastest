package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// A solved cf_clearance is expensive and reusable, and it was being thrown away
// after every run.
//
// Most of a solve is Cloudflare's own challenge: its JavaScript runs, the
// Turnstile widget executes, and the edge decides. A real browser pays that too
// — there is nothing to optimise away. What there is, is not paying it again
// for a cookie that is still valid. The cookie outlives the process by design;
// only the process was forgetting it.
//
// The entry is keyed by everything the cookie is bound to. Cloudflare ties
// cf_clearance to the User-Agent, the TLS fingerprint and the source IP, so a
// cached cookie is only reusable by a run presenting the same three. Host,
// proxy and UA cover what this tool can vary; the fingerprint follows from the
// profile, which -solve pins to Chrome.

type solveCacheEntry struct {
	Host      string         `json:"host"`
	Proxy     string         `json:"proxy"`
	UserAgent string         `json:"user_agent"`
	Cookies   []solvedCookie `json:"cookies"`
	SolvedAt  time.Time      `json:"solved_at"`
	ExpiresAt time.Time      `json:"expires_at"` // from cf_clearance, zero when absent

	// ChromiumMajor is the browser that earned these cookies, so a reused solve
	// reports the same fingerprint drift a fresh one would. Absent in entries
	// written before this was recorded, which reads back as 0 — "not measured",
	// which the check skips rather than treats as a match.
	ChromiumMajor int `json:"chromium_major,omitempty"`
}

// solveCacheKey identifies a reusable solve. The UA is not in the key: it is
// what the solver returns, so it is a property of the entry rather than of the
// lookup.
func solveCacheKey(target, proxy string) string {
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Host
	}
	sum := sha256.Sum256([]byte(host + "\x00" + proxy))
	return hex.EncodeToString(sum[:8])
}

// defaultSolveCachePath keeps solved cookies out of the working tree. They are
// credentials in every sense that matters.
func defaultSolveCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "gofire", "solve-cache")
}

// loadSolveCache returns a usable entry, or nil when there is none. Anything
// unreadable or unparseable is treated as a miss: a bad cache must cost a solve,
// never a run.
func loadSolveCache(path, target, proxy string, maxAge time.Duration) *solveCacheEntry {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(path, solveCacheKey(target, proxy)+".json"))
	if err != nil {
		return nil
	}
	var e solveCacheEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil
	}
	if len(e.Cookies) == 0 {
		return nil
	}
	now := time.Now()
	if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
		return nil
	}
	if maxAge > 0 && now.Sub(e.SolvedAt) > maxAge {
		return nil
	}
	return &e
}

// storeSolveCache writes the entry, best-effort. A cache that cannot be written
// is not worth failing a successful solve over — it only costs the next run.
func storeSolveCache(path, target, proxy string, res *solveResult) {
	if path == "" || len(res.CookieList) == 0 {
		return
	}
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Host
	}
	e := solveCacheEntry{
		Host:          host,
		Proxy:         proxy,
		UserAgent:     res.UserAgent,
		Cookies:       res.CookieList,
		SolvedAt:      time.Now(),
		ChromiumMajor: res.ChromiumMajor,
	}
	for _, c := range res.CookieList {
		if c.Name == "cf_clearance" && c.Expires > 0 {
			e.ExpiresAt = time.Unix(int64(c.Expires), 0)
		}
	}

	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return
	}
	// 0600: this file holds a cf_clearance, which is a bearer token for the
	// origin until it expires.
	_ = os.WriteFile(filepath.Join(path, solveCacheKey(target, proxy)+".json"), raw, 0o600)
}

// seedFromCache turns a cached entry into the seed a fresh solve through this
// exit would have produced, so the caller cannot tell the two apart.
func seedFromCache(proxy string, e *solveCacheEntry) *solveSeed {
	age := time.Since(e.SolvedAt).Truncate(time.Second)
	left := "unknown"
	if !e.ExpiresAt.IsZero() {
		left = time.Until(e.ExpiresAt).Truncate(time.Second).String()
	}
	logSolve(proxy, "reusing the solve from %s ago (%d cookie(s), expires in %s) — "+
		"pass -solve-refresh to earn a new one", age, len(e.Cookies), left)

	seed := &solveSeed{proxy: proxy, userAgent: e.UserAgent, chromiumMajor: e.ChromiumMajor}
	for _, c := range e.Cookies {
		seed.cookies = append(seed.cookies, c.Name+"="+c.Value)
	}
	return seed
}
