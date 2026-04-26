package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// SolverServer manages the lifecycle of the persistent solver process
// (solver/server.js) and provides Go-side helpers for talking to its
// HTTP API.
//
// Lifecycle:
//   - StartSolverServer launches `node solver/server.js <target>` if no
//     server is already listening, then polls /healthz until ready.
//   - WaitPoolReady blocks until at least 1 (or N) slots are healthy.
//   - GetCookie pulls one cookie set from the pool (round-robin).
//   - Invalidate marks a slot dirty so the JS server refreshes it.
//   - Stop terminates the child node process.
type SolverServer struct {
	addr   string
	target string
	cmd    *exec.Cmd
	owned  bool // true if we spawned the node process; false if it was already running

	httpClient *http.Client
}

// SolverCookie is one cookie set retrieved from the pool.
type SolverCookie struct {
	Slot      int    `json:"slot"`
	Cookies   string `json:"cookies"`
	UserAgent string `json:"user_agent"`
}

// SolverStatus describes pool health.
type SolverStatus struct {
	Target   string `json:"target"`
	PoolSize int    `json:"pool_size"`
	Healthy  int    `json:"healthy"`
	Slots    []struct {
		ID           int    `json:"id"`
		Ready        bool   `json:"ready"`
		Refreshing   bool   `json:"refreshing"`
		Uses         int    `json:"uses"`
		Invalidations int    `json:"invalidations"`
		AgeMs        int    `json:"ageMs"`
		LastError    string `json:"lastError"`
	} `json:"slots"`
}

// SolverFingerprint is what the solver browser actually emits, captured
// from tls.peet.ws inside one of the pool browsers.
type SolverFingerprint struct {
	JA3Hash      string `json:"ja3_hash"`
	JA4          string `json:"ja4"`
	AkamaiH2Hash string `json:"akamai_h2_hash"`
	UserAgent    string `json:"user_agent"`
}

func newSolverServer(target string, poolSize int, port int) *SolverServer {
	if port <= 0 {
		port = 9876
	}
	return &SolverServer{
		addr:   fmt.Sprintf("127.0.0.1:%d", port),
		target: target,
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
}

// Start launches the node solver server. If something is already listening
// on the configured port we assume it's a previous instance and reuse it.
func (s *SolverServer) Start(poolSize int) error {
	if s.alreadyListening() {
		s.owned = false
		return nil
	}

	solverPath := findSolverServer()
	if solverPath == "" {
		return fmt.Errorf("solver/server.js bulunamadi")
	}
	if _, err := os.Stat("solver/node_modules"); os.IsNotExist(err) {
		return fmt.Errorf("solver/node_modules yok - 'cd solver && npm install' gerekli")
	}

	cmd := exec.Command("node", solverPath, s.target)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SOLVER_POOL=%d", poolSize),
		fmt.Sprintf("SOLVER_PORT=%d", portFromAddr(s.addr)),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = os.Stderr // surface solver logs in blaze stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("solver baslatilamadi: %w", err)
	}
	s.cmd = cmd
	s.owned = true

	// Poll /healthz until the server is up (max 30s).
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if s.healthy() {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("solver server zamaninda baslamadi")
}

// WaitPoolReady blocks until at least minHealthy slots are healthy or
// timeout elapses. Returns the number of healthy slots achieved.
func (s *SolverServer) WaitPoolReady(ctx context.Context, minHealthy int, timeout time.Duration) (int, error) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	var lastHealthy int
	for {
		st, err := s.Status(tctx)
		if err == nil {
			lastHealthy = st.Healthy
			if st.Healthy >= minHealthy {
				return st.Healthy, nil
			}
		}
		select {
		case <-tctx.Done():
			return lastHealthy, fmt.Errorf("pool zamaninda hazir olmadi (saglikli=%d/%d)", lastHealthy, minHealthy)
		case <-tick.C:
		}
	}
}

// GetCookie fetches one cookie set from the pool.
func (s *SolverServer) GetCookie(ctx context.Context) (*SolverCookie, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+s.addr+"/cookie", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("solver /cookie %d: %s", resp.StatusCode, string(body))
	}
	var c SolverCookie
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Invalidate tells the server that a slot's cookies were rejected so the
// JS pool can rebuild that slot. Non-blocking: returns immediately.
func (s *SolverServer) Invalidate(ctx context.Context, slot int, reason string) {
	body, _ := json.Marshal(map[string]any{"slot": slot, "reason": reason})
	req, err := http.NewRequestWithContext(ctx, "POST", "http://"+s.addr+"/invalidate", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("content-type", "application/json")
	go func() {
		resp, err := s.httpClient.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
}

// Status reads the pool status JSON.
func (s *SolverServer) Status(ctx context.Context) (*SolverStatus, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+s.addr+"/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("solver /status %d", resp.StatusCode)
	}
	var st SolverStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Fingerprint asks the solver browser to query tls.peet.ws so we can
// verify JA4 alignment between solver and our emulated client.
func (s *SolverServer) Fingerprint(ctx context.Context) (*SolverFingerprint, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+s.addr+"/fingerprint", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("solver /fingerprint %d: %s", resp.StatusCode, string(body))
	}
	var fp SolverFingerprint
	if err := json.Unmarshal(body, &fp); err != nil {
		return nil, err
	}
	return &fp, nil
}

// Stop terminates the solver process if we own it. Safe to call multiple times.
func (s *SolverServer) Stop() {
	if !s.owned || s.cmd == nil {
		return
	}
	// Send SIGTERM to the process group so any chrome subprocesses go too.
	if s.cmd.Process != nil {
		syscall.Kill(-s.cmd.Process.Pid, syscall.SIGTERM)
	}
	done := make(chan struct{})
	go func() { s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		if s.cmd.Process != nil {
			syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		}
	}
}

func (s *SolverServer) healthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+s.addr+"/healthz", nil)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode == 200
}

func (s *SolverServer) alreadyListening() bool {
	c, err := net.DialTimeout("tcp", s.addr, 250*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// CookiePool is the blaze-side cache of cookies fetched from the solver.
// It hands out cookies round-robin to workers and accepts feedback when
// a cookie is rejected (403/503) so it can pull a fresh one and notify
// the solver server.
type CookiePool struct {
	server *SolverServer

	mu      sync.RWMutex
	entries []*pooledCookie
	round   atomic.Uint64
}

type pooledCookie struct {
	slot      int
	cookies   string
	userAgent string
	failures  atomic.Int64
}

func newCookiePool(server *SolverServer) *CookiePool {
	return &CookiePool{server: server}
}

// Fill pulls `n` distinct cookies from the solver pool. Call once at startup
// after WaitPoolReady. Returns the count actually fetched.
func (p *CookiePool) Fill(ctx context.Context, n int) int {
	got := 0
	seen := make(map[int]bool, n)
	for i := 0; i < n*3 && got < n; i++ {
		c, err := p.server.GetCookie(ctx)
		if err != nil || c == nil || c.Cookies == "" {
			continue
		}
		if seen[c.Slot] {
			continue
		}
		seen[c.Slot] = true
		p.mu.Lock()
		p.entries = append(p.entries, &pooledCookie{
			slot:      c.Slot,
			cookies:   c.Cookies,
			userAgent: c.UserAgent,
		})
		p.mu.Unlock()
		got++
	}
	return got
}

// Pick returns the next cookie in round-robin order. Returns nil if empty.
func (p *CookiePool) Pick() *pooledCookie {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.entries) == 0 {
		return nil
	}
	idx := int(p.round.Add(1)-1) % len(p.entries)
	return p.entries[idx]
}

// Reject is called by a worker when a request using the given cookie
// returned a status code that suggests the cookie is dead. After a
// threshold of failures we tell the solver to rebuild that slot and
// pull a replacement cookie locally.
func (p *CookiePool) Reject(ctx context.Context, c *pooledCookie, statusCode int) {
	if c == nil {
		return
	}
	if c.failures.Add(1) < 10 {
		return // threshold to avoid thundering refresh on transient blips
	}
	c.failures.Store(0)
	go func() {
		p.server.Invalidate(context.Background(), c.slot, fmt.Sprintf("status=%d", statusCode))
		// Wait briefly for the slot to be rebuilt, then pull a fresh cookie.
		time.Sleep(2 * time.Second)
		fresh, err := p.server.GetCookie(context.Background())
		if err != nil || fresh == nil || fresh.Cookies == "" {
			return
		}
		p.mu.Lock()
		c.slot = fresh.Slot
		c.cookies = fresh.Cookies
		c.userAgent = fresh.UserAgent
		p.mu.Unlock()
	}()
}

// Snapshot returns the current cookies as plain strings, useful for
// logging or initial template setup.
func (p *CookiePool) Snapshot() []SolverCookie {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]SolverCookie, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, SolverCookie{Slot: e.slot, Cookies: e.cookies, UserAgent: e.userAgent})
	}
	return out
}

func findSolverServer() string {
	for _, p := range []string{"solver/server.js", "./solver/server.js"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func portFromAddr(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 9876
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	if port <= 0 {
		return 9876
	}
	return port
}
