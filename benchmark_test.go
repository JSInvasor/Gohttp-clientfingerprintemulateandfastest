package gofire

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmulate(t *testing.T) {
	client, err := Emulate(Firefox148)
	if err != nil {
		t.Fatalf("Emulate(Firefox148) error: %v", err)
	}
	defer client.Close()

	if client.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
	if client.transport == nil {
		t.Fatal("transport is nil")
	}
	if client.config.browser != Firefox148 {
		t.Errorf("browser = %v, want Firefox148", client.config.browser)
	}
}

func TestEmulateWithOptions(t *testing.T) {
	client, err := Emulate(Firefox148,
		WithTimeout(5*time.Second),
		WithMaxIdleConnsPerHost(500),
		WithInsecureSkipVerify(),
		WithForceHTTP1(),
		WithAcceptLanguage("tr-TR,tr;q=0.9"),
	)
	if err != nil {
		t.Fatalf("Emulate() error: %v", err)
	}
	defer client.Close()

	if client.config.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", client.config.timeout)
	}
	if client.config.transport.MaxIdleConnsPerHost != 500 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 500", client.config.transport.MaxIdleConnsPerHost)
	}
	if !client.config.transport.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
	if !client.config.transport.ForceHTTP1 {
		t.Error("ForceHTTP1 should be true")
	}
	if client.config.acceptLanguage != "tr-TR,tr;q=0.9" {
		t.Errorf("acceptLanguage = %q, want tr-TR", client.config.acceptLanguage)
	}
}

func TestNewClient(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	defer client.Close()

	if client.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
}

func TestFirefoxHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	applyFirefoxHeaders(req, "text/html", "en-US,en;q=0.5")

	tests := []struct {
		header string
		want   string
	}{
		{"User-Agent", Firefox148UserAgent},
		{"Accept", "text/html"},
		{"Accept-Language", "en-US,en;q=0.5"},
		{"Accept-Encoding", "gzip, deflate, br, zstd"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-User", "?1"},
		{"Priority", "u=0, i"},
		{"TE", "trailers"},
		{"Upgrade-Insecure-Requests", "1"},
	}

	// Verify Firefox 148 does NOT send these headers
	for _, h := range []string{"DNT", "Sec-GPC", "Connection"} {
		if got := req.Header.Get(h); got != "" {
			t.Errorf("Header %s should NOT be set, got %q", h, got)
		}
	}

	for _, tt := range tests {
		if got := req.Header.Get(tt.header); got != tt.want {
			t.Errorf("Header %s = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestFirefoxHeadersNoOverride(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("User-Agent", "custom-agent")
	req.Header.Set("Accept", "application/json")
	applyFirefoxHeaders(req, "text/html", "en-US")

	if got := req.Header.Get("User-Agent"); got != "custom-agent" {
		t.Errorf("User-Agent was overridden: got %q", got)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept was overridden: got %q", got)
	}
}

func TestFirefox148Spec(t *testing.T) {
	// Verify H2 settings are correct (Firefox 148 fingerprint)
	s := Firefox148H2Settings()
	if s.HeaderTableSize != 65536 {
		t.Errorf("HeaderTableSize = %d, want 65536", s.HeaderTableSize)
	}
	if s.EnablePush != 0 {
		t.Errorf("EnablePush = %d, want 0", s.EnablePush)
	}
	if s.InitialWindowSize != 131072 {
		t.Errorf("InitialWindowSize = %d, want 131072", s.InitialWindowSize)
	}
	if s.MaxFrameSize != 16384 {
		t.Errorf("MaxFrameSize = %d, want 16384", s.MaxFrameSize)
	}
	if s.ConnectionWindowSize != 12517377 {
		t.Errorf("ConnectionWindowSize = %d, want 12517377", s.ConnectionWindowSize)
	}

	// Verify pseudo-header order
	order := Firefox148PseudoHeaderOrder()
	if len(order) != 4 {
		t.Errorf("PseudoHeaderOrder len = %d, want 4", len(order))
	}
}

func TestH2Settings(t *testing.T) {
	s := Firefox148H2Settings()
	if s.HeaderTableSize != 65536 {
		t.Errorf("HeaderTableSize = %d, want 65536", s.HeaderTableSize)
	}
	if s.EnablePush != 0 {
		t.Errorf("EnablePush = %d, want 0", s.EnablePush)
	}
	if s.InitialWindowSize != 131072 {
		t.Errorf("InitialWindowSize = %d, want 131072", s.InitialWindowSize)
	}
	if s.MaxFrameSize != 16384 {
		t.Errorf("MaxFrameSize = %d, want 16384", s.MaxFrameSize)
	}
	if s.ConnectionWindowSize != 12517377 {
		t.Errorf("ConnectionWindowSize = %d, want 12517377", s.ConnectionWindowSize)
	}
}

func TestPseudoHeaderOrder(t *testing.T) {
	order := Firefox148PseudoHeaderOrder()
	expected := []string{":method", ":path", ":authority", ":scheme"}
	if len(order) != len(expected) {
		t.Fatalf("PseudoHeaderOrder length = %d, want %d", len(order), len(expected))
	}
	for i, v := range expected {
		if order[i] != v {
			t.Errorf("PseudoHeaderOrder[%d] = %q, want %q", i, order[i], v)
		}
	}
}

func TestDNSCache(t *testing.T) {
	cache := newDNSCache(5 * time.Minute)
	defer cache.Close()

	// IP passthrough
	ip, err := cache.lookup("127.0.0.1")
	if err != nil || ip != "127.0.0.1" {
		t.Errorf("lookup(127.0.0.1) = %q, %v", ip, err)
	}

	// Actual DNS resolution
	ip, err = cache.lookup("localhost")
	if err != nil {
		t.Fatalf("lookup(localhost) error: %v", err)
	}
	if ip == "" {
		t.Error("lookup(localhost) returned empty")
	}

	// Second lookup should hit cache
	ip2, err := cache.lookup("localhost")
	if err != nil {
		t.Fatalf("cached lookup error: %v", err)
	}
	if ip2 != ip {
		t.Errorf("cached lookup = %q, want %q", ip2, ip)
	}
}

func TestHeaderOrder(t *testing.T) {
	h := make(http.Header)
	h.Set("Accept", "text/html")
	h.Set("User-Agent", "test")
	h.Set("Custom-Header", "value")

	ordered := OrderHeaders(h)
	if len(ordered) != 3 {
		t.Fatalf("OrderHeaders returned %d headers, want 3", len(ordered))
	}
	// Firefox 148 header order: User-Agent first, then Accept
	if ordered[0].Key != "User-Agent" {
		t.Errorf("First header = %q, want 'User-Agent'", ordered[0].Key)
	}
	if ordered[1].Key != "Accept" {
		t.Errorf("Second header = %q, want 'Accept'", ordered[1].Key)
	}
	// Custom headers come after known Firefox headers
	if ordered[2].Key != "Custom-Header" {
		t.Errorf("Third header = %q, want 'Custom-Header'", ordered[2].Key)
	}
}

func TestBrowserProfile(t *testing.T) {
	if Firefox148.String() != "Firefox/148.0" {
		t.Errorf("Firefox148.String() = %q, want 'Firefox/148.0'", Firefox148.String())
	}
}

func TestRequestBuilder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client, err := Emulate(Firefox148, WithForceHTTP1(), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	resp, err := client.BuildRequest().
		Method("GET").
		URL(server.URL).
		Header("X-Custom", "test").
		Send()

	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode())
	}

	text, err := resp.Text()
	if err != nil {
		t.Fatalf("Text() error: %v", err)
	}
	if text != `{"status":"ok"}` {
		t.Errorf("body = %q", text)
	}
}

func TestResponseJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"gofire","version":1}`))
	}))
	defer server.Close()

	client, err := Emulate(Firefox148, WithForceHTTP1())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Close()

	var result struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	}
	if err := resp.JSON(&result); err != nil {
		t.Fatal(err)
	}
	if result.Name != "gofire" || result.Version != 1 {
		t.Errorf("got %+v", result)
	}
}

func TestFlood(t *testing.T) {
	var count atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := Emulate(Firefox148, WithForceHTTP1(), WithTimeout(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := 100
	responses, errors := client.Flood(ctx, "GET", server.URL, n, 20)

	successCount := 0
	for i := 0; i < n; i++ {
		if errors[i] == nil && responses[i] != nil {
			successCount++
			responses[i].Close()
		}
	}

	if successCount == 0 {
		t.Error("no successful responses")
	}
	t.Logf("Flood: %d/%d successful", successCount, n)
}

func TestPipeline(t *testing.T) {
	var count atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, err := Emulate(Firefox148, WithForceHTTP1(), WithTimeout(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	pipeline := client.NewPipeline(50)
	defer pipeline.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Send 200 requests through pipeline
	results := make([]<-chan *PipelineResult, 200)
	for i := 0; i < 200; i++ {
		results[i] = pipeline.Send(ctx, "GET", server.URL, nil, nil)
	}

	// Collect results
	successCount := 0
	for _, ch := range results {
		result := <-ch
		if result.Err == nil {
			successCount++
			if result.Response != nil {
				result.Response.Close()
			}
		}
	}

	if successCount == 0 {
		t.Error("no successful pipeline responses")
	}
	t.Logf("Pipeline: %d/200 successful, stats: sent=%d ok=%d err=%d",
		successCount,
		pipeline.Stats.TotalSent.Load(),
		pipeline.Stats.TotalOK.Load(),
		pipeline.Stats.TotalErr.Load(),
	)
}

func TestPipelineSpray(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := Emulate(Firefox148, WithForceHTTP1(), WithTimeout(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	pipeline := client.NewPipeline(100)
	defer pipeline.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := pipeline.Spray(ctx, "GET", server.URL, 500)
	t.Logf("Spray: %d/%d success, %.0f RPS, %v duration",
		result.Success, result.Total, result.RPS, result.Duration.Round(time.Millisecond))

	if result.Success == 0 {
		t.Error("no successful spray responses")
	}
}

func TestPipelineFireAndForget(t *testing.T) {
	var count atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := Emulate(Firefox148, WithForceHTTP1(), WithTimeout(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	pipeline := client.NewPipeline(50)
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		pipeline.FireAndForget(ctx, "GET", server.URL, nil, nil)
	}

	pipeline.Close() // waits for all workers

	if count.Load() == 0 {
		t.Error("no requests completed in fire-and-forget mode")
	}
	t.Logf("FireAndForget: %d/100 completed", count.Load())
}

func TestPreConnect(t *testing.T) {
	var connCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connCount.Add(1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := Emulate(Firefox148, WithForceHTTP1(), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()
	err = client.PreConnect(ctx, server.URL, 5)
	if err != nil {
		t.Fatalf("PreConnect error: %v", err)
	}

	if connCount.Load() == 0 {
		t.Error("PreConnect made no connections")
	}
	t.Logf("PreConnect: %d connections warmed", connCount.Load())
}

// Benchmarks

func BenchmarkGet(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, err := Emulate(Firefox148, WithForceHTTP1(), WithTimeout(10*time.Second))
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Get(server.URL)
			if err != nil {
				b.Fatal(err)
			}
			resp.Close()
		}
	})
}

func BenchmarkGetConcurrent(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, err := Emulate(Firefox148,
		WithForceHTTP1(),
		WithTimeout(10*time.Second),
		WithMaxIdleConnsPerHost(1000),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	b.ResetTimer()
	b.SetParallelism(100)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Get(server.URL)
			if err != nil {
				b.Fatal(err)
			}
			resp.Close()
		}
	})
}

func BenchmarkPipeline(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, err := Emulate(Firefox148,
		WithForceHTTP1(),
		WithTimeout(10*time.Second),
		WithMaxIdleConnsPerHost(1000),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	pipeline := client.NewPipeline(500)
	defer pipeline.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ch := pipeline.Send(ctx, "GET", server.URL, nil, nil)
			result := <-ch
			if result.Response != nil {
				result.Response.Close()
			}
		}
	})
}

func BenchmarkFirefoxHeaders(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		applyFirefoxHeaders(req, "text/html", "en-US,en;q=0.5")
	}
}

func BenchmarkFirefox148H2Settings(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Firefox148H2Settings()
	}
}
