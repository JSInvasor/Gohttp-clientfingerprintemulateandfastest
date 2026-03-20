package gofire

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	defer client.Close()

	if client.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
	if client.transport == nil {
		t.Fatal("transport is nil")
	}
}

func TestClientOptions(t *testing.T) {
	client, err := NewClient(
		WithTimeout(5*time.Second),
		WithMaxIdleConnsPerHost(500),
		WithMaxIdleConns(5000),
		WithDisableRedirects(),
		WithForceHTTP1(),
		WithAcceptLanguage("tr-TR,tr;q=0.9"),
	)
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	defer client.Close()

	if client.config.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", client.config.timeout)
	}
	if client.config.transport.MaxIdleConnsPerHost != 500 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 500", client.config.transport.MaxIdleConnsPerHost)
	}
	if client.config.followRedirects != false {
		t.Error("followRedirects should be false")
	}
	if client.config.transport.ForceHTTP1 != true {
		t.Error("ForceHTTP1 should be true")
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
		{"DNT", "1"},
		{"Sec-GPC", "1"},
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
	applyFirefoxHeaders(req, "text/html", "en-US")

	if got := req.Header.Get("User-Agent"); got != "custom-agent" {
		t.Errorf("User-Agent was overridden: got %q, want %q", got, "custom-agent")
	}
}

func TestFirefox148Spec(t *testing.T) {
	spec := Firefox148Spec()
	if spec == nil {
		t.Fatal("Firefox148Spec() returned nil")
	}
	if len(spec.CipherSuites) == 0 {
		t.Error("CipherSuites is empty")
	}
	if len(spec.Extensions) == 0 {
		t.Error("Extensions is empty")
	}
	if spec.TLSVersMax != 0x0304 { // TLS 1.3
		t.Errorf("TLSVersMax = 0x%04x, want 0x0304", spec.TLSVersMax)
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
}

func TestDNSCache(t *testing.T) {
	cache := newDNSCache(5 * time.Minute)

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
	h.Set("Host", "example.com")
	h.Set("Custom-Header", "value")

	ordered := OrderHeaders(h)
	if len(ordered) != 4 {
		t.Fatalf("OrderHeaders returned %d headers, want 4", len(ordered))
	}

	// Host should come first in Firefox order
	if ordered[0].Key != "Host" {
		t.Errorf("First header = %q, want 'Host'", ordered[0].Key)
	}
	// User-Agent second
	if ordered[1].Key != "User-Agent" {
		t.Errorf("Second header = %q, want 'User-Agent'", ordered[1].Key)
	}
}

func TestRequestBuilder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client, err := NewClient(WithForceHTTP1(), WithTimeout(5*time.Second))
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

	client, err := NewClient(WithForceHTTP1())
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

// BenchmarkGet benchmarks HTTP GET requests through the fingerprinted client.
func BenchmarkGet(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, err := NewClient(WithForceHTTP1(), WithTimeout(10*time.Second))
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

// BenchmarkGetConcurrent measures throughput with high concurrency.
func BenchmarkGetConcurrent(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, err := NewClient(
		WithForceHTTP1(),
		WithTimeout(10*time.Second),
		WithMaxIdleConnsPerHost(1000),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	b.ResetTimer()
	b.SetParallelism(100) // 100 goroutines per GOMAXPROCS
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

// BenchmarkFirefoxHeaders benchmarks header application.
func BenchmarkFirefoxHeaders(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		applyFirefoxHeaders(req, "text/html", "en-US,en;q=0.5")
	}
}

// BenchmarkFirefox148Spec benchmarks TLS spec creation.
func BenchmarkFirefox148Spec(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Firefox148Spec()
	}
}

// TestFlood tests the Flood method for concurrent requests.
func TestFlood(t *testing.T) {
	var count atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := NewClient(WithForceHTTP1(), WithTimeout(10*time.Second))
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
