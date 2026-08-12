package gofire

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmulate(t *testing.T) {
	client, err := Emulate(SafariIOS18)
	if err != nil {
		t.Fatalf("Emulate(SafariIOS18) error: %v", err)
	}
	defer client.Close()

	if client.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
	if client.transport == nil {
		t.Fatal("transport is nil")
	}
	if client.config.browser != SafariIOS18 {
		t.Errorf("browser = %v, want SafariIOS18", client.config.browser)
	}
}

func TestEmulateWithOptions(t *testing.T) {
	client, err := Emulate(SafariIOS18,
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

func TestSafariHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	applySafariHeaders(req, "text/html", "en-US,en;q=0.9", "", modeNavigate)

	tests := []struct {
		header string
		want   string
	}{
		{"User-Agent", SafariIOS18UserAgent},
		{"Accept", "text/html"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Accept-Encoding", "gzip, deflate, br, zstd"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Priority", "u=0, i"},
	}

	// Verify Safari iOS 18 does NOT send these headers
	for _, h := range []string{
		"Upgrade-Insecure-Requests",
		"TE",
		"Sec-Fetch-User",
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Platform",
		"DNT",
		"Sec-GPC",
		"Connection",
	} {
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

func TestSafariHeadersNoOverride(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("User-Agent", "custom-agent")
	req.Header.Set("Accept", "application/json")
	applySafariHeaders(req, "text/html", "en-US", "", modeNavigate)

	if got := req.Header.Get("User-Agent"); got != "custom-agent" {
		t.Errorf("User-Agent was overridden: got %q", got)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept was overridden: got %q", got)
	}
}

func TestSafariIOS18Spec(t *testing.T) {
	s := SafariIOS18H2Settings()
	if s.HeaderTableSize != 0 {
		t.Errorf("HeaderTableSize = %d, want 0 (Safari omits)", s.HeaderTableSize)
	}
	if s.EnablePush != 0 {
		t.Errorf("EnablePush = %d, want 0", s.EnablePush)
	}
	if s.MaxConcurrentStreams != 100 {
		t.Errorf("MaxConcurrentStreams = %d, want 100", s.MaxConcurrentStreams)
	}
	if s.InitialWindowSize != 2097152 {
		t.Errorf("InitialWindowSize = %d, want 2097152", s.InitialWindowSize)
	}
	if s.NoRFC7540Priorities != 1 {
		t.Errorf("NoRFC7540Priorities = %d, want 1", s.NoRFC7540Priorities)
	}
	if s.ConnectionWindowSize != 10420225 {
		t.Errorf("ConnectionWindowSize = %d, want 10420225", s.ConnectionWindowSize)
	}

	order := SafariIOS18PseudoHeaderOrder()
	expected := []string{":method", ":scheme", ":authority", ":path"}
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
	// Safari iOS 18 header order: User-Agent comes before Accept
	// (Sec-Fetch-Dest is first overall, but not present here).
	if ordered[0].Key != "User-Agent" {
		t.Errorf("First header = %q, want 'User-Agent'", ordered[0].Key)
	}
	if ordered[1].Key != "Accept" {
		t.Errorf("Second header = %q, want 'Accept'", ordered[1].Key)
	}
	// Custom headers come after known Safari headers
	if ordered[2].Key != "Custom-Header" {
		t.Errorf("Third header = %q, want 'Custom-Header'", ordered[2].Key)
	}
}

func TestBrowserProfile(t *testing.T) {
	if got := SafariIOS18.String(); got != "Safari/26.5.2" {
		t.Errorf("SafariIOS18.String() = %q, want 'Safari/26.5.2'", got)
	}
	if got := Chrome151.String(); got != "Chrome/151.0" {
		t.Errorf("Chrome151.String() = %q, want 'Chrome/151.0'", got)
	}
	// The legacy names must keep resolving to the current profiles.
	if Chrome147 != Chrome150 || Chrome146 != Chrome150 {
		t.Error("Chrome147/Chrome146 aliases no longer resolve to Chrome150")
	}
}

func TestRequestBuilder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client, err := Emulate(SafariIOS18, WithForceHTTP1(), WithTimeout(5*time.Second))
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

	client, err := Emulate(SafariIOS18, WithForceHTTP1())
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

	client, err := Emulate(SafariIOS18, WithForceHTTP1(), WithTimeout(10*time.Second))
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

	client, err := Emulate(SafariIOS18, WithForceHTTP1(), WithTimeout(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	pipeline := client.NewPipeline(50)
	defer pipeline.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results := make([]<-chan *PipelineResult, 200)
	for i := 0; i < 200; i++ {
		results[i] = pipeline.Send(ctx, "GET", server.URL, nil, nil)
	}

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

	client, err := Emulate(SafariIOS18, WithForceHTTP1(), WithTimeout(10*time.Second))
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

	client, err := Emulate(SafariIOS18, WithForceHTTP1(), WithTimeout(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	pipeline := client.NewPipeline(50)
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		pipeline.FireAndForget(ctx, "GET", server.URL, nil, nil)
	}

	// Close() discards whatever is still buffered in jobCh — that is its
	// documented contract for a fire-and-forget pipeline, and workers check
	// stopCh before jobCh so shutdown is prompt. Calling it immediately and
	// then asserting on the count is therefore a race against the workers,
	// which is exactly what this test used to do. Wait (bounded) for the
	// pipeline to have dispatched something, then shut down.
	deadline := time.Now().Add(5 * time.Second)
	for count.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	dispatched := count.Load()

	pipeline.Close()

	if dispatched == 0 {
		t.Error("no requests dispatched in fire-and-forget mode within 5s")
	}
	t.Logf("FireAndForget: %d/100 dispatched before shutdown", dispatched)
}

// TestPipelineCloseRace ensures Close() does not panic when a flood of
// concurrent FireAndForget calls is racing with shutdown. The previous
// implementation closed jobCh directly, which raced senders that had just
// passed the closed.Load() check and panicked with "send on closed channel".
func TestPipelineCloseRace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	client, err := Emulate(SafariIOS18, WithForceHTTP1(), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	pipeline := client.NewPipeline(32)
	ctx := context.Background()

	// Fire from many goroutines while another goroutine closes mid-burst.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				pipeline.FireAndForget(ctx, "GET", server.URL, nil, nil)
			}
		}()
	}

	// Close while senders are still active. Must not panic.
	time.Sleep(5 * time.Millisecond)
	pipeline.Close()
	wg.Wait()
}

// TestRetryExhaustionPreservesResponse verifies that when retries are
// exhausted on a retryable status code, the caller still receives the final
// response (so the body and headers are inspectable) rather than only a
// stringified "HTTP 5xx" error.
func TestRetryExhaustionPreservesResponse(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(503)
		w.Write([]byte("upstream busy"))
	}))
	defer server.Close()

	client, err := NewClient(
		WithForceHTTP1(),
		WithTimeout(5*time.Second),
		WithRetry(2, 1*time.Millisecond, 503),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("expected response on retry exhaustion, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response on retry exhaustion")
	}
	defer resp.Close()

	if resp.StatusCode() != 503 {
		t.Errorf("status = %d, want 503", resp.StatusCode())
	}
	if got := resp.GetHeader("Retry-After"); got != "1" {
		t.Errorf("Retry-After header = %q, want %q", got, "1")
	}
	body, err := resp.Text()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if body != "upstream busy" {
		t.Errorf("body = %q, want %q", body, "upstream busy")
	}
	if hits.Load() != 3 {
		t.Errorf("server saw %d hits, want 3 (initial + 2 retries)", hits.Load())
	}
}

// TestPreConnect checks that pre-warming opens connections and, just as
// importantly, that it sends no HTTP request while doing so. A browser's
// <link rel="preconnect"> opens the socket and stops; an implementation that
// warms the pool with a throwaway HEAD puts a request on the wire that the
// emulated browser would never have made.
func TestPreConnect(t *testing.T) {
	var (
		connCount atomic.Int64
		reqCount  atomic.Int64
	)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(200)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connCount.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	client, err := Emulate(SafariIOS18, WithForceHTTP1(), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()
	err = client.PreConnect(ctx, server.URL, 5)
	if err != nil {
		t.Fatalf("PreConnect error: %v", err)
	}

	// ConnState fires on the server's per-connection goroutine, which is not
	// synchronised with the dial returning, so poll rather than sampling once.
	deadline := time.Now().Add(2 * time.Second)
	for connCount.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if connCount.Load() == 0 {
		t.Error("PreConnect made no connections")
	}
	if n := reqCount.Load(); n != 0 {
		t.Errorf("PreConnect sent %d HTTP request(s); it must warm the connection without one", n)
	}
	t.Logf("PreConnect: %d connections warmed, %d requests sent", connCount.Load(), reqCount.Load())
}

// Benchmarks

func BenchmarkGet(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client, err := Emulate(SafariIOS18, WithForceHTTP1(), WithTimeout(10*time.Second))
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

	client, err := Emulate(SafariIOS18,
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

	client, err := Emulate(SafariIOS18,
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

func BenchmarkSafariHeaders(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		applySafariHeaders(req, "text/html", "en-US,en;q=0.9", "", modeNavigate)
	}
}

func BenchmarkSafariIOS18H2Settings(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = SafariIOS18H2Settings()
	}
}

// TestALPNAbsentFallsBackToHTTP1 covers the harder half of the same failure:
// a server that answers with no ALPN extension at all.
//
// TestALPNFallbackToHTTP1 below uses a server that explicitly selects
// http/1.1, which the dispatcher always caught. A server that simply omits the
// extension — common on older stacks and on origins with ALPN switched off —
// reported an empty protocol, and the dispatcher read empty as "fine, h2" and
// pumped the h2 preface into it. RFC 7301 §3.2 has the server echo what it
// selected, so no extension means it selected nothing.
//
// httptest cannot express this (StartTLS fills NextProtos in when it is nil),
// so the listener is built by hand.
func TestALPNAbsentFallsBackToHTTP1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// NextProtos deliberately unset: the server negotiates no ALPN whatsoever.
	tlsLn := cryptotls.NewListener(ln, &cryptotls.Config{
		Certificates: []cryptotls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   cryptotls.VersionTLS13,
	})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.Write([]byte("ok"))
	})}
	go srv.Serve(tlsLn)
	defer srv.Close()

	client, err := Emulate(Chrome151, WithInsecureSkipVerify(), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("request to an ALPN-less server: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode())
	}
	if got := resp.GetHeader("X-Proto"); got != "HTTP/1.1" {
		t.Errorf("X-Proto = %q, want HTTP/1.1", got)
	}
}

// TestALPNFallbackToHTTP1 verifies the dispatcher falls back to HTTP/1.1
// when the server doesn't speak h2. Without the fallback, h2Transport would
// pipe the h2 preface into an http/1.1 conn and every request to such hosts
// would fail — producing the "site to site RPS varies wildly" symptom from
// the multi-target benchmark.
func TestALPNFallbackToHTTP1(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	// Force http/1.1-only — emulates an origin that disables h2.
	server.TLS = &cryptotls.Config{NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()

	client, err := Emulate(SafariIOS18,
		WithInsecureSkipVerify(),
		WithTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// First request: h2 dial discovers the server only speaks http/1.1, falls
	// back to h1Transport, and caches the protocol for the host.
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode())
	}
	if got := resp.GetHeader("X-Proto"); got != "HTTP/1.1" {
		t.Errorf("X-Proto = %q, want HTTP/1.1", got)
	}
	resp.Close()

	// Second request: hostProto cache routes directly to h1Transport,
	// skipping the failed-h2 dial.
	resp, err = client.Get(server.URL)
	if err != nil {
		t.Fatalf("cached-h1 request: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("cached request status = %d, want 200", resp.StatusCode())
	}
	resp.Close()
}
