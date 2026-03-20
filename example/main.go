package main

import (
	"context"
	"fmt"
	"log"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

func main() {
	// ============================================================
	// 1. Create client with Firefox 148 emulation
	// ============================================================
	client, err := gofire.Emulate(gofire.Firefox148,
		gofire.WithTimeout(15*time.Second),
		gofire.WithMaxIdleConnsPerHost(2000),
		gofire.WithMaxIdleConns(20000),
		gofire.WithDNSCacheTTL(10*time.Minute),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// ============================================================
	// 2. Simple GET request
	// ============================================================
	fmt.Println("=== Simple GET ===")
	resp, err := client.Get("https://httpbin.org/get")
	if err != nil {
		log.Fatal(err)
	}
	text, _ := resp.Text()
	fmt.Printf("Status: %d | Body: %d bytes\n\n", resp.StatusCode(), len(text))

	// ============================================================
	// 3. POST JSON
	// ============================================================
	fmt.Println("=== POST JSON ===")
	resp, err = client.PostJSON("https://httpbin.org/post", []byte(`{"test":true}`))
	if err != nil {
		log.Fatal(err)
	}
	text, _ = resp.Text()
	fmt.Printf("Status: %d | Body: %d bytes\n\n", resp.StatusCode(), len(text))

	// ============================================================
	// 4. Builder pattern
	// ============================================================
	fmt.Println("=== Builder Pattern ===")
	resp, err = client.BuildRequest().
		Method("GET").
		URL("https://httpbin.org/headers").
		Header("X-Custom-Header", "gofire-test").
		Send()
	if err != nil {
		log.Fatal(err)
	}
	text, _ = resp.Text()
	fmt.Printf("Status: %d\nHeaders:\n%s\n\n", resp.StatusCode(), text)

	// ============================================================
	// 5. Pipeline for maximum RPS
	// ============================================================
	fmt.Println("=== Pipeline Spray (max RPS) ===")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Pre-warm connections
	_ = client.PreConnect(ctx, "https://httpbin.org/get", 10)

	// Create pipeline with 200 workers
	pipeline := client.NewPipeline(200)
	defer pipeline.Close()

	// Spray 500 requests
	result := pipeline.Spray(ctx, "GET", "https://httpbin.org/get", 500)

	fmt.Printf("Total:    %d requests\n", result.Total)
	fmt.Printf("Success:  %d\n", result.Success)
	fmt.Printf("Failed:   %d\n", result.Failed)
	fmt.Printf("Duration: %v\n", result.Duration.Round(time.Millisecond))
	fmt.Printf("RPS:      %.0f req/s\n", result.RPS)
	fmt.Printf("Conns:    %d\n", client.ActiveConnections())
}
