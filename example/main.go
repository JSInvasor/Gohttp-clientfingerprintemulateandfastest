package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

func main() {
	// Create client with default settings (optimized for max RPS)
	client, err := gofire.NewClient(
		gofire.WithTimeout(15*time.Second),
		gofire.WithMaxIdleConnsPerHost(1000),
		gofire.WithMaxIdleConns(10000),
		gofire.WithDNSCacheTTL(10*time.Minute),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Simple GET
	fmt.Println("=== Simple GET ===")
	resp, err := client.Get("https://httpbin.org/get")
	if err != nil {
		log.Fatal(err)
	}
	text, _ := resp.Text()
	fmt.Printf("Status: %d\nBody length: %d\n\n", resp.StatusCode(), len(text))

	// POST JSON
	fmt.Println("=== POST JSON ===")
	resp, err = client.PostJSON("https://httpbin.org/post", []byte(`{"test": true}`))
	if err != nil {
		log.Fatal(err)
	}
	text, _ = resp.Text()
	fmt.Printf("Status: %d\nBody length: %d\n\n", resp.StatusCode(), len(text))

	// Builder pattern
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
	fmt.Printf("Status: %d\nHeaders response:\n%s\n\n", resp.StatusCode(), text)

	// High-throughput benchmark
	fmt.Println("=== Throughput Test ===")
	benchmarkRPS(client, "https://httpbin.org/get", 500, 100)
}

func benchmarkRPS(client *gofire.Client, url string, total, concurrency int) {
	var (
		success atomic.Int64
		fail    atomic.Int64
		wg      sync.WaitGroup
	)

	sem := make(chan struct{}, concurrency)
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 0; i < total; i++ {
		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			resp, err := client.GetWithContext(ctx, url)
			if err != nil {
				fail.Add(1)
				return
			}
			resp.Close()
			success.Add(1)
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	s := success.Load()
	f := fail.Load()
	rps := float64(s) / elapsed.Seconds()

	fmt.Printf("Total:      %d requests\n", total)
	fmt.Printf("Success:    %d\n", s)
	fmt.Printf("Failed:     %d\n", f)
	fmt.Printf("Duration:   %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("RPS:        %.0f req/s\n", rps)
	fmt.Printf("Conns used: %d\n", client.ActiveConnections())
}
