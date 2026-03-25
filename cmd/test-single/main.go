package main

import (
	"fmt"
	"log"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

func main() {
	client, err := gofire.Emulate(gofire.Firefox148,
		gofire.WithTimeout(15*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	url := "https://wafonix.com"
	fmt.Printf("Sending single GET to %s...\n", url)

	start := time.Now()
	resp, err := client.Get(url)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		fmt.Printf("Elapsed: %v\n", elapsed)
		return
	}

	fmt.Printf("Status:  %d\n", resp.StatusCode())
	fmt.Printf("Elapsed: %v\n", elapsed)

	// Print response headers
	fmt.Println("\n=== Response Headers ===")
	for k, v := range resp.Headers() {
		fmt.Printf("  %s: %s\n", k, v)
	}

	// Print body (first 500 chars)
	text, _ := resp.Text()
	if len(text) > 500 {
		text = text[:500] + "..."
	}
	fmt.Printf("\n=== Body (%d bytes) ===\n%s\n", len(text), text)
}
