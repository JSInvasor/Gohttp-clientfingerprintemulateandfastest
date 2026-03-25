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

	fmt.Println("\n=== Response Headers ===")
	for k, v := range resp.Headers() {
		for _, val := range v {
			fmt.Printf("  %s: %s\n", k, val)
		}
	}

	// Don't print body - just show size
	fmt.Printf("\nContent-Encoding: %s\n", resp.GetHeader("Content-Encoding"))
	fmt.Printf("Content-Type: %s\n", resp.GetHeader("Content-Type"))
}
