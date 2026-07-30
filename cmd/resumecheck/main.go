// Command resumecheck reports whether a host issues TLS 1.3 session tickets and
// whether this module's TLS stack can resume against it.
//
// Resumption cannot be validated from a sandboxed or proxied network: a TLS
// terminator in the path answers the handshake itself, and if it issues no
// tickets every host looks identical. Run this from a machine with direct
// egress to find out what a given operator actually does.
//
//	go run ./cmd/resumecheck www.cloudflare.com github.com www.google.com
//
// Each host is dialled twice. crypto/tls runs the same two dials as a control:
// it is a known-correct client, so the two columns separate "this server issues
// no tickets" from "this server issues tickets we fail to use".
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	ctls "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/ctls"
)

func main() {
	hosts := os.Args[1:]
	if len(hosts) == 0 {
		hosts = []string{"www.cloudflare.com", "github.com", "www.google.com"}
	}

	fmt.Printf("%-28s %-14s %-14s %s\n", "HOST", "crypto/tls", "this client", "VERDICT")
	fmt.Println(strings.Repeat("-", 78))

	for _, h := range hosts {
		host := h
		if !strings.Contains(host, ":") {
			host += ":443"
		}
		name, _, _ := net.SplitHostPort(host)

		std, stdErr := stdlibResumes(host, name)
		ours, ourErr := ctlsResumes(host, name)

		fmt.Printf("%-28s %-14s %-14s %s\n",
			name, state(std, stdErr), state(ours, ourErr), verdict(std, stdErr, ours, ourErr))
	}
}

func state(resumed bool, err error) string {
	if err != nil {
		return "error"
	}
	if resumed {
		return "resumed"
	}
	return "no ticket"
}

func verdict(std bool, stdErr error, ours bool, ourErr error) string {
	switch {
	case stdErr != nil:
		return "control failed: " + short(stdErr)
	case ourErr != nil:
		return "THIS CLIENT FAILED: " + short(ourErr)
	case std && ours:
		return "ok - server issues tickets, we resume"
	case !std && !ours:
		return "server issues no usable tickets (nothing to fix here)"
	case std && !ours:
		return "BUG - server issues tickets but we do not resume"
	default:
		return "we resumed where the control did not; verify by hand"
	}
}

func short(err error) string {
	s := err.Error()
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return s
}

// stdlibResumes is the control: crypto/tls with its own session cache.
func stdlibResumes(addr, name string) (bool, error) {
	cfg := &tls.Config{
		ServerName:         name,
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
		MinVersion:         tls.VersionTLS13,
	}
	var resumed bool
	for i := 0; i < 2; i++ {
		c, err := tls.Dial("tcp", addr, cfg)
		if err != nil {
			return false, err
		}
		resumed = c.ConnectionState().DidResume
		// crypto/tls processes post-handshake messages only while reading, so
		// a connection closed straight after the handshake never sees the
		// ticket and can never resume. Both sides must read for the comparison
		// to mean anything.
		fetch(c, name)
		c.Close()
	}
	return resumed, nil
}

// ctlsResumes runs the same two dials through this module's TLS stack.
func ctlsResumes(addr, name string) (bool, error) {
	cache := ctls.NewSessionCache()
	var resumed bool

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			cancel()
			return false, err
		}
		conn, err := ctls.WrapConnConfig(ctx, raw, &ctls.Config{
			ServerName: name,
			// http/1.1 keeps the exchange small: a plain GET is enough to make
			// the server flush the tickets it queued after its Finished.
			ALPN:       []string{"http/1.1"},
			Browser:    ctls.BrowserChrome,
			Sessions:   cache,
			SessionKey: name,
		})
		cancel()
		if err != nil {
			raw.Close()
			return false, err
		}

		resumed = conn.DidResume()
		fetch(conn, name)
		conn.Close()
	}
	return resumed, nil
}

// fetch issues a minimal request and drains the reply. Reading is what walks the
// NewSessionTicket records and feeds them to the cache.
func fetch(conn net.Conn, host string) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: resumecheck\r\nConnection: close\r\n\r\n", host)
	buf := make([]byte, 16<<10)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}
