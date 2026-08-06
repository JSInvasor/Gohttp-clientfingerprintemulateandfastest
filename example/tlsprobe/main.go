// Command tlsprobe reports why a TLS handshake to a target fails.
//
// "server alert: handshake_failure (40)" says the server refused the
// ClientHello. It does not say whether it refused *this* ClientHello or would
// have refused any, and that is the whole question: one means the emulated
// fingerprint is being rejected, the other means the target, the SNI or the
// path is wrong. tlsprobe answers it by handshaking against the same endpoint
// with each emulated profile and, as a control, with Go's stock crypto/tls.
//
// Run it from the host that sees the failures. A probe from somewhere else
// measures a different network path, and anything that terminates TLS in
// between answers with its own certificate — so the handshake succeeds against
// a middlebox while the target never sees the ClientHello. The certificate
// issuer printed below is what tells you that happened.
//
// Usage:
//
//	go run ./example/tlsprobe -target example.com
//	go run ./example/tlsprobe -target example.com -proxy http://user:pass@host:8080
//	go run ./example/tlsprobe -target 1.2.3.4:443 -sni example.com
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/ctls"
)

var alpn = []string{"h2", "http/1.1"}

func main() {
	target := flag.String("target", "", "host, host:port or URL to probe (required)")
	sni := flag.String("sni", "", "server name to send (default: the target host)")
	proxyURL := flag.String("proxy", "", "http:// or socks5:// proxy to reach the target through")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	timeout := flag.Duration("timeout", 10*time.Second, "per-attempt timeout")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "-target is required")
		flag.Usage()
		os.Exit(2)
	}

	addr, host, err := splitTarget(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad -target: %v\n", err)
		os.Exit(2)
	}
	name := *sni
	if name == "" {
		name = host
	}

	dial, err := dialer(*proxyURL, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad -proxy: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("target   %s (sni=%s)\n", addr, name)
	if *proxyURL == "" {
		fmt.Printf("via      direct\n")
	} else {
		fmt.Printf("via      %s\n", redact(*proxyURL))
	}
	if *insecure {
		fmt.Printf("verify   off\n")
	}
	fmt.Println()

	// Reach the endpoint once before handshaking anything, so a dial failure
	// is reported as itself instead of as three handshake failures.
	start := time.Now()
	conn, err := dial(addr)
	if err != nil {
		fmt.Printf("connect  FAIL  %v\n", err)
		fmt.Println()
		fmt.Println("The TCP connection never came up, so nothing below could run.")
		fmt.Println("Check the address, the firewall, and the proxy if you set one.")
		os.Exit(1)
	}
	conn.Close()
	fmt.Printf("connect  ok    %v\n", time.Since(start).Round(time.Millisecond))

	control := probeStdlib(dial, addr, name, *insecure, *timeout)
	report("stdlib", control)

	results := map[string]result{}
	for _, p := range []struct {
		label   string
		browser ctls.BrowserType
	}{
		{"chrome", ctls.BrowserChrome},
		{"safari", ctls.BrowserSafari},
	} {
		res := probeCtls(dial, addr, name, p.browser, *insecure, *timeout)
		results[p.label] = res
		report(p.label, res)
	}

	fmt.Println()
	verdict(control, results)
}

type result struct {
	ok      bool
	err     error
	detail  string // filled when ok
	subject string // leaf certificate, control only
	issuer  string
}

// probeStdlib handshakes with Go's own TLS client. It is the control: whatever
// it can negotiate, the target is willing to give a client that is not
// pretending to be a browser.
func probeStdlib(dial func(string) (net.Conn, error), addr, name string, insecure bool, timeout time.Duration) result {
	conn, err := dial(addr)
	if err != nil {
		return result{err: err}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	c := tls.Client(conn, &tls.Config{
		ServerName:         name,
		NextProtos:         alpn,
		InsecureSkipVerify: insecure,
	})
	if err := c.Handshake(); err != nil {
		return result{err: err}
	}
	st := c.ConnectionState()

	res := result{
		ok:     true,
		detail: fmt.Sprintf("%s alpn=%s cipher=0x%04x", versionName(st.Version), orNone(st.NegotiatedProtocol), st.CipherSuite),
	}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		res.subject = leaf.Subject.String()
		res.issuer = leaf.Issuer.String()
	}
	return res
}

// probeCtls handshakes with one of the emulated ClientHellos.
func probeCtls(dial func(string) (net.Conn, error), addr, name string, browser ctls.BrowserType, insecure bool, timeout time.Duration) result {
	conn, err := dial(addr)
	if err != nil {
		return result{err: err}
	}
	conn.SetDeadline(time.Now().Add(timeout))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConn, err := ctls.WrapConn(ctx, conn, name, alpn, insecure, nil, browser)
	if err != nil {
		conn.Close()
		return result{err: err}
	}
	defer tlsConn.Close()

	st := tlsConn.ConnectionState()
	return result{
		ok:     true,
		detail: fmt.Sprintf("tls1.3 alpn=%s cipher=0x%04x", orNone(st.NegotiatedProtocol), st.CipherSuite),
	}
}

func report(label string, res result) {
	if res.ok {
		fmt.Printf("%-8s ok    %s\n", label, res.detail)
		if res.subject != "" {
			fmt.Printf("%-8s cert  %s\n", "", res.subject)
			fmt.Printf("%-8s by    %s\n", "", res.issuer)
		}
		return
	}
	fmt.Printf("%-8s FAIL  %v\n", label, res.err)
}

// verdict turns the three outcomes into the one sentence worth acting on.
func verdict(control result, results map[string]result) {
	var okCount int
	for _, r := range results {
		if r.ok {
			okCount++
		}
	}

	switch {
	case anyErrContains(control, results, "not a TLS record"):
		fmt.Println("The endpoint answered with something that is not TLS at all.")
		fmt.Println("With a proxy set, that is the proxy replying in cleartext instead of")
		fmt.Println("opening the tunnel — read the bytes in the error, they are its reply.")

	case okCount == len(results) && control.ok:
		fmt.Println("Every handshake completed. The TLS layer is not what is failing;")
		fmt.Println("look at the HTTP response — a challenge or a block page is not a")
		fmt.Println("handshake error. Check the certificate issuer above is the target's")
		fmt.Println("own CA and not a middlebox terminating TLS on the way.")

	case control.ok && okCount == 0:
		fmt.Println("The target completes a handshake with a stock Go client and refuses")
		fmt.Println("every emulated one. The rejection is about our ClientHello, not the")
		fmt.Println("address or the network: cipher suites, groups, signature algorithms")
		fmt.Println("or the fingerprint itself. The alert above names which.")

	case control.ok && okCount > 0:
		fmt.Println("Some profiles get through and others do not, so the target is")
		fmt.Println("deciding on the ClientHello. Use a profile that completed, and")
		fmt.Println("compare the two hellos for the difference the edge reacted to.")

	case !control.ok && okCount > 0:
		fmt.Println("The emulated hellos work where the stock client does not, which is")
		fmt.Println("the fingerprint doing its job. Nothing to fix here.")

	case allErrContains(control, results, "unrecognized_name"):
		fmt.Println("The server has no certificate for this name. Send the SNI the")
		fmt.Println("target expects (-sni), and make sure the Host header matches it.")

	case allErrContains(control, results, "protocol_version"):
		fmt.Println("The target refuses TLS 1.3 and this package speaks only TLS 1.3.")
		fmt.Println("Nothing in the fingerprint will change that.")

	default:
		fmt.Println("Nothing completed, including the stock client, so the target is")
		fmt.Println("refusing everyone on this path — not just the emulated hello.")
		fmt.Println("The alert above is the server's own reason; treat it as the target's")
		fmt.Println("answer, not as a bug in the client.")
	}
}

func anyErrContains(control result, results map[string]result, needle string) bool {
	if control.err != nil && strings.Contains(control.err.Error(), needle) {
		return true
	}
	for _, r := range results {
		if r.err != nil && strings.Contains(r.err.Error(), needle) {
			return true
		}
	}
	return false
}

func allErrContains(control result, results map[string]result, needle string) bool {
	if control.err == nil || !strings.Contains(control.err.Error(), needle) {
		return false
	}
	for _, r := range results {
		if r.err == nil || !strings.Contains(r.err.Error(), needle) {
			return false
		}
	}
	return true
}

// dialer returns a function that opens a TCP connection to addr, through the
// proxy if one was given.
func dialer(raw string, timeout time.Duration) (func(string) (net.Conn, error), error) {
	if raw == "" {
		return func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, timeout)
		}, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "http", "https":
		return func(addr string) (net.Conn, error) {
			return connectTunnel(u, addr, timeout)
		}, nil

	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, err
		}
		return func(addr string) (net.Conn, error) {
			return d.Dial("tcp", addr)
		}, nil

	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
}

// connectTunnel opens an HTTP CONNECT tunnel to addr through the proxy.
func connectTunnel(u *url.URL, addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", u.Host, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if u.User != nil {
		pw, _ := u.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pw))
		req += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT reply: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy refused CONNECT: %s", resp.Status)
	}
	if br.Buffered() > 0 {
		// The proxy sent body bytes before the tunnel opened; the TLS
		// handshake would read them as a record and report nonsense.
		conn.Close()
		return nil, fmt.Errorf("proxy sent %d bytes after the CONNECT reply", br.Buffered())
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

// splitTarget accepts a host, a host:port or a URL and returns a dial address
// and the host name to use for SNI.
func splitTarget(target string) (addr, host string, err error) {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", "", err
		}
		host = u.Hostname()
		port := u.Port()
		if port == "" {
			port = "443"
		}
		return net.JoinHostPort(host, port), host, nil
	}

	if h, p, err := net.SplitHostPort(target); err == nil {
		return net.JoinHostPort(h, p), h, nil
	}
	return net.JoinHostPort(target, "443"), target, nil
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "tls1.3"
	case tls.VersionTLS12:
		return "tls1.2"
	case tls.VersionTLS11:
		return "tls1.1"
	case tls.VersionTLS10:
		return "tls1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// redact hides proxy credentials so the output can be pasted somewhere.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		u.User = url.User("***")
	}
	return u.String()
}
