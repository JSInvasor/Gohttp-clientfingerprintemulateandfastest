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
//
// A handshake that only fails under load fails for a different reason than one
// that fails on its own. -n repeats it at a concurrency you choose and buckets
// the outcomes, so the two are told apart by counting rather than by guessing:
//
//	go run ./example/tlsprobe -target example.com -n 500 -c 64
//
// When every handshake completes, the failure is above TLS and the response is
// what names it. -http sends one real request per profile through this
// package's own client and reports the status, the edge that answered and
// whether it challenged, blocked or rate limited:
//
//	go run ./example/tlsprobe -target example.com -http
//	go run ./example/tlsprobe -target example.com -http -path /api/session
//
// -n with -http repeats the request rather than the handshake, over one client
// and one connection pool, and buckets the responses by status and by the edge
// decision behind it — which is where a workload that survives every handshake
// still falls over:
//
//	go run ./example/tlsprobe -target example.com -http -n 500 -c 64
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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/ctls"
)

var alpn = []string{"h2", "http/1.1"}

// profiles is the emulated set, in report order. The HTTP leg reuses the same
// labels so a handshake line and a response line name the same client.
var profiles = []struct {
	label   string
	browser ctls.BrowserType
}{
	{"chrome", ctls.BrowserChrome},
	{"safari", ctls.BrowserSafari},
}

func main() {
	target := flag.String("target", "", "host, host:port or URL to probe (required)")
	sni := flag.String("sni", "", "server name to send (default: the target host)")
	proxyURL := flag.String("proxy", "", "http:// or socks5:// proxy to reach the target through")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	timeout := flag.Duration("timeout", 10*time.Second, "per-attempt timeout")
	count := flag.Int("n", 0, "after the single pass, run this many handshakes — or requests, with -http — to reproduce a failure that only appears under load")
	conc := flag.Int("c", 32, "concurrent handshakes during the -n run")
	profile := flag.String("profile", "chrome", "profile for the -n run: chrome, safari or stdlib")
	doHTTP := flag.Bool("http", false, "after the handshakes, send one real request per profile and report what came back")
	path := flag.String("path", "/", "path to request during the -http run")
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
	for _, p := range profiles {
		res := probeCtls(dial, addr, name, p.browser, *insecure, *timeout)
		results[p.label] = res
		report(p.label, res)
	}

	fmt.Println()
	verdict(control, results, *doHTTP)

	if *doHTTP {
		// Only profiles that completed a handshake can carry a request; the
		// others already have their answer above.
		var ready []string
		for _, p := range profiles {
			if results[p.label].ok {
				ready = append(ready, p.label)
			}
		}
		fmt.Println()
		if len(ready) == 0 {
			fmt.Println("http     skipped — no emulated profile finished its handshake, so")
			fmt.Println("         there is no response to read.")
		} else {
			reqURL, pinned := requestURL(addr, name, *path)
			httpRun(reqURL, *proxyURL, ready, pinned, *insecure, *timeout)
		}
	}

	if *count > 0 {
		fmt.Println()
		if *doHTTP {
			// With -http the workload being reproduced is requests, not dials:
			// loading the handshake again would only re-measure what the leg
			// above already established.
			reqURL, _ := requestURL(addr, name, *path)
			httpLoad(reqURL, *proxyURL, *profile, *count, *conc, *insecure, *timeout)
		} else {
			singleOK := control.ok
			if res, ok := results[*profile]; ok {
				singleOK = res.ok
			}
			loadRun(dial, addr, name, *profile, *count, *conc, singleOK, *insecure, *timeout)
		}
	}
}

// loadRun repeats the handshake to catch what a single one cannot see. An edge
// that answers one hello happily still drops them under a few thousand
// parallel dials, and that failure arrives as the same alert or a bare EOF —
// so the only way to tell a fingerprint rejection from a capacity limit is to
// count how the outcomes split at the volume that produced them.
func loadRun(dial func(string) (net.Conn, error), addr, name, profile string, count, conc int, singleOK, insecure bool, timeout time.Duration) {
	if conc < 1 {
		conc = 1
	}
	if conc > count {
		conc = count
	}

	var attempt func() (time.Duration, error)
	switch profile {
	case "stdlib":
		attempt = func() (time.Duration, error) {
			start := time.Now()
			res := probeStdlib(dial, addr, name, insecure, timeout)
			return time.Since(start), res.err
		}
	case "safari", "chrome":
		browser := ctls.BrowserChrome
		if profile == "safari" {
			browser = ctls.BrowserSafari
		}
		attempt = func() (time.Duration, error) {
			start := time.Now()
			res := probeCtls(dial, addr, name, browser, insecure, timeout)
			return time.Since(start), res.err
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown -profile %q (chrome, safari or stdlib)\n", profile)
		os.Exit(2)
	}

	fmt.Printf("load     %d handshakes, %d concurrent, %s\n", count, conc, profile)

	type outcome struct {
		took time.Duration
		err  error
	}
	jobs := make(chan struct{})
	out := make(chan outcome, count)

	var wg sync.WaitGroup
	started := time.Now()
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				took, err := attempt()
				out <- outcome{took, err}
			}
		}()
	}
	for i := 0; i < count; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()
	close(out)
	elapsed := time.Since(started)

	var oks []time.Duration
	failures := map[string]int{}
	for o := range out {
		if o.err == nil {
			oks = append(oks, o.took)
			continue
		}
		failures[normalize(o.err.Error())]++
	}

	pct := func(n int) float64 { return float64(n) * 100 / float64(count) }
	fmt.Printf("         %v elapsed, %.0f handshakes/sec\n", elapsed.Round(time.Millisecond), float64(count)/elapsed.Seconds())

	if len(oks) > 0 {
		sort.Slice(oks, func(i, j int) bool { return oks[i] < oks[j] })
		fmt.Printf("ok       %d (%.1f%%)  median %v  p95 %v  max %v\n",
			len(oks), pct(len(oks)),
			oks[len(oks)/2].Round(time.Millisecond),
			oks[(len(oks)*95)/100].Round(time.Millisecond),
			oks[len(oks)-1].Round(time.Millisecond))
	}
	if len(failures) == 0 {
		fmt.Println("fail     0")
		fmt.Println()
		fmt.Println("Nothing failed at this volume. If the real workload fails, raise -n")
		fmt.Println("and -c until they match it — the failure lives in the concurrency,")
		fmt.Println("not in the handshake.")
		return
	}

	total := 0
	for _, n := range failures {
		total += n
	}
	fmt.Printf("fail     %d (%.1f%%)\n", total, pct(total))

	type bucket struct {
		msg string
		n   int
	}
	buckets := make([]bucket, 0, len(failures))
	for msg, n := range failures {
		buckets = append(buckets, bucket{msg, n})
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].n > buckets[j].n })
	for _, b := range buckets {
		fmt.Printf("  %5d  %s\n", b.n, b.msg)
	}

	fmt.Println()
	if singleOK {
		fmt.Println("This profile completed its single handshake and fails here, so the")
		fmt.Println("failure is about volume rather than the ClientHello: the edge is")
		fmt.Println("shedding load. Lower -c until it disappears — that number is the")
		fmt.Println("target's ceiling for this source address, and no fingerprint change")
		fmt.Println("moves it.")
		return
	}
	fmt.Println("The single handshake above failed too, so this is not about volume.")
	fmt.Println("Read the verdict there: repeating a rejection only counts it.")
}

// normalize collapses the endpoint addresses in transport errors so the same
// failure does not land in a hundred buckets, one per ephemeral port.
var addrPattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b`)

func normalize(msg string) string {
	return addrPattern.ReplaceAllString(msg, "IP:PORT")
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
// httpRequested suppresses the pointer at -http when the run is already about
// to do it.
func verdict(control result, results map[string]result, httpRequested bool) {
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
		if !httpRequested {
			fmt.Println("Re-run with -http to send one request per profile and read what")
			fmt.Println("comes back.")
		}

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
