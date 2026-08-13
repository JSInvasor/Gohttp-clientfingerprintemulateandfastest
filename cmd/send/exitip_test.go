package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// traceServer stands in for the address check, answering in Cloudflare's trace
// format. Given more than one address it returns them in turn, one per request,
// which is what a backconnect gateway looks like from the client's side.
//
// Per request rather than per connection on purpose: what breaks a cf_clearance
// is the address changing between the solve and the requests that follow, and a
// request is the unit that has one.
func traceServer(t *testing.T, ips ...string) *httptest.Server {
	t.Helper()
	var n atomic.Uint64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ips[(n.Add(1)-1)%uint64(len(ips))]
		fmt.Fprintf(w, "fl=1f2\nh=www.cloudflare.com\nip=%s\nts=1\n", ip)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// tunnelProxy is a CONNECT proxy that ignores where it was asked to go and
// tunnels to a fixed backend, so each simulated exit can answer with an address
// of its own without any of them needing a real one.
func tunnelProxy(t *testing.T, backends ...string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var n atomic.Uint64
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				br := bufio.NewReader(client)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				backend := backends[(n.Add(1)-1)%uint64(len(backends))]
				up, err := net.Dial("tcp", backend)
				if err != nil {
					fmt.Fprint(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				if _, err := fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					return
				}
				go io.Copy(up, br) //nolint:errcheck // the tunnel ends when either side closes
				io.Copy(client, up)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

func exitOptions(t *testing.T) *options {
	t.Helper()
	return &options{
		exitCheck: "https://trace.test/cdn-cgi/trace",
		insecure:  true, // the stand-in trace servers are self-signed
		maxBody:   -1,
	}
}

func hostOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "https://")
}

// The point of the whole file: a hundred-line list is usually not a hundred
// exits. Entries that leave from one address are one identity and one solve.
func TestResolveExitsCollapsesSharedAddresses(t *testing.T) {
	a := traceServer(t, "203.0.113.10")
	b := traceServer(t, "203.0.113.10") // same address, different entry
	c := traceServer(t, "203.0.113.99")

	proxies := []string{
		tunnelProxy(t, hostOf(t, a)),
		tunnelProxy(t, hostOf(t, b)),
		tunnelProxy(t, hostOf(t, c)),
	}

	exits, err := resolveExits(context.Background(), exitOptions(t), gofire.Chrome151, proxies)
	if err != nil {
		t.Fatalf("resolveExits: %v", err)
	}
	if len(exits) != 2 {
		t.Fatalf("%d exits from 3 proxies on 2 addresses: %+v", len(exits), exits)
	}
	if exits[0].ip != "203.0.113.10" || exits[1].ip != "203.0.113.99" {
		t.Errorf("exits = %+v, want the two distinct addresses in first-seen order", exits)
	}
	// The survivor of a group is the entry that got there first, so the list
	// stays in the order the file gave.
	if exits[0].proxy != proxies[0] || exits[1].proxy != proxies[2] {
		t.Errorf("exits = %+v, want the first proxy of each group", exits)
	}
}

// A backconnect gateway cannot hold a cf_clearance: the cookie is bound to
// whichever address the browser happened to get, and the next request leaves
// from a different one. Solving through it is not slow, it is pointless.
func TestResolveExitsDropsRotatingProxies(t *testing.T) {
	rotates := traceServer(t, "203.0.113.1", "203.0.113.2")
	fixed := traceServer(t, "203.0.113.7")

	rotating := tunnelProxy(t, hostOf(t, rotates))
	steady := tunnelProxy(t, hostOf(t, fixed))

	exits, err := resolveExits(context.Background(), exitOptions(t), gofire.Chrome151,
		[]string{rotating, steady})
	if err != nil {
		t.Fatalf("resolveExits: %v", err)
	}
	if len(exits) != 1 || exits[0].proxy != steady {
		t.Fatalf("exits = %+v, want only the steady proxy", exits)
	}
}

// A dead proxy costs a second here instead of a whole solve timeout, which on a
// list with a few dead entries is most of the saving on its own.
func TestResolveExitsDropsUnreachableProxies(t *testing.T) {
	live := traceServer(t, "203.0.113.5")
	good := tunnelProxy(t, hostOf(t, live))

	// A listener that is closed immediately: connecting to it fails fast rather
	// than hanging for the probe timeout.
	dead := deadAddr(t)

	exits, err := resolveExits(context.Background(), exitOptions(t), gofire.Chrome151,
		[]string{"http://" + dead, good})
	if err != nil {
		t.Fatalf("resolveExits: %v", err)
	}
	if len(exits) != 1 || exits[0].proxy != good {
		t.Fatalf("exits = %+v, want only the reachable proxy", exits)
	}
}

// Nothing usable is a configuration error worth stopping on, with the reason
// and the way to override it.
func TestResolveExitsFailsWhenNothingIsUsable(t *testing.T) {
	_, err := resolveExits(context.Background(), exitOptions(t), gofire.Chrome151,
		[]string{"http://" + deadAddr(t)})
	if err == nil {
		t.Fatal("a list with no usable exit was accepted")
	}
	if !strings.Contains(err.Error(), "-solve-ip-check") {
		t.Errorf("error %q does not say how to solve through them anyway", err)
	}
}

// Turning the check off is the old behaviour: every entry stands for its own
// exit, and nothing is measured or dialled.
func TestResolveExitsSkippedWhenDisabled(t *testing.T) {
	o := exitOptions(t)
	o.exitCheck = ""
	proxies := []string{"http://a.test:1", "http://b.test:2"}

	exits, err := resolveExits(context.Background(), o, gofire.Chrome151, proxies)
	if err != nil {
		t.Fatalf("resolveExits: %v", err)
	}
	if len(exits) != 2 {
		t.Fatalf("exits = %+v, want one per entry", exits)
	}
	for i, e := range exits {
		if e.proxy != proxies[i] || e.ip != "" {
			t.Errorf("exit %d = %+v, want the entry unmeasured", i, e)
		}
	}
}

// The cache is keyed by what the cookie is bound to. Two entries on one address
// share the entry — which is the same reason they share a solve.
func TestExitIdentityIsTheAddressWhenKnown(t *testing.T) {
	measured := exit{proxy: "http://a.test:1", ip: "203.0.113.10"}
	other := exit{proxy: "http://b.test:2", ip: "203.0.113.10"}
	if measured.identity() != other.identity() {
		t.Error("two entries on one address got different cache identities")
	}
	if solveCacheKey("https://site.test/", measured.identity()) !=
		solveCacheKey("https://site.test/", other.identity()) {
		t.Error("the shared address did not produce a shared cache key")
	}

	// Unmeasured falls back to the proxy string, which is what it was before
	// any of this and is still correct — just less shareable.
	unmeasured := exit{proxy: "http://a.test:1"}
	if unmeasured.identity() != "http://a.test:1" {
		t.Errorf("identity() = %q, want the proxy string", unmeasured.identity())
	}
	// Credentials must not reach the output through the label.
	withAuth := exit{proxy: "http://user:pass@a.test:1", ip: "203.0.113.10"}
	if strings.Contains(withAuth.label(), "pass") {
		t.Errorf("label() = %q leaks the password", withAuth.label())
	}
}

func TestParseExitIP(t *testing.T) {
	trace := "fl=1f2\nh=www.cloudflare.com\nip=203.0.113.10\nts=1700000000.1\nvisit_scheme=https\n"
	if got := parseExitIP(trace); got != "203.0.113.10" {
		t.Errorf("trace ip = %q", got)
	}
	// Every other what-is-my-ip service answers with the bare address, so
	// -solve-ip-check can point at one without a second parser.
	if got := parseExitIP("203.0.113.10\n"); got != "203.0.113.10" {
		t.Errorf("bare ip = %q", got)
	}
	if got := parseExitIP("2001:db8::1"); got != "2001:db8::1" {
		t.Errorf("ipv6 = %q", got)
	}
	// An error page is not an address.
	for _, body := range []string{"", "   ", "<html><body>502</body></html>", "not an address here"} {
		if got := parseExitIP(body); got != "" {
			t.Errorf("parseExitIP(%q) = %q, want no address", body, got)
		}
	}
}

// deadAddr returns a loopback address with nothing listening on it.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}
