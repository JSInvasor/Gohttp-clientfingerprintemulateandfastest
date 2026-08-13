package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// The claim -solve -proxy-file makes is that a cookie leaves through the exit it
// was issued to. Everything else in these tests checks a step of that; this one
// checks the whole thing, with real sockets: two CONNECT proxies in front of one
// origin, and an assertion that the request carrying exit A's cf_clearance is
// the one that arrived through proxy A.
//
// The pairing is recovered from the ports. A CONNECT tunnel is opaque to the
// proxy once it is up, so the proxy cannot read the cookie — but it knows the
// local address it dialled the origin from, and the origin sees that address as
// the client. Joining the two is what turns "both cookies arrived" into "each
// cookie arrived through its own exit", which is the difference between this
// working and it silently pinning everything to one proxy.
func TestSolvedSessionsDialTheirOwnExit(t *testing.T) {
	var (
		mu       sync.Mutex
		exitPort = map[string]string{} // origin-side port -> proxy name
		seen     = map[string]string{} // proxy name -> cf_clearance it carried
	)

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clearance := ""
		if c, err := r.Cookie("cf_clearance"); err == nil {
			clearance = c.Value
		}
		_, port, _ := net.SplitHostPort(r.RemoteAddr)

		mu.Lock()
		seen[exitPort[port]] = clearance
		mu.Unlock()

		w.Write([]byte("ok"))
	}))
	defer origin.Close()
	originAddr := strings.TrimPrefix(origin.URL, "https://")

	proxies := make([]string, 2)
	for i, name := range []string{"a", "b"} {
		addr, stop := connectProxy(t, originAddr, func(localPort string) {
			mu.Lock()
			exitPort[localPort] = name
			mu.Unlock()
		})
		defer stop()
		proxies[i] = "http://" + addr
	}

	o := &options{
		sessions:  2,
		insecure:  true, // httptest's certificate is self-signed
		maxBody:   -1,
		proxyList: proxies,
		solveSeeds: []solveSeed{
			{proxy: proxies[0], cookies: []string{"cf_clearance=for-a"}},
			{proxy: proxies[1], cookies: []string{"cf_clearance=for-b"}},
		},
	}
	pool, err := newSessionPool(o, gofire.Chrome151, origin.URL)
	if err != nil {
		t.Fatalf("newSessionPool: %v", err)
	}
	defer pool.Close()

	for i, s := range pool.sessions {
		resp, err := s.client.Get(origin.URL)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		resp.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	for name, want := range map[string]string{"a": "for-a", "b": "for-b"} {
		if got := seen[name]; got != want {
			t.Errorf("proxy %s carried cf_clearance=%q, want %q", name, got, want)
		}
	}
}

// connectProxy is an HTTP CONNECT proxy that only ever tunnels to origin, and
// reports the local port it dialled from so the caller can tell its traffic
// apart from another proxy's.
func connectProxy(t *testing.T, origin string, onDial func(localPort string)) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}

	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()

				// Read the CONNECT request. Nothing here inspects it: the
				// target is fixed, and what is being tested is which proxy the
				// client chose, not what it asked for.
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

				up, err := net.Dial("tcp", origin)
				if err != nil {
					fmt.Fprint(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				if _, port, err := net.SplitHostPort(up.LocalAddr().String()); err == nil {
					onDial(port)
				}

				if _, err := fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					return
				}
				go io.Copy(up, br) //nolint:errcheck // the tunnel ends when either side closes
				io.Copy(client, up)
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}
