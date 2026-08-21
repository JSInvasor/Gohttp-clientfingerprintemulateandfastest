package gofire

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// deadTunnelProxy accepts CONNECT, answers 200, and then carries nothing: the
// bytes after the tunnel comes up are not a TLS server.
//
// It is the shape of a proxy that is reachable but useless — an intercepting
// gateway, a pool answering for exits it can no longer reach, an upstream that
// died after the handshake with the proxy itself. From the rotator's old
// vantage point it was indistinguishable from a healthy one, because the only
// thing it ever saw was the CONNECT.
func deadTunnelProxy(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// A proxy that tunnels and then carries nothing has to be benched.
//
// It was not. MarkSuccess was called the moment CONNECT returned 200, which is
// the weaker claim: the proxy is reachable, not that anything can be carried
// over it. Since a success also clears deadUntilNs, such a proxy could never
// accumulate the consecutive failures a bench needs — it was credited, failed
// the request, and credited again on the next one, forever. Under -s pinning
// that is a session spending its entire share of a run on one dead exit.
func TestTLSFailureThroughAProxyBenchesIt(t *testing.T) {
	addr, stop := deadTunnelProxy(t)
	defer stop()

	pr, err := NewProxyRotator([]string{"http://" + addr})
	if err != nil {
		t.Fatalf("NewProxyRotator: %v", err)
	}
	pr.SetFailThreshold(1)
	pr.SetCooldown(time.Minute)

	client, err := Emulate(Chrome151,
		WithTimeout(5*time.Second),
		WithTLSHandshakeTimeout(2*time.Second),
	)
	if err != nil {
		t.Fatalf("Emulate: %v", err)
	}
	defer client.Close()
	client.SetProxyRotator(pr)

	if resp, err := client.Get("https://site.invalid/"); err == nil {
		resp.Close()
		t.Fatal("the request succeeded through a proxy that carries nothing")
	}

	if live := pr.LiveCount(); live != 0 {
		t.Errorf("LiveCount = %d, want 0: the proxy completed CONNECT and then failed the "+
			"handshake, and was left in rotation", live)
	}
	st := pr.Stats()[0]
	if st.Failed == 0 {
		t.Errorf("Failed = 0: the handshake failure was not charged to the proxy")
	}
	if st.Used != 0 {
		t.Errorf("Used = %d, want 0: Used counts connections that carried something, and this "+
			"one never got past the handshake", st.Used)
	}
}

// The counterpart, so the fix above cannot be "never credit anything": a proxy
// that does carry the connection is credited, and its earlier failures cleared.
func TestWorkingProxyIsStillCredited(t *testing.T) {
	origin, _, stopOrigin := fakeOrigin(t)
	defer stopOrigin()

	addr, stop := connectProxyTo(t, origin)
	defer stop()

	pr, err := NewProxyRotator([]string{"http://" + addr})
	if err != nil {
		t.Fatalf("NewProxyRotator: %v", err)
	}

	client, err := Emulate(Chrome151, WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("Emulate: %v", err)
	}
	defer client.Close()
	client.SetProxyRotator(pr)

	// Cleartext, so the verdict lands on the path that has no handshake to wait
	// for — the one case where scoring at dial time is still right.
	resp, err := client.Get("http://" + origin + "/")
	if err != nil {
		t.Fatalf("request through a working proxy: %v", err)
	}
	resp.Close()

	if st := pr.Stats()[0]; st.Used == 0 {
		t.Errorf("Used = 0: a connection that carried a response was not credited")
	}
	if live := pr.LiveCount(); live != 1 {
		t.Errorf("LiveCount = %d, want 1", live)
	}
}

// connectProxyTo is a CONNECT proxy that only ever tunnels to origin.
func connectProxyTo(t *testing.T, origin string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
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
					fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// WithDisableKeepAlives has to reach the HTTP/2 transport, not only the
// HTTP/1.1 one.
//
// It did not. The fork's h2 Transport is constructed standalone, and upstream
// reads the setting off t1 — the net/http Transport a ConfigureTransports
// pairing supplies, which this client never creates. So the flag applied to the
// h1 path only, which is the wrong half: h2 is where a connection is long-lived
// enough for the difference to matter, and under a rotator it is what decides
// whether a run leaves from one address or from all of them.
func TestDisableKeepAlivesReachesHTTP2(t *testing.T) {
	client, err := Emulate(Chrome151, WithDisableKeepAlives())
	if err != nil {
		t.Fatalf("Emulate: %v", err)
	}
	defer client.Close()

	if client.transport.h2Transport == nil {
		t.Fatal("no h2 transport to check")
	}
	if !client.transport.h2Transport.DisableKeepAlives {
		t.Error("WithDisableKeepAlives did not reach the HTTP/2 transport, so an h2 run keeps " +
			"its connections — and, under a rotator, its single exit")
	}
	if !client.transport.h1Transport.DisableKeepAlives {
		t.Error("WithDisableKeepAlives stopped reaching the HTTP/1.1 transport")
	}

	// Off by default on both, so nothing here changes an ordinary run.
	plain, err := Emulate(Chrome151)
	if err != nil {
		t.Fatalf("Emulate: %v", err)
	}
	defer plain.Close()
	if plain.transport.h2Transport.DisableKeepAlives {
		t.Error("keep-alives are disabled on h2 without the option being given")
	}
}
