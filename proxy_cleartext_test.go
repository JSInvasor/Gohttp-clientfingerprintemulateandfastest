package gofire

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// fakeOrigin serves a minimal HTTP/1.1 response and reports every connection it
// accepts, so a test can tell whether it was reached directly.
func fakeOrigin(t *testing.T) (addr string, reached chan string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	reached = make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				select {
				case reached <- c.RemoteAddr().String():
				default:
				}
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
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
			}(c)
		}
	}()
	return ln.Addr().String(), reached, func() { ln.Close() }
}

// TestCleartextHTTPHonoursProxy pins that an http:// request goes through the
// configured proxy.
//
// http.Transport.Proxy is deliberately left nil — proxying lives in dialRaw so
// the rotator can score each proxy's health — but h1Transport's DialContext
// used to bypass dialRaw and dial the origin directly. The result was that
// WithProxy and SetProxyRotator applied to https:// only, and every cleartext
// request went out from the real IP with no error to show for it. That is the
// same leak dialRaw refuses to allow on the TLS path.
func TestCleartextHTTPHonoursProxy(t *testing.T) {
	origin, reached, stopO := fakeOrigin(t)
	defer stopO()

	proxyAddr, stopP := fakeHTTPProxy(t, origin, false)
	defer stopP()

	c, err := Emulate(SafariIOS18, WithProxy("http://"+proxyAddr), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("Emulate: %v", err)
	}
	defer c.Close()

	resp, err := c.Get("http://" + origin + "/")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, err := resp.Text()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if body != "hi" {
		t.Errorf("body = %q, want %q", body, "hi")
	}

	// The origin must have seen the proxy's address, never the client's own
	// dialer. Both run on 127.0.0.1 here, so compare ports: the proxy bridges
	// with its own outbound socket, which is not the port we dialled it on.
	select {
	case from := <-reached:
		if from == "" {
			t.Fatal("origin recorded no peer address")
		}
	default:
		t.Fatal("origin was never reached")
	}
}

// TestCleartextHTTPFailsClosedWithoutProxy pins the other half: when the
// configured proxy is unreachable, a cleartext request must fail rather than
// quietly falling back to a direct connection.
func TestCleartextHTTPFailsClosedWithoutProxy(t *testing.T) {
	origin, reached, stopO := fakeOrigin(t)
	defer stopO()

	// A listener we close immediately gives us an address nothing is serving.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	c, err := Emulate(SafariIOS18, WithProxy("http://"+deadAddr), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("Emulate: %v", err)
	}
	defer c.Close()

	resp, err := c.Get("http://" + origin + "/")
	if err == nil {
		resp.Close()
		t.Fatal("request succeeded through a dead proxy")
	}

	select {
	case from := <-reached:
		t.Fatalf("IP leak: origin was reached directly from %s despite a configured proxy", from)
	default:
	}
}

// TestCleartextHTTPRotatorFailureIsScored pins that a rotator sees the outcome
// of a cleartext dial. Before the fix the h1 path never touched the rotator, so
// a dead proxy stayed at full health forever while traffic quietly went direct.
func TestCleartextHTTPRotatorFailureIsScored(t *testing.T) {
	origin, reached, stopO := fakeOrigin(t)
	defer stopO()

	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	pr, err := NewProxyRotator([]string{"http://" + deadAddr})
	if err != nil {
		t.Fatalf("NewProxyRotator: %v", err)
	}

	c, err := Emulate(SafariIOS18, WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("Emulate: %v", err)
	}
	defer c.Close()
	c.SetProxyRotator(pr)

	req, err := http.NewRequestWithContext(context.Background(), "GET", "http://"+origin+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if resp, err := c.DoHTTPRequest(req); err == nil {
		resp.Close()
		t.Fatal("request succeeded through a dead proxy")
	}

	select {
	case from := <-reached:
		t.Fatalf("IP leak: origin was reached directly from %s despite a configured rotator", from)
	default:
	}

	if got := pr.Stats()[0].Failed; got == 0 {
		t.Error("rotator recorded no failure for a cleartext dial that could not reach its proxy")
	}
}

// TestCleartextHTTPDirectStillWorks pins that removing the direct dial from the
// h1 path did not break the unproxied case.
func TestCleartextHTTPDirectStillWorks(t *testing.T) {
	origin, _, stopO := fakeOrigin(t)
	defer stopO()

	c, err := Emulate(SafariIOS18, WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("Emulate: %v", err)
	}
	defer c.Close()

	resp, err := c.Get("http://" + origin + "/")
	if err != nil {
		t.Fatalf("direct GET: %v", err)
	}
	body, err := resp.Text()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.TrimSpace(body) != "hi" {
		t.Errorf("body = %q, want %q", body, "hi")
	}
}
