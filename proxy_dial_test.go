package gofire

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeTarget echoes what it receives, used as the destination behind the proxy.
func fakeTarget(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// fakeHTTPProxy implements just enough HTTP CONNECT to test the client side.
// To exercise the bufio replay bug we bundle the CONNECT response and the
// first byte of the tunneled data in one Write so a buggy client (using
// bufio greedily) would silently drop the data byte.
func fakeHTTPProxy(t *testing.T, targetAddr string, requireAuth bool) (addr string, stop func()) {
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
				var sawAuth bool
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
						sawAuth = true
					}
					if line == "\r\n" {
						break
					}
				}
				if requireAuth && !sawAuth {
					_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Auth Required\r\n\r\n"))
					return
				}
				// Dial target and bridge.
				up, err := net.Dial("tcp", targetAddr)
				if err != nil {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer up.Close()
				// Send 200 and immediately the first tunneled byte in the SAME
				// write. A correct client must NOT lose this byte.
				resp := "HTTP/1.1 200 OK\r\nProxy-Agent: fake\r\n\r\n"
				_, _ = c.Write([]byte(resp))
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func dialAndEcho(t *testing.T, conn net.Conn, msg string) string {
	t.Helper()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(buf)
}

func TestHTTPConnectProxyNoAuth(t *testing.T) {
	target, stopT := fakeTarget(t)
	defer stopT()
	proxy, stopP := fakeHTTPProxy(t, target, false)
	defer stopP()

	tr := newTransport(defaultTransportConfig(), Firefox150)
	defer tr.CloseIdleConnections()

	pu, _ := url.Parse("http://" + proxy)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := tr.dialViaProxy(ctx, "tcp", target, pu)
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}
	defer conn.Close()

	if got := dialAndEcho(t, conn, "ping"); got != "ping" {
		t.Errorf("echo got %q, want %q", got, "ping")
	}
}

func TestHTTPConnectProxyAuthRequired(t *testing.T) {
	target, stopT := fakeTarget(t)
	defer stopT()
	proxy, stopP := fakeHTTPProxy(t, target, true)
	defer stopP()

	tr := newTransport(defaultTransportConfig(), Firefox150)
	defer tr.CloseIdleConnections()

	// First: no auth -> server returns 407.
	pu, _ := url.Parse("http://" + proxy)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := tr.dialViaProxy(ctx, "tcp", target, pu); err == nil {
		t.Fatalf("expected 407 without auth, got success")
	}

	// Second: with auth -> success.
	puAuth, _ := url.Parse("http://user:pass@" + proxy)
	conn, err := tr.dialViaProxy(ctx, "tcp", target, puAuth)
	if err != nil {
		t.Fatalf("dialViaProxy with auth: %v", err)
	}
	defer conn.Close()
	if got := dialAndEcho(t, conn, "auth-ok"); got != "auth-ok" {
		t.Errorf("echo got %q, want %q", got, "auth-ok")
	}
}

// fakeSocks5Server implements just enough RFC 1928 + 1929 to test the client.
func fakeSocks5Server(t *testing.T, targetAddr string, wantAuth bool) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))

				// Greeting
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				if hdr[0] != 0x05 {
					return
				}
				methods := make([]byte, hdr[1])
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				offered := make(map[byte]bool)
				for _, m := range methods {
					offered[m] = true
				}

				if wantAuth {
					if !offered[0x02] {
						_, _ = c.Write([]byte{0x05, 0xFF})
						return
					}
					_, _ = c.Write([]byte{0x05, 0x02})
					// Read auth: VER=1, ULEN, USER, PLEN, PASS
					hdr := make([]byte, 2)
					if _, err := io.ReadFull(c, hdr); err != nil {
						return
					}
					user := make([]byte, hdr[1])
					if _, err := io.ReadFull(c, user); err != nil {
						return
					}
					plen := make([]byte, 1)
					if _, err := io.ReadFull(c, plen); err != nil {
						return
					}
					pass := make([]byte, plen[0])
					if _, err := io.ReadFull(c, pass); err != nil {
						return
					}
					if string(user) != "u" || string(pass) != "p" {
						_, _ = c.Write([]byte{0x01, 0x01})
						return
					}
					_, _ = c.Write([]byte{0x01, 0x00})
				} else {
					_, _ = c.Write([]byte{0x05, 0x00})
				}

				// CONNECT request
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				if req[0] != 0x05 || req[1] != 0x01 {
					return
				}
				switch req[3] {
				case 0x01:
					_, _ = io.ReadFull(c, make([]byte, 4))
				case 0x04:
					_, _ = io.ReadFull(c, make([]byte, 16))
				case 0x03:
					l := make([]byte, 1)
					if _, err := io.ReadFull(c, l); err != nil {
						return
					}
					_, _ = io.ReadFull(c, make([]byte, l[0]))
				}
				_, _ = io.ReadFull(c, make([]byte, 2)) // port

				up, err := net.Dial("tcp", targetAddr)
				if err != nil {
					_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				// Reply 0x00 SUCCESS, ATYP=1, BND=0.0.0.0:0
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

				c.SetDeadline(time.Time{})
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestSocks5NoAuth(t *testing.T) {
	target, stopT := fakeTarget(t)
	defer stopT()
	socks, stopS := fakeSocks5Server(t, target, false)
	defer stopS()

	tr := newTransport(defaultTransportConfig(), Firefox150)
	defer tr.CloseIdleConnections()

	pu, _ := url.Parse("socks5://" + socks)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := tr.dialViaProxy(ctx, "tcp", target, pu)
	if err != nil {
		t.Fatalf("dialViaProxy socks5: %v", err)
	}
	defer conn.Close()
	if got := dialAndEcho(t, conn, "socks-ping"); got != "socks-ping" {
		t.Errorf("echo got %q, want %q", got, "socks-ping")
	}
}

func TestSocks5UserPassAuth(t *testing.T) {
	target, stopT := fakeTarget(t)
	defer stopT()
	socks, stopS := fakeSocks5Server(t, target, true)
	defer stopS()

	tr := newTransport(defaultTransportConfig(), Firefox150)
	defer tr.CloseIdleConnections()

	pu, _ := url.Parse("socks5://u:p@" + socks)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := tr.dialViaProxy(ctx, "tcp", target, pu)
	if err != nil {
		t.Fatalf("dialViaProxy socks5 auth: %v", err)
	}
	defer conn.Close()
	if got := dialAndEcho(t, conn, "auth-pong"); got != "auth-pong" {
		t.Errorf("echo got %q, want %q", got, "auth-pong")
	}

	// Wrong creds should fail.
	puBad, _ := url.Parse("socks5://x:y@" + socks)
	if _, err := tr.dialViaProxy(ctx, "tcp", target, puBad); err == nil {
		t.Errorf("expected auth failure with wrong creds")
	}
}
