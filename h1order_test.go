package gofire

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeConn captures everything written to it.
type fakeConn struct {
	net.Conn
	buf bytes.Buffer
}

func (f *fakeConn) Write(p []byte) (int, error) { return f.buf.Write(p) }
func (f *fakeConn) Close() error                { return nil }

// headerNames returns the header keys of a request head in wire order.
func headerNames(head string) []string {
	lines := strings.Split(head, "\r\n")
	var out []string
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		if i := strings.IndexByte(line, ':'); i > 0 {
			out = append(out, http.CanonicalHeaderKey(line[:i]))
		}
	}
	return out
}

// TestH1OrderConnReordersHeaders covers the core of the HTTP/1.1 fix.
// net/http sorts request headers alphabetically with no hook to change it, so
// without this rewrite the h1 path emitted an order no browser produces.
func TestH1OrderConnReordersHeaders(t *testing.T) {
	// What net/http would put on the wire: Host first, then alphabetical.
	head := "GET /path HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Accept: text/html\r\n" +
		"Accept-Encoding: gzip\r\n" +
		"Accept-Language: en-US\r\n" +
		"Priority: u=0, i\r\n" +
		"Sec-Fetch-Dest: document\r\n" +
		"Sec-Fetch-Mode: navigate\r\n" +
		"Sec-Fetch-Site: none\r\n" +
		"User-Agent: TestAgent\r\n" +
		"\r\n"

	fc := &fakeConn{}
	conn := newH1OrderConn(fc, safariIOS18HeaderOrder)
	n, err := conn.Write([]byte(head))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(head) {
		t.Fatalf("Write returned %d, want %d", n, len(head))
	}

	got := headerNames(fc.buf.String())
	want := []string{
		"Host",
		"Sec-Fetch-Dest",
		"User-Agent",
		"Accept",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Accept-Language",
		"Priority",
		"Accept-Encoding",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("header order:\n got %v\nwant %v", got, want)
	}

	// Reordering must not lose or invent bytes.
	if fc.buf.Len() != len(head) {
		t.Fatalf("rewrote %d bytes, input was %d", fc.buf.Len(), len(head))
	}
}

// TestH1OrderConnBodyPassthrough checks that request bodies are forwarded
// untouched and that the connection returns to head state afterwards, so a
// second request on the same keep-alive connection is also reordered.
func TestH1OrderConnBodyPassthrough(t *testing.T) {
	body := `{"a":1}`
	first := "POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Accept: */*\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n" +
		"Content-Type: application/json\r\n" +
		"User-Agent: TestAgent\r\n" +
		"\r\n" + body
	second := "GET /next HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Accept: text/html\r\n" +
		"User-Agent: TestAgent\r\n" +
		"\r\n"

	for _, split := range []int{0, 1, 17, 40, len(first) - 1} {
		t.Run(fmt.Sprintf("split-%d", split), func(t *testing.T) {
			fc := &fakeConn{}
			conn := newH1OrderConn(fc, safariIOS18HeaderOrder)

			payload := first + second
			if split == 0 {
				if _, err := conn.Write([]byte(payload)); err != nil {
					t.Fatalf("Write: %v", err)
				}
			} else {
				if _, err := conn.Write([]byte(payload[:split])); err != nil {
					t.Fatalf("Write head: %v", err)
				}
				if _, err := conn.Write([]byte(payload[split:])); err != nil {
					t.Fatalf("Write tail: %v", err)
				}
			}

			out := fc.buf.String()
			if !strings.Contains(out, body) {
				t.Fatalf("request body missing from the wire: %q", out)
			}
			if fc.buf.Len() != len(payload) {
				t.Fatalf("wrote %d bytes, input was %d", fc.buf.Len(), len(payload))
			}
			// User-Agent precedes Accept in Safari order; alphabetical would
			// have put Accept first. Both requests must show the fix.
			if strings.Count(out, "User-Agent: TestAgent\r\nAccept:") != 2 {
				t.Fatalf("second request on the connection was not reordered:\n%s", out)
			}
		})
	}
}

// TestH1OrderConnChunkedBody checks that a chunked request body is passed
// through byte for byte and that the following request is still reordered —
// the chunk framing has to be parsed to know where the body ends.
func TestH1OrderConnChunkedBody(t *testing.T) {
	chunked := "POST /upload HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Accept: */*\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"User-Agent: TestAgent\r\n" +
		"\r\n" +
		"5\r\nhello\r\n" +
		"6\r\n world\r\n" +
		"0\r\n\r\n"
	next := "GET /after HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Accept: text/html\r\n" +
		"User-Agent: TestAgent\r\n" +
		"\r\n"

	fc := &fakeConn{}
	conn := newH1OrderConn(fc, safariIOS18HeaderOrder)
	payload := chunked + next
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	out := fc.buf.String()
	if !strings.Contains(out, "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n") {
		t.Fatalf("chunk framing was altered:\n%q", out)
	}
	if fc.buf.Len() != len(payload) {
		t.Fatalf("wrote %d bytes, input was %d", fc.buf.Len(), len(payload))
	}
	if strings.Count(out, "User-Agent: TestAgent\r\nAccept:") != 2 {
		t.Fatalf("request after the chunked body was not reordered:\n%s", out)
	}
}

// TestH1OrderConnLeavesUnknownHeadersAtEnd pins that headers outside the
// browser table keep their relative order and are not dropped.
func TestH1OrderConnLeavesUnknownHeadersAtEnd(t *testing.T) {
	head := "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"X-Zulu: 1\r\n" +
		"Accept: text/html\r\n" +
		"X-Alpha: 2\r\n" +
		"\r\n"

	fc := &fakeConn{}
	conn := newH1OrderConn(fc, safariIOS18HeaderOrder)
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := headerNames(fc.buf.String())
	want := []string{"Host", "Accept", "X-Zulu", "X-Alpha"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("header order:\n got %v\nwant %v", got, want)
	}
}

// rawHTTPServer accepts one connection, records the request head, and replies.
func rawHTTPServer(t *testing.T) (addr string, heads func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	var captured []string

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				var head strings.Builder
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					head.WriteString(line)
					if line == "\r\n" {
						break
					}
				}
				mu.Lock()
				captured = append(captured, head.String())
				mu.Unlock()
				fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}()
		}
	}()

	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), captured...)
	}
}

// TestHTTP1RequestsUseBrowserHeaderOrder is the end-to-end check: a real
// request through the client must reach the wire in browser order, not the
// alphabetical order net/http produces.
func TestHTTP1RequestsUseBrowserHeaderOrder(t *testing.T) {
	addr, heads := rawHTTPServer(t)

	client, err := NewClient(WithForceHTTP1())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.GetWithContext(ctx, "http://"+addr+"/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Close()

	got := heads()
	if len(got) == 0 {
		t.Fatal("server captured no request")
	}
	names := headerNames(got[0])
	if len(names) < 3 {
		t.Fatalf("too few headers captured: %v", names)
	}
	if names[0] != "Host" {
		t.Fatalf("Host must come first, got %v", names)
	}

	// Safari sends Sec-Fetch-Dest before User-Agent and Accept-Encoding last.
	// Alphabetical order would put Accept-Encoding second and Sec-Fetch-Dest
	// near the end, so this fails loudly if the rewrite stops running.
	pos := map[string]int{}
	for i, n := range names {
		pos[n] = i
	}
	if pos["Sec-Fetch-Dest"] > pos["User-Agent"] {
		t.Errorf("Sec-Fetch-Dest must precede User-Agent, got %v", names)
	}
	if pos["Accept-Encoding"] != len(names)-1 {
		t.Errorf("Accept-Encoding must be last, got %v", names)
	}
}
