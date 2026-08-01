package gofire

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// maxRequestHead bounds how much of a request head we will buffer while looking
// for the end of the header block.
const maxRequestHead = 64 * 1024

var headEnd = []byte("\r\n\r\n")

// h1OrderConn rewrites outgoing HTTP/1.1 request header blocks into a browser's
// header order.
//
// net/http writes request headers alphabetically — Header.writeSubset sorts the
// keys and exposes no hook to change that — so without this the HTTP/1.1 path
// emits an order no browser produces. That silently undid half the emulation on
// every host whose ALPN selects http/1.1 and on every client built with
// WithForceHTTP1, while the HTTP/2 path kept its order through HPACK.
//
// Reordering happens on the wire, between net/http and the socket, so the
// transport keeps its own connection pooling, keep-alive and timeout handling.
// Permuting whole header lines preserves the total byte count, which keeps
// Write's return value consistent with what the caller handed us.
type h1OrderConn struct {
	net.Conn
	order []string

	state    h1WriteState
	buf      []byte // partial request head
	bodyLeft int64  // remaining identity-encoded body bytes
	chunk    chunkState
}

type h1WriteState int

const (
	stateHead h1WriteState = iota
	stateBody
	stateChunked
)

// tlsConnInfo is the handshake-inspection surface a ctls.Conn exposes. An
// embedded net.Conn does not promote these, so wrapping a TLS conn would
// otherwise hide them from any caller that type-asserts for them.
type tlsConnInfo interface {
	ConnectionState() tls.ConnectionState
	NegotiatedProtocol() string
}

// h1OrderTLSConn is h1OrderConn over a TLS connection, re-exposing the
// handshake accessors the wrapper would otherwise mask.
type h1OrderTLSConn struct {
	*h1OrderConn
	info tlsConnInfo
}

func (c *h1OrderTLSConn) ConnectionState() tls.ConnectionState { return c.info.ConnectionState() }
func (c *h1OrderTLSConn) NegotiatedProtocol() string           { return c.info.NegotiatedProtocol() }

// newH1OrderConn wraps conn so request headers are written in order. A nil conn
// or empty order returns conn untouched.
func newH1OrderConn(conn net.Conn, order []string) net.Conn {
	if conn == nil || len(order) == 0 {
		return conn
	}
	base := &h1OrderConn{Conn: conn, order: order}
	if info, ok := conn.(tlsConnInfo); ok {
		return &h1OrderTLSConn{h1OrderConn: base, info: info}
	}
	return base
}

func (c *h1OrderConn) Write(p []byte) (int, error) {
	consumed := 0

	for len(p) > 0 {
		switch c.state {
		case stateHead:
			n, err := c.writeHead(p)
			consumed += n
			if err != nil {
				return consumed, err
			}
			p = p[n:]

		case stateBody:
			n := len(p)
			if int64(n) > c.bodyLeft {
				n = int(c.bodyLeft)
			}
			written, err := c.Conn.Write(p[:n])
			consumed += written
			c.bodyLeft -= int64(written)
			if err != nil {
				return consumed, err
			}
			p = p[n:]
			if c.bodyLeft == 0 {
				c.state = stateHead
			}

		case stateChunked:
			n, done, err := c.chunk.consume(p)
			if n > 0 {
				written, werr := c.Conn.Write(p[:n])
				consumed += written
				if werr != nil {
					return consumed, werr
				}
			}
			if err != nil {
				return consumed, err
			}
			p = p[n:]
			if done {
				c.state = stateHead
			}
		}
	}

	return consumed, nil
}

// writeHead buffers p until the header block is complete, then emits the
// reordered head and moves to the matching body state. It returns how many
// bytes of p it took.
func (c *h1OrderConn) writeHead(p []byte) (int, error) {
	// Only search the tail that could contain a terminator spanning the join.
	searchFrom := len(c.buf) - (len(headEnd) - 1)
	if searchFrom < 0 {
		searchFrom = 0
	}
	c.buf = append(c.buf, p...)

	idx := bytes.Index(c.buf[searchFrom:], headEnd)
	if idx < 0 {
		if len(c.buf) > maxRequestHead {
			return len(p), fmt.Errorf("http/1.1 request head exceeds %d bytes", maxRequestHead)
		}
		return len(p), nil
	}
	end := searchFrom + idx + len(headEnd)

	head := c.buf[:end]
	rest := c.buf[end:]
	taken := len(p) - len(rest)

	ordered := reorderRequestHead(head, c.order)
	c.buf = nil
	if _, err := c.Conn.Write(ordered); err != nil {
		return taken, err
	}

	c.setBodyState(head)
	return taken, nil
}

// setBodyState decides how the body following head is framed.
func (c *h1OrderConn) setBodyState(head []byte) {
	length, chunked := bodyFraming(head)
	switch {
	case chunked:
		c.state = stateChunked
		c.chunk = chunkState{}
	case length > 0:
		c.state = stateBody
		c.bodyLeft = length
	default:
		c.state = stateHead
	}
}

// bodyFraming reads Content-Length and Transfer-Encoding out of a request head.
func bodyFraming(head []byte) (length int64, chunked bool) {
	for _, line := range splitHeaderLines(head) {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := http.CanonicalHeaderKey(string(bytes.TrimSpace(line[:colon])))
		value := string(bytes.TrimSpace(line[colon+1:]))
		switch key {
		case "Content-Length":
			if n, err := strconv.ParseInt(value, 10, 64); err == nil && n > 0 {
				length = n
			}
		case "Transfer-Encoding":
			if strings.Contains(strings.ToLower(value), "chunked") {
				chunked = true
			}
		}
	}
	return length, chunked
}

// splitHeaderLines returns the header lines of a request head, excluding the
// request line and the terminating blank line.
func splitHeaderLines(head []byte) [][]byte {
	body := bytes.TrimSuffix(head, headEnd)
	lines := bytes.Split(body, []byte("\r\n"))
	if len(lines) <= 1 {
		return nil
	}
	return lines[1:]
}

// reorderRequestHead permutes the header lines of head into the browser's
// order. The request line stays first and Host stays immediately after it,
// which is where every browser puts it on HTTP/1.1. Headers not named in order
// keep their relative positions at the end.
//
// The head is returned unchanged if it uses obsolete line folding, since
// reordering folded continuations would change their meaning. Go never emits
// them, so this is belt and braces.
func reorderRequestHead(head []byte, order []string) []byte {
	body := bytes.TrimSuffix(head, headEnd)
	lines := bytes.Split(body, []byte("\r\n"))
	if len(lines) <= 2 {
		return head
	}

	requestLine := lines[0]
	fields := lines[1:]

	type field struct {
		key  string
		line []byte
	}
	parsed := make([]field, 0, len(fields))
	for _, line := range fields {
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			return head // obs-fold; leave the block alone
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			return head // not a header line we understand
		}
		parsed = append(parsed, field{
			key:  http.CanonicalHeaderKey(string(bytes.TrimSpace(line[:colon]))),
			line: line,
		})
	}

	out := make([]byte, 0, len(head))
	out = append(out, requestLine...)
	out = append(out, '\r', '\n')

	used := make([]bool, len(parsed))
	emit := func(i int) {
		out = append(out, parsed[i].line...)
		out = append(out, '\r', '\n')
		used[i] = true
	}

	for i := range parsed {
		if parsed[i].key == "Host" {
			emit(i)
		}
	}
	for _, key := range order {
		for i := range parsed {
			if !used[i] && parsed[i].key == key {
				emit(i)
			}
		}
	}
	for i := range parsed {
		if !used[i] {
			emit(i)
		}
	}

	out = append(out, '\r', '\n')
	return out
}

// chunkState tracks position within a chunked request body so the wrapper knows
// where the body ends and the next request head begins. Go's client only uses
// chunked framing when the body length is unknown, which this package's []byte
// bodies never are, but DoHTTPRequest and FastDo accept arbitrary bodies.
type chunkState struct {
	phase   chunkPhase
	line    []byte // partial size or trailer line
	dataLen int64  // bytes left in the current chunk
}

type chunkPhase int

const (
	chunkSizeLine chunkPhase = iota
	chunkData
	chunkDataCRLF
	chunkTrailer
)

// consume reports how many bytes of p belong to the chunked body and whether
// the terminal chunk has been seen. Bytes are never modified, only counted.
func (s *chunkState) consume(p []byte) (n int, done bool, err error) {
	for n < len(p) {
		switch s.phase {
		case chunkSizeLine, chunkTrailer:
			i := bytes.IndexByte(p[n:], '\n')
			if i < 0 {
				s.line = append(s.line, p[n:]...)
				if len(s.line) > maxRequestHead {
					return len(p), false, fmt.Errorf("chunked framing line too long")
				}
				return len(p), false, nil
			}
			s.line = append(s.line, p[n:n+i+1]...)
			n += i + 1
			line := bytes.TrimRight(s.line, "\r\n")
			s.line = s.line[:0]

			if s.phase == chunkTrailer {
				// A blank line ends the trailer section and the body.
				if len(line) == 0 {
					s.phase = chunkSizeLine
					return n, true, nil
				}
				continue
			}

			// Chunk size, optionally followed by extensions after a ';'.
			if i := bytes.IndexByte(line, ';'); i >= 0 {
				line = line[:i]
			}
			size, perr := strconv.ParseInt(string(bytes.TrimSpace(line)), 16, 64)
			if perr != nil || size < 0 {
				return n, false, fmt.Errorf("malformed chunk size %q", line)
			}
			if size == 0 {
				s.phase = chunkTrailer
				continue
			}
			s.dataLen = size
			s.phase = chunkData

		case chunkData:
			avail := int64(len(p) - n)
			if avail > s.dataLen {
				avail = s.dataLen
			}
			n += int(avail)
			s.dataLen -= avail
			if s.dataLen == 0 {
				s.phase = chunkDataCRLF
				s.dataLen = 2
			}

		case chunkDataCRLF:
			avail := int64(len(p) - n)
			if avail > s.dataLen {
				avail = s.dataLen
			}
			n += int(avail)
			s.dataLen -= avail
			if s.dataLen == 0 {
				s.phase = chunkSizeLine
			}
		}
	}
	return n, false, nil
}
