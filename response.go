package gofire

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Response wraps http.Response with convenience methods and zero-alloc helpers.
type Response struct {
	*http.Response

	bodyRead    bool
	bodyData    []byte
	bodyErr     error
	maxBodySize int64 // 0 = unlimited
}

// StatusCode returns the HTTP status code.
func (r *Response) StatusCode() int {
	return r.Response.StatusCode
}

// Bytes reads and returns the full response body.
// Handles gzip, br, deflate decompression automatically.
// The body is cached after the first call.
func (r *Response) Bytes() ([]byte, error) {
	if r.bodyRead {
		return r.bodyData, r.bodyErr
	}
	r.bodyRead = true

	if r.Response.Body == nil {
		return nil, nil
	}

	reader, closers, err := decodeBody(r.Response.Body, r.Response.Header)
	if err != nil {
		r.drainAndClose()
		r.bodyErr = err
		return nil, err
	}
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i].Close() //nolint:errcheck
		}
	}()

	limited := reader
	if r.maxBodySize > 0 {
		limited = io.LimitReader(reader, r.maxBodySize+1)
	}

	data, err := io.ReadAll(limited)
	if err != nil {
		r.drainAndClose()
		r.bodyErr = err
		return nil, err
	}
	if r.maxBodySize > 0 && int64(len(data)) > r.maxBodySize {
		// Drain rather than cutting the body off. Closing an unfinished body
		// makes HTTP/2 emit RST_STREAM, which Cloudflare and Akamai score as
		// abusive — the exact signal Close and the pipeline's drain pool exist
		// to avoid. See Close for why the drain is unbounded.
		r.drainAndClose()
		r.bodyErr = fmt.Errorf("response body exceeds maximum size of %d bytes", r.maxBodySize)
		r.bodyData = nil
		return nil, r.bodyErr
	}
	r.Response.Body.Close() //nolint:errcheck
	r.bodyData = data
	return data, nil
}

// drainAndClose consumes whatever is left of the underlying body so the stream
// ends with END_STREAM, then closes it.
func (r *Response) drainAndClose() {
	io.Copy(io.Discard, r.Response.Body) //nolint:errcheck
	r.Response.Body.Close()              //nolint:errcheck
}

// contentCodings returns the Content-Encoding tokens in the order the server
// applied them. Values are lowercased and trimmed because the header is a
// case-insensitive token list, not a fixed string: "GZIP" and "gzip " are the
// same coding, and matching them exactly used to return compressed bytes with
// no error at all.
func contentCodings(header http.Header) []string {
	var out []string
	for _, v := range header.Values("Content-Encoding") {
		for _, part := range strings.Split(v, ",") {
			coding := strings.ToLower(strings.TrimSpace(part))
			// "identity" means no transformation, and empty elements are legal
			// in a comma list; neither carries a coding to undo.
			if coding == "" || coding == "identity" {
				continue
			}
			out = append(out, coding)
		}
	}
	return out
}

// decodeBody wraps body in the decoder chain named by Content-Encoding.
// RFC 9110 §8.4 lists codings in the order they were applied, so a body sent as
// "gzip, br" is brotli on the outside and has to be undone last-first.
// maxContentCodings bounds how long a decoder chain a response may ask for.
//
// Every entry costs a decoder before a single byte of body is read, and the
// cost is not uniform: gzip.NewReader reads its header immediately and fails on
// anything that is not gzip, so a chain of those collapses on the second entry.
// zstd.NewReader validates nothing up front — it allocates and spawns decode
// goroutines and returns successfully. Measured here: ten nested zstd readers
// cost fourteen goroutines, and fifty hung the process outright. The attacker's
// side of that is about three hundred bytes of response header.
//
// Which is a bargain worth refusing, because the server is the untrusted party
// in this client: it is pointed at hosts that would rather it stopped working.
// Real responses carry one coding. RFC 9110 §8.4 allows a list and Chrome will
// undo a short one, so four leaves room for anything legitimate and none for
// this.
const maxContentCodings = 4

func decodeBody(body io.Reader, header http.Header) (io.Reader, []io.Closer, error) {
	codings := contentCodings(header)
	if len(codings) == 0 {
		return body, nil, nil
	}
	if len(codings) > maxContentCodings {
		return nil, nil, fmt.Errorf("response declares %d content codings, at most %d are decoded",
			len(codings), maxContentCodings)
	}

	var closers []io.Closer
	reader := body
	for i := len(codings) - 1; i >= 0; i-- {
		next, closer, err := wrapDecoder(reader, codings[i])
		if err != nil {
			for j := len(closers) - 1; j >= 0; j-- {
				closers[j].Close() //nolint:errcheck
			}
			return nil, nil, err
		}
		if closer != nil {
			closers = append(closers, closer)
		}
		reader = next
	}
	return reader, closers, nil
}

// wrapDecoder returns a reader that undoes a single content coding.
func wrapDecoder(r io.Reader, coding string) (io.Reader, io.Closer, error) {
	switch coding {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("gzip: %w", err)
		}
		return gr, gr, nil

	case "br":
		return brotli.NewReader(r), nil, nil

	case "deflate":
		return newDeflateReader(r)

	case "zstd":
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("zstd: %w", err)
		}
		return zr, zstdCloser{zr}, nil

	default:
		// Returning the undecoded bytes here would hand the caller compressed
		// data with a nil error, which is worse than failing: nothing
		// downstream can tell the difference.
		return nil, nil, fmt.Errorf("unsupported Content-Encoding %q", coding)
	}
}

// newDeflateReader decodes the "deflate" coding. RFC 9110 §8.4.1.2 defines it
// as the zlib format (RFC 1950), but a long tail of servers emit raw DEFLATE
// (RFC 1951) instead. Browsers accept both, so sniff the two-byte zlib header
// and fall back to raw rather than failing with "corrupt input before offset 5".
func newDeflateReader(r io.Reader) (io.Reader, io.Closer, error) {
	var hdr [2]byte
	n, err := io.ReadFull(r, hdr[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, nil, fmt.Errorf("deflate: %w", err)
	}
	head := io.MultiReader(bytes.NewReader(hdr[:n]), r)

	// zlib header: CM (low nibble of CMF) is 8 for deflate, and the CMF/FLG
	// pair read big-endian is a multiple of 31.
	if n == 2 && hdr[0]&0x0F == 0x08 && (uint16(hdr[0])<<8|uint16(hdr[1]))%31 == 0 {
		zr, err := zlib.NewReader(head)
		if err != nil {
			return nil, nil, fmt.Errorf("deflate (zlib): %w", err)
		}
		return zr, zr, nil
	}

	fr := flate.NewReader(head)
	return fr, fr, nil
}

// zstdCloser adapts *zstd.Decoder, whose Close returns nothing, to io.Closer.
type zstdCloser struct{ d *zstd.Decoder }

func (z zstdCloser) Close() error { z.d.Close(); return nil }

// Text reads the response body as a string.
func (r *Response) Text() (string, error) {
	data, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// JSON decodes the response body into the given value.
func (r *Response) JSON(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Close releases the response body.
// Fully drains the body to avoid RST_STREAM on HTTP/2 (which WAFs detect as anomalous).
// Real browsers always consume the full response, so we must too.
func (r *Response) Close() {
	if r.Response == nil || r.Response.Body == nil || r.bodyRead {
		return
	}
	// Unbounded drain so the HTTP/2 stream closes with END_STREAM (not
	// RST_STREAM/CANCEL). Cloudflare/Akamai score cancelled streams as
	// abusive — exactly what fingerprint emulation is trying to avoid.
	// Callers that don't want to pay this cost should hand the response to
	// the Pipeline's async drain pool instead of calling Close synchronously.
	io.Copy(io.Discard, r.Response.Body) //nolint:errcheck
	r.Response.Body.Close()
}

// Headers returns the response headers.
func (r *Response) Headers() http.Header {
	return r.Response.Header
}

// GetHeader returns a specific response header value.
func (r *Response) GetHeader(key string) string {
	return r.Response.Header.Get(key)
}

// Cookies returns the response cookies.
func (r *Response) GetCookies() []*http.Cookie {
	return r.Response.Cookies()
}
