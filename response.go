package gofire

import (
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/andybalholm/brotli"
)

// Response wraps http.Response with convenience methods and zero-alloc helpers.
type Response struct {
	*http.Response

	bodyRead bool
	bodyData []byte
	bodyErr  error
}

var bodyBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, 4096)
		return &buf
	},
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
	defer r.Response.Body.Close()

	var reader io.Reader
	switch r.Response.Header.Get("Content-Encoding") {
	case "gzip":
		gr, err := gzip.NewReader(r.Response.Body)
		if err != nil {
			r.bodyErr = err
			return nil, err
		}
		defer gr.Close()
		reader = gr
	case "br":
		reader = brotli.NewReader(r.Response.Body)
	case "deflate":
		reader = flate.NewReader(r.Response.Body)
	default:
		reader = r.Response.Body
	}

	data, err := io.ReadAll(reader)
	r.bodyData = data
	r.bodyErr = err
	return data, err
}

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
func (r *Response) Close() {
	if r.Response != nil && r.Response.Body != nil && !r.bodyRead {
		io.Copy(io.Discard, r.Response.Body)
		r.Response.Body.Close()
	}
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
