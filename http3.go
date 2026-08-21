package gofire

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	quicprofile "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quic"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo/http3"
)

// HTTP/3, and how a request comes to be sent over it.
//
// A browser does not choose HTTP/3 for a host it has never met. It connects
// over TCP, and if the response carries an Alt-Svc header offering h3 it
// remembers that and uses QUIC next time. That ordering is itself part of the
// fingerprint: a client whose very first packet to an unknown host is a QUIC
// Initial is doing something Chrome does not do, whatever that Initial looks
// like.
//
// So discovery is the default here, and forcing is an option rather than the
// other way round. What is cached is only what the header said, per host, with
// the lifetime the header gave.
//
// Everything below the decision is in internal/quicgo and internal/qpack: the
// ClientHello, the shape of the first flight, the transport parameters, the
// SETTINGS and their order, the frames after them, QPACK's dynamic table, and
// the request header order. This file only decides when to use them.

// altSvcEntry is one host's advertised HTTP/3 endpoint.
type altSvcEntry struct {
	authority string // usually ":443", meaning the same host on the same port
	expires   time.Time
}

// h3Cache remembers which hosts have offered HTTP/3.
type h3Cache struct {
	mu      sync.RWMutex
	entries map[string]altSvcEntry
}

func newH3Cache() *h3Cache { return &h3Cache{entries: map[string]altSvcEntry{}} }

func (c *h3Cache) get(host string) (altSvcEntry, bool) {
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return altSvcEntry{}, false
	}
	return e, true
}

func (c *h3Cache) put(host string, e altSvcEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[host] = e
}

func (c *h3Cache) clear(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, host)
}

// parseAltSvc reads an Alt-Svc header and returns the h3 endpoint it offers.
//
// The grammar is RFC 7838's, and only the parts that decide anything are read:
// the protocol id, the authority, and ma. Everything else — persist, extra
// parameters, alternatives for other protocols — is skipped rather than
// rejected, because a header this client does not fully understand is not a
// reason to refuse an upgrade the browser would take.
//
// `clear` is honoured: it is how a server withdraws an offer, and ignoring it
// would keep sending QUIC to a host that has asked for TCP.
func parseAltSvc(v string) (authority string, ttl time.Duration, clear, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", 0, false, false
	}
	if strings.EqualFold(v, "clear") {
		return "", 0, true, true
	}

	for _, alt := range splitOutsideQuotes(v, ',') {
		fields := splitOutsideQuotes(alt, ';')
		if len(fields) == 0 {
			continue
		}
		id, rawAuthority, found := strings.Cut(strings.TrimSpace(fields[0]), "=")
		if !found {
			continue
		}
		// h3 is the final protocol; the draft names are still seen on older
		// edges and mean the same thing to a client that speaks v1.
		id = strings.TrimSpace(id)
		if id != "h3" && !strings.HasPrefix(id, "h3-") {
			continue
		}

		authority = strings.Trim(strings.TrimSpace(rawAuthority), `"`)
		ttl = 24 * time.Hour
		for _, f := range fields[1:] {
			k, val, found := strings.Cut(strings.TrimSpace(f), "=")
			if !found || !strings.EqualFold(strings.TrimSpace(k), "ma") {
				continue
			}
			if secs, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`)); err == nil && secs > 0 {
				ttl = time.Duration(secs) * time.Second
			}
		}
		return authority, ttl, false, true
	}
	return "", 0, false, false
}

// splitOutsideQuotes splits on sep, ignoring separators inside double quotes.
//
// Alt-Svc quotes its authority and its parameter values, and an authority may
// contain a comma in principle. Splitting naively works almost always, which is
// the worst kind of parser to write.
func splitOutsideQuotes(s string, sep byte) []string {
	var out []string
	var start int
	var inQuotes bool
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuotes = !inQuotes
		case sep:
			if !inQuotes {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// recordAltSvc reads a response's Alt-Svc header and remembers what it offered.
func (t *Transport) recordAltSvc(resp *http.Response) {
	if resp == nil || t.h3Cache == nil || resp.Request == nil || resp.Request.URL == nil {
		return
	}
	v := resp.Header.Get("Alt-Svc")
	if v == "" {
		return
	}
	host := hostProtoKey(resp.Request.URL.Host, "443")
	authority, ttl, clear, ok := parseAltSvc(v)
	if !ok {
		return
	}
	if clear {
		t.h3Cache.clear(host)
		return
	}
	t.h3Cache.put(host, altSvcEntry{authority: authority, expires: time.Now().Add(ttl)})
}

// h3Target returns the address to dial for a request, and whether HTTP/3 should
// be used at all.
func (t *Transport) h3Target(req *http.Request) (string, bool) {
	if t.h3Transport == nil || req.URL.Scheme != "https" {
		return "", false
	}
	host := hostProtoKey(req.URL.Host, "443")

	if t.forceH3 {
		return host, true
	}
	if t.h3Cache == nil {
		return "", false
	}
	e, ok := t.h3Cache.get(host)
	if !ok {
		return "", false
	}
	return altSvcAddr(host, e.authority), true
}

// h3Request points a request at the address Alt-Svc named, without changing
// what the request says it is for.
//
// An offer may move HTTP/3 to another port or another name, and the transport
// dials whatever is in the URL — so the address has to go there. But :authority
// must stay the origin the caller asked for, or the server routes the request
// somewhere else entirely, so it is pinned in Host first. Computing the address
// and then not using it was the first version of this, and it cost a five
// second timeout per request and a silent fall back to TCP.
func h3Request(req *http.Request, addr string) *http.Request {
	if addr == req.URL.Host {
		return req
	}
	out := req.Clone(req.Context())
	if out.Host == "" {
		out.Host = req.URL.Host
	}
	out.URL = new(url.URL)
	*out.URL = *req.URL
	out.URL.Host = addr
	return out
}

// altSvcAddr resolves an Alt-Svc authority against the host it came from.
//
// The common form is ":443", meaning the same host on that port. A full
// host:port is honoured too, which is how an edge moves QUIC to a different
// name.
func altSvcAddr(host, authority string) string {
	if authority == "" {
		return host
	}
	if strings.HasPrefix(authority, ":") {
		h, _, err := net.SplitHostPort(host)
		if err != nil {
			h = host
		}
		return net.JoinHostPort(h, strings.TrimPrefix(authority, ":"))
	}
	if _, _, err := net.SplitHostPort(authority); err != nil {
		return net.JoinHostPort(authority, "443")
	}
	return authority
}

// newH3Transport builds the HTTP/3 transport for a browser profile.
//
// The field orders come from the profile rather than from this package's own
// tables, because HTTP/3 and HTTP/2 do not use the same one: internal/http2's
// chromeHeaderOrder is the h2 order, and internal/quic/http3.go holds the h3
// one. They are close but not equal, and using either for the other would be a
// difference visible on the first request.
func newH3Transport(browser BrowserProfile, rootCAs *x509.CertPool, skipVerify bool) *http3.Transport {
	if browser != Chrome151 {
		// Only the Chrome profile has a measured HTTP/3 fingerprint. Safari on
		// iOS speaks HTTP/3 too, but nothing in this repository has captured it,
		// and shipping Chrome's QUIC under a Safari user agent would be a
		// contradiction the edge can see — the two disagree from the
		// ClientHello onward.
		return nil
	}
	ref := quicprofile.Chrome151H3
	return &http3.Transport{
		PseudoHeaderOrder: ref.PseudoHeaderOrder,
		HeaderOrder:       ref.FetchHeaderOrder,
		TLSClientConfig: &tls.Config{
			RootCAs:            rootCAs,
			InsecureSkipVerify: skipVerify,
			MinVersion:         tls.VersionTLS13,
		},
		QUICConfig: &quic.Config{
			MaxIncomingStreams: -1,
			KeepAlivePeriod:    30 * time.Second,
		},
	}
}
