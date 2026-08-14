package main

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/html"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// A browser that fetches a document and nothing else is a browser that never
// renders anything.
//
// Every layer below this one is exact — the ClientHello, the HTTP/2 frames, the
// header set — and then the traffic pattern gives it away: a document request
// with no stylesheet, no script, no image following it, every request arriving
// as a fresh navigation with Sec-Fetch-Site: none and no Referer. Real page
// loads do not look like that, and nothing about the TLS layer can fix it.
//
// -assets parses the document and fetches what it references, with the headers
// Chrome sends for each destination. Those values are measured, not guessed:
// against Chromium over HTTP/2, serving a page that references one of each.
//
//	dest    accept                                     mode      priority
//	style   text/css,*/*;q=0.1                         no-cors   u=0
//	script  */*                                        no-cors   u=1
//	image   image/avif,image/webp,image/apng,           no-cors   u=2, i
//	        image/svg+xml,image/*,*/*;q=0.8
//	font    */*                                        cors      u=1
//
// All four carry a Referer and none carries Upgrade-Insecure-Requests or
// Sec-Fetch-User, which are navigation-only. The CORS one (font) also carries an
// Origin.
//
// What is deliberately NOT set here is the header order. The order observed on
// that rig disagreed with the order fpcheck confirms against a real browser at a
// real endpoint, which makes the rig the suspect rather than the client — so the
// package's existing fetch-mode ordering stands, and the subresource order is an
// open question rather than a value invented to close it.

// requestDoer is the slice of *gofire.Client this needs, so the parallel fetch
// can be tested without a network.
type requestDoer interface {
	DoWithContext(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (*gofire.Response, error)
}

// assetDest is a Sec-Fetch-Dest value, which is what decides the rest.
type assetDest string

const (
	destStyle  assetDest = "style"
	destScript assetDest = "script"
	destImage  assetDest = "image"
	destFont   assetDest = "font"
)

type asset struct {
	url  string
	dest assetDest
}

// assetProfile is the header set Chrome sends for one destination.
type assetProfile struct {
	accept   string
	mode     string
	priority string
	cors     bool // adds Origin, and makes Sec-Fetch-Mode cors
}

var assetProfiles = map[assetDest]assetProfile{
	destStyle:  {accept: "text/css,*/*;q=0.1", mode: "no-cors", priority: "u=0"},
	destScript: {accept: "*/*", mode: "no-cors", priority: "u=1"},
	destImage: {
		accept:   "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
		mode:     "no-cors",
		priority: "u=2, i",
	},
	destFont: {accept: "*/*", mode: "cors", priority: "u=1", cors: true},
}

// parseAssets pulls the subresources a browser would fetch out of a document.
//
// It reads the same elements the preload scanner does — stylesheets, scripts,
// images, preloaded fonts — and resolves them against the document URL. Anything
// it cannot resolve, or that is not http(s), is skipped: data: and blob: URLs
// never reach the network, so fetching them would invent traffic no browser
// produces.
func parseAssets(body []byte, base *url.URL, limit int) []asset {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}

	var out []asset
	seen := make(map[string]bool)
	add := func(ref string, dest assetDest) {
		if limit > 0 && len(out) >= limit {
			return
		}
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return
		}
		u, err := base.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		u.Fragment = ""
		s := u.String()
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, asset{url: s, dest: dest})
	}

	attr := func(n *html.Node, name string) string {
		for _, a := range n.Attr {
			if strings.EqualFold(a.Key, name) {
				return a.Val
			}
		}
		return ""
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "link":
				rel := strings.ToLower(attr(n, "rel"))
				switch {
				case strings.Contains(rel, "stylesheet"):
					add(attr(n, "href"), destStyle)
				case strings.Contains(rel, "icon"):
					add(attr(n, "href"), destImage)
				case strings.Contains(rel, "preload"):
					switch strings.ToLower(attr(n, "as")) {
					case "font":
						add(attr(n, "href"), destFont)
					case "style":
						add(attr(n, "href"), destStyle)
					case "script":
						add(attr(n, "href"), destScript)
					case "image":
						add(attr(n, "href"), destImage)
					}
				}
			case "script":
				add(attr(n, "src"), destScript)
			case "img":
				add(attr(n, "src"), destImage)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

// assetHeaders builds the request headers for one subresource.
//
// Sec-Fetch-Site is the document's relationship to the asset, not a constant:
// same-origin for the document's own host, same-site across a subdomain of the
// same registrable domain, cross-site otherwise. Getting it wrong is the kind of
// detail that says "not a browser" on its own.
func assetHeaders(a asset, doc *url.URL) map[string]string {
	p, ok := assetProfiles[a.dest]
	if !ok {
		p = assetProfiles[destImage]
	}

	h := map[string]string{
		"Accept":         p.accept,
		"Sec-Fetch-Site": assetFetchSite(doc, a.url),
		"Sec-Fetch-Mode": p.mode,
		"Sec-Fetch-Dest": string(a.dest),
		"Referer":        doc.String(),
		"Priority":       p.priority,
	}
	if p.cors {
		h["Origin"] = doc.Scheme + "://" + doc.Host
	}
	return h
}

// assetFetchSite classifies the document-to-asset origin relationship.
func assetFetchSite(doc *url.URL, assetURL string) string {
	u, err := url.Parse(assetURL)
	if err != nil {
		return "cross-site"
	}
	switch {
	case sameOrigin(doc, u):
		return "same-origin"
	// "Schemefully same-site": the scheme is part of the site, so an http
	// subresource on an https page is cross-site even on the same host.
	case u.Scheme == doc.Scheme && sameSite(u.Hostname(), doc.Hostname()):
		return "same-site"
	default:
		return "cross-site"
	}
}

// sameOrigin compares scheme, host and port with the default port normalised.
// https://site.test and https://site.test:443 are one origin, and comparing the
// Host strings would put Sec-Fetch-Site: cross-site on a page's own stylesheet.
func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		originPort(a) == originPort(b)
}

func originPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// sameSite reports whether two hosts share a registrable domain, approximated by
// the last two labels. It is an approximation on purpose: the exact answer needs
// the public suffix list, and the only cost of being wrong here is sending
// "cross-site" where a browser would have said "same-site".
func sameSite(a, b string) bool {
	if a == b {
		return true
	}
	la, lb := strings.Split(a, "."), strings.Split(b, ".")
	if len(la) < 2 || len(lb) < 2 {
		return false
	}
	return strings.Join(la[len(la)-2:], ".") == strings.Join(lb[len(lb)-2:], ".")
}

// fetchAssets requests the subresources of a document, in parallel the way a
// browser multiplexes them over one HTTP/2 connection. Failures are counted, not
// returned: a missing image is a normal thing on a real page and must not fail
// the run that asked for the document.
func fetchAssets(ctx context.Context, client requestDoer, doc *url.URL, assets []asset, parallel int) (ok, failed int) {
	if parallel < 1 {
		parallel = 6 // what Chrome opens per host on HTTP/1.1, and a sane cap on h2
	}

	// Counted atomically rather than under a mutex, because an interrupt has to
	// be able to stop starting new fetches without stopping the count.
	//
	// The cancellation path used to `return ok, failed` from inside the loop,
	// which read both counters with no lock while the fetches already in flight
	// were still incrementing them under one — a data race on every Ctrl-C
	// during -assets, confirmed with `go test -race`. It also returned before
	// wg.Wait(), so the goroutines outlived the function that owned them and
	// the number printed was still moving as it was printed.
	//
	// Breaking out and waiting is the fix: the fetches already started are
	// cancelled by their own context, which is what actually stops them, and
	// the totals are read once nothing can write them.
	var (
		okN, failedN atomic.Int64
		wg           sync.WaitGroup
		sem          = make(chan struct{}, parallel)
	)

start:
	for _, a := range assets {
		// Checked before the select rather than only inside it. A select with
		// two ready cases picks at random, so an already-cancelled run would
		// start a fetch half the time.
		if ctx.Err() != nil {
			break
		}
		// The slot is taken before the goroutine is registered, and taking it
		// is itself interruptible: a run cancelled while every slot is busy
		// would otherwise sit here until one came free.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break start
		}

		wg.Add(1)
		go func(a asset) {
			defer wg.Done()
			defer func() { <-sem }()

			resp, err := client.DoWithContext(ctx, "GET", a.url, nil, assetHeaders(a, doc))
			if err != nil {
				failedN.Add(1)
				return
			}
			// Drain and close: an abandoned body makes HTTP/2 emit RST_STREAM,
			// the abusive-client signal this package exists to avoid.
			_, _ = resp.Bytes()
			resp.Close()
			okN.Add(1)
		}(a)
	}
	wg.Wait()
	return int(okN.Load()), int(failedN.Load())
}
