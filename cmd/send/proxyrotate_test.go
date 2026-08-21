package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// How many exits a run actually leaves from.
//
// The rotator picks a proxy per dial, which is the only granularity there is —
// an address cannot change under a connection that is already open. What that
// meant in practice, though, was decided elsewhere: every session was handed a
// Pinned view, which returns its one primary for as long as that proxy is
// alive. So a hundred-entry file behind -s 2 was two addresses and ninety-eight
// idle lines, and the run reported "100 proxies loaded" either way.
//
// -proxy-rotate hands the session the bare rotator instead. These two tests are
// the same setup with the flag off and on, and the difference between them is
// the whole point of it.

// exitTracker runs n CONNECT proxies in front of one TLS origin and reports
// which proxy carried each request.
//
// The pairing is recovered from the ports, the way TestSolvedSessionsDialTheirOwnExit
// does it: the tunnel is opaque once it is up, but the proxy knows the local
// address it dialled the origin from and the origin sees that address as its
// client.
type exitTracker struct {
	mu       sync.Mutex
	exitPort map[string]string // origin-side port -> proxy name
	carried  map[string]int    // proxy name -> requests it carried

	url  string
	list []string
	stop func()
}

func newExitTracker(t *testing.T, names ...string) *exitTracker {
	t.Helper()
	tr := &exitTracker{exitPort: map[string]string{}, carried: map[string]int{}}

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, port, _ := net.SplitHostPort(r.RemoteAddr)
		tr.mu.Lock()
		tr.carried[tr.exitPort[port]]++
		tr.mu.Unlock()
		w.Write([]byte("ok"))
	}))
	tr.url = origin.URL
	originAddr := strings.TrimPrefix(origin.URL, "https://")

	stops := []func(){origin.Close}
	for _, name := range names {
		addr, stop := connectProxy(t, originAddr, func(localPort string) {
			tr.mu.Lock()
			tr.exitPort[localPort] = name
			tr.mu.Unlock()
		})
		stops = append(stops, stop)
		tr.list = append(tr.list, "http://"+addr)
	}
	tr.stop = func() {
		for _, s := range stops {
			s()
		}
	}
	return tr
}

// exitsUsed is how many distinct proxies carried at least one request.
func (tr *exitTracker) exitsUsed() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	n := 0
	for name, count := range tr.carried {
		if name != "" && count > 0 {
			n++
		}
	}
	return n
}

func runThrough(t *testing.T, o *options, target string, requests int) {
	t.Helper()
	pool, err := newSessionPool(o, gofire.Chrome151, target)
	if err != nil {
		t.Fatalf("newSessionPool: %v", err)
	}
	defer pool.Close()

	for i := 0; i < requests; i++ {
		s := pool.sessions[i%len(pool.sessions)]
		resp, err := s.client.Get(target)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		// Read it out: a body left unread keeps the connection busy, and this
		// test is counting connections.
		if _, err := resp.Bytes(); err != nil {
			t.Fatalf("request %d body: %v", i, err)
		}
		resp.Close()
	}
}

// The default: one session keeps one exit however many requests it makes.
//
// Pinned by design — a session is an identity, and an identity whose address
// changes under it is not one. Pinned here so the flag below has something to
// be measured against, and so the cost of the default is written down rather
// than discovered.
func TestPinnedSessionKeepsOneExit(t *testing.T) {
	tr := newExitTracker(t, "a", "b", "c")
	defer tr.stop()

	runThrough(t, &options{
		sessions:    1,
		concurrency: 1,
		insecure:    true, // httptest's certificate is self-signed
		maxBody:     -1,
		noKeepAlive: true, // a dial per request, so rotation has every chance to happen
		proxyFile:   proxyFile(t, tr.list...),
	}, tr.url, 6)

	if used := tr.exitsUsed(); used != 1 {
		t.Errorf("a pinned session used %d exits over 6 requests, want 1 — pinning is what "+
			"keeps a session's cookies and its address together", used)
	}
}

// -proxy-rotate: the same single session reaches the whole list.
func TestProxyRotateReachesEveryExit(t *testing.T) {
	tr := newExitTracker(t, "a", "b", "c")
	defer tr.stop()

	runThrough(t, &options{
		sessions:    1,
		concurrency: 1,
		insecure:    true,
		maxBody:     -1,
		noKeepAlive: true,
		proxyRotate: true,
		proxyFile:   proxyFile(t, tr.list...),
	}, tr.url, 6)

	if used := tr.exitsUsed(); used != len(tr.list) {
		t.Errorf("-proxy-rotate used %d of %d exits over 6 requests, want all of them",
			used, len(tr.list))
	}
}

// The flag has to be refused where it would quietly do nothing or quietly break
// something, rather than accepted and ignored.
func TestProxyRotateValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			// No list means no rotator at all: the flag would be accepted and
			// then have nothing to act on.
			"without a list",
			[]string{"-proxy-rotate", "https://site.test"},
			"needs -proxy-file",
		},
		{
			// A clearance is bound to the address that earned it, so rotating
			// replays each one from an exit it was never issued to.
			"with -solve",
			[]string{"-solve", "-proxy-rotate", "-proxy-file", "p.txt", "https://site.test"},
			"cannot be combined with -solve",
		},
		{
			// The list wins at dial time, so -proxy beside it was accepted and
			// dialled by nothing.
			"both proxy sources",
			[]string{"-proxy", "http://a.test:1", "-proxy-file", "p.txt", "https://site.test"},
			"not both",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseFlags(tc.args)
			if err == nil {
				t.Fatalf("args %v were accepted", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// The run says how many exits it will use, not how many lines it read.
//
// "100 proxies loaded, 2 sessions pinned across them" reads as though the list
// is in use. It is not, and that gap is the single most surprising thing about
// this tool's proxying — so it is now stated, with what to do about it.
func TestDescribeExitsNamesTheRealNumber(t *testing.T) {
	var sb strings.Builder
	describeExits(&sb, &options{sessions: 2, concurrency: 50}, 100)
	got := sb.String()

	for _, want := range []string{"leaves from 2 of them", "98 entries will never be dialled", "-proxy-rotate"} {
		if !strings.Contains(got, want) {
			t.Errorf("pinned summary %q does not mention %q", got, want)
		}
	}

	sb.Reset()
	describeExits(&sb, &options{sessions: 2, concurrency: 50, proxyRotate: true}, 100)
	got = sb.String()
	if !strings.Contains(got, "every session rotating over all of them") {
		t.Errorf("rotate summary %q does not say the list is in use", got)
	}
	// Rotation turns on connection open, so a run that holds one connection
	// rotates once. Said while there is still time to add the flag for it.
	if !strings.Contains(got, "-no-keepalive") {
		t.Errorf("rotate summary %q does not mention what keeps the rotation turning", got)
	}

	sb.Reset()
	describeExits(&sb, &options{sessions: 2, concurrency: 50, proxyRotate: true, noKeepAlive: true}, 100)
	if strings.Contains(sb.String(), "note:") {
		t.Errorf("the note fired for a run that already opens a connection per request: %q", sb.String())
	}
}
