package cdp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// authProxy is an HTTP proxy that demands credentials once and then forwards.
//
// It exists to drive Tab.AuthenticateProxy against something that actually
// challenges, because the failure it guards against is invisible from anywhere
// else: a 407 arrives, the handler answers it, and if that answer cannot be sent
// the request simply hangs until its context expires. From outside that looks
// like a slow proxy.
type authProxy struct {
	listener net.Listener
	user     string
	pass     string

	mu        sync.Mutex
	challenge int // how many 407s were issued
	forwarded int // how many requests were let through
}

func newAuthProxy(t *testing.T, user, pass string) *authProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &authProxy{listener: ln, user: user, pass: pass}

	srv := &http.Server{Handler: http.HandlerFunc(p.serve)}
	go srv.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return p
}

func (p *authProxy) URL() string { return "http://" + p.listener.Addr().String() }

func (p *authProxy) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.challenge, p.forwarded
}

func (p *authProxy) serve(w http.ResponseWriter, r *http.Request) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(p.user+":"+p.pass))
	if r.Header.Get("Proxy-Authorization") != want {
		p.mu.Lock()
		p.challenge++
		p.mu.Unlock()
		w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
		http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
		return
	}

	p.mu.Lock()
	p.forwarded++
	p.mu.Unlock()

	// Absolute-form request, which is what a browser sends to a proxy. Answering
	// it directly keeps the test off the network.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><head><title>proxied</title></head><body>%s</body></html>", r.Host)
}

// A 407 has to be answered, and answering it must not deadlock.
//
// The handler that answers runs on the connection's event path, and it issues a
// CDP command of its own (Fetch.continueWithAuth). Running it on the read loop
// would block waiting for a response only the read loop can deliver — so the
// authentication would never be sent, every request through an authenticated
// proxy would stall until its context expired, and the solve would report a
// browser that could not reach the target. This is the test that says otherwise.
func TestAuthenticateProxyAnswersTheChallenge(t *testing.T) {
	b := testBrowser(t)
	proxy := newAuthProxy(t, "user", "hunter2")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c, err := b.NewContext(ctx, proxy.URL())
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	defer c.Close(ctx)

	tab, err := c.NewTab(ctx)
	if err != nil {
		t.Fatalf("tab: %v", err)
	}
	defer tab.Close(ctx)

	if err := tab.AuthenticateProxy(ctx, "user", "hunter2"); err != nil {
		t.Fatalf("AuthenticateProxy: %v", err)
	}

	// Comfortably longer than a round trip, comfortably shorter than the
	// handler's own 10s fallback — so a deadlock shows up as this deadline
	// rather than as a slow pass.
	navCtx, navCancel := context.WithTimeout(ctx, 20*time.Second)
	defer navCancel()

	start := time.Now()
	if err := tab.Navigate(navCtx, "http://proxied.test/"); err != nil {
		t.Fatalf("navigate through the proxy: %v", err)
	}
	elapsed := time.Since(start)

	var body string
	if err := tab.Evaluate(ctx, "document.body ? document.body.innerText : ''", &body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(body, "proxied.test") {
		t.Fatalf("body = %q, want the proxy's answer", body)
	}

	challenged, forwarded := proxy.counts()
	if challenged == 0 {
		t.Error("the proxy never challenged; this did not test authentication")
	}
	if forwarded == 0 {
		t.Error("the proxy never let a request through: the credentials were not sent")
	}
	// A deadlocked handler would only recover when its own context expired, so a
	// navigation that took that long has passed for the wrong reason.
	if elapsed > 10*time.Second {
		t.Errorf("the navigation took %s — the auth handler blocked the read loop", elapsed)
	}
}

// A site's own 401 is not the proxy's, and answering it would hand the proxy's
// credentials to the target.
func TestAuthenticateProxyDoesNotAnswerSiteAuth(t *testing.T) {
	b := testBrowser(t)

	// Guarded: the handler runs on the server's goroutine, the assertion on the
	// test's.
	var (
		mu  sync.Mutex
		got string
	)
	site := newOriginWith(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("WWW-Authenticate", `Basic realm="site"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tab, err := b.DefaultContext().NewTab(ctx)
	if err != nil {
		t.Fatalf("tab: %v", err)
	}
	defer tab.Close(ctx)

	if err := tab.AuthenticateProxy(ctx, "user", "hunter2"); err != nil {
		t.Fatalf("AuthenticateProxy: %v", err)
	}
	navCtx, navCancel := context.WithTimeout(ctx, 20*time.Second)
	defer navCancel()
	_ = tab.Navigate(navCtx, site.URL)

	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(got, "hunter2") {
		t.Errorf("the proxy's password was sent to the site: %q", got)
	}
}

// newOriginWith is a bare server for tests that need their own handler.
func newOriginWith(t *testing.T, h http.HandlerFunc) *serverAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return &serverAddr{URL: "http://" + ln.Addr().String() + "/"}
}

type serverAddr struct{ URL string }
