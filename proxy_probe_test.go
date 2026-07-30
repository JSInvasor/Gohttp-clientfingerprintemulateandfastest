package gofire

import (
	"testing"
	"time"
)

// TestParseProxyStringForms pins the accepted input formats. The shorthand
// splits on colons, which is exactly where an IPv6 literal collides with it.
func TestParseProxyStringForms(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantUser string
		wantPass string
		wantErr  bool
	}{
		{in: "1.2.3.4:8080", wantHost: "1.2.3.4:8080"},
		{in: "1.2.3.4:8080:bob:secret", wantHost: "1.2.3.4:8080", wantUser: "bob", wantPass: "secret"},
		// A password may legitimately contain a colon; SplitN's limit keeps it whole.
		{in: "1.2.3.4:8080:bob:pa:ss", wantHost: "1.2.3.4:8080", wantUser: "bob", wantPass: "pa:ss"},
		{in: "socks5://1.2.3.4:1080", wantHost: "1.2.3.4:1080"},
		{in: "socks5://bob:secret@1.2.3.4:1080", wantHost: "1.2.3.4:1080", wantUser: "bob", wantPass: "secret"},
		// IPv6 literals are valid proxy addresses and the colon-splitting
		// shorthand mangles them into a host that cannot be dialled.
		{in: "[2001:db8::1]:1080", wantHost: "[2001:db8::1]:1080"},
		{in: "not-a-proxy", wantErr: true},
	}

	for _, tc := range cases {
		u, err := parseProxyString(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: expected an error, got %v", tc.in, u)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if u.Host != tc.wantHost {
			t.Errorf("%q: host = %q, want %q", tc.in, u.Host, tc.wantHost)
		}
		user := ""
		pass := ""
		if u.User != nil {
			user = u.User.Username()
			pass, _ = u.User.Password()
		}
		if user != tc.wantUser || pass != tc.wantPass {
			t.Errorf("%q: credentials = %q/%q, want %q/%q", tc.in, user, pass, tc.wantUser, tc.wantPass)
		}
	}
}

// TestRotatorSkipsAndRecovers checks the health machinery end to end: a proxy
// that trips the failure threshold leaves rotation, and comes back once its
// cooldown expires.
func TestRotatorSkipsAndRecovers(t *testing.T) {
	pr, err := NewProxyRotator([]string{"1.1.1.1:1", "2.2.2.2:2"})
	if err != nil {
		t.Fatalf("rotator: %v", err)
	}
	pr.SetCooldown(150 * time.Millisecond)
	pr.SetFailThreshold(2)

	// Kill the first proxy.
	first := pr.proxies[0]
	pr.MarkFailure(first)
	pr.MarkFailure(first)

	if got := pr.LiveCount(); got != 1 {
		t.Fatalf("LiveCount = %d after killing one of two, want 1", got)
	}
	for i := 0; i < 8; i++ {
		if e := pr.NextEntry(); e == first {
			t.Fatal("rotation handed back a proxy that is in cooldown")
		}
	}

	time.Sleep(200 * time.Millisecond)
	if got := pr.LiveCount(); got != 2 {
		t.Fatalf("LiveCount = %d after the cooldown expired, want 2", got)
	}

	// A success must clear the failure history, not leave it one strike away.
	pr.MarkFailure(first)
	pr.MarkSuccess(first)
	pr.MarkFailure(first)
	if pr.LiveCount() != 2 {
		t.Error("a single failure after a success killed the proxy; the success " +
			"did not reset the consecutive-failure count")
	}
}

// TestPinnedSharesHealthButNotCursor pins the two properties Pinned promises:
// views share proxy health with their parent, and a view falls back to a live
// proxy when its own primary is in cooldown.
func TestPinnedSharesHealthButNotCursor(t *testing.T) {
	pr, err := NewProxyRotator([]string{"1.1.1.1:1", "2.2.2.2:2", "3.3.3.3:3"})
	if err != nil {
		t.Fatalf("rotator: %v", err)
	}
	pr.SetFailThreshold(1)
	pr.SetCooldown(time.Minute)

	v0 := pr.Pinned(0)
	v1 := pr.Pinned(1)

	if got := v0.NextEntry(); got != pr.proxies[0] {
		t.Error("pinned view 0 did not prefer its primary")
	}
	if got := v1.NextEntry(); got != pr.proxies[1] {
		t.Error("pinned view 1 did not prefer its primary")
	}

	// Health is shared: killing proxy 0 through the parent must move view 0 off it.
	pr.MarkFailure(pr.proxies[0])
	if got := v0.NextEntry(); got == pr.proxies[0] {
		t.Error("pinned view kept using a primary the parent marked dead; " +
			"health is not shared")
	}

	// And the view must not have wandered off a healthy primary.
	if got := v1.NextEntry(); got != pr.proxies[1] {
		t.Error("pinned view 1 left a healthy primary")
	}
}

// TestRotatorAllDeadStillReturnsUsable makes sure a fully rotten list degrades
// to probing rather than to a nil dereference: Next() dereferences whatever
// NextEntry hands back.
func TestRotatorAllDeadStillReturnsUsable(t *testing.T) {
	pr, err := NewProxyRotator([]string{"1.1.1.1:1", "2.2.2.2:2"})
	if err != nil {
		t.Fatalf("rotator: %v", err)
	}
	pr.SetFailThreshold(1)
	pr.SetCooldown(time.Minute)

	for _, e := range pr.proxies {
		pr.MarkFailure(e)
	}
	if pr.LiveCount() != 0 {
		t.Fatal("expected every proxy to be in cooldown")
	}
	if u := pr.Next(); u == nil {
		t.Fatal("Next() returned nil with every proxy in cooldown; callers " +
			"dereference this")
	}
}
