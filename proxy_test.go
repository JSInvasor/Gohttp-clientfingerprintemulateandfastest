package gofire

import (
	"testing"
	"time"
)

func TestParseProxyString(t *testing.T) {
	cases := []struct {
		in      string
		wantURL string
		wantErr bool
	}{
		{"1.2.3.4:8080", "http://1.2.3.4:8080", false},
		{"1.2.3.4:8080:user:pass", "http://user:pass@1.2.3.4:8080", false},
		{"http://1.2.3.4:8080", "http://1.2.3.4:8080", false},
		{"https://1.2.3.4:443", "https://1.2.3.4:443", false},
		{"socks5://1.2.3.4:1080", "socks5://1.2.3.4:1080", false},
		{"socks5://user:pass@1.2.3.4:1080", "socks5://user:pass@1.2.3.4:1080", false},
		{"socks5h://1.2.3.4:1080", "socks5h://1.2.3.4:1080", false},
		{"ftp://1.2.3.4:21", "", true},
		{"justhost", "", true},
		{"://nohost", "", true},
		// Password containing ':' must survive shorthand parsing.
		{"1.2.3.4:8080:user:p:a:s:s", "http://user:p%3Aa%3As%3As@1.2.3.4:8080", false},
	}
	for _, tc := range cases {
		got, err := parseProxyString(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseProxyString(%q) expected error, got %s", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseProxyString(%q) unexpected err: %v", tc.in, err)
			continue
		}
		if got.String() != tc.wantURL {
			t.Errorf("parseProxyString(%q) = %q, want %q", tc.in, got.String(), tc.wantURL)
		}
	}
}

func TestProxyRotatorHealth(t *testing.T) {
	pr, err := NewProxyRotator([]string{
		"1.1.1.1:8080",
		"2.2.2.2:8080",
		"3.3.3.3:8080",
	})
	if err != nil {
		t.Fatalf("NewProxyRotator: %v", err)
	}
	pr.SetCooldown(50 * time.Millisecond)
	pr.SetFailThreshold(2)

	if pr.Count() != 3 {
		t.Fatalf("Count = %d, want 3", pr.Count())
	}
	if pr.LiveCount() != 3 {
		t.Fatalf("LiveCount = %d, want 3", pr.LiveCount())
	}

	// Mark first proxy as failed twice -> dead.
	e := pr.NextEntry()
	first := e.url.Host
	pr.MarkFailure(e)
	pr.MarkFailure(e)

	if pr.LiveCount() != 2 {
		t.Fatalf("LiveCount after death = %d, want 2", pr.LiveCount())
	}

	// Next() must skip the dead proxy for the duration of cooldown.
	for i := 0; i < 10; i++ {
		got := pr.Next()
		if got.Host == first {
			t.Errorf("Next returned dead proxy %q (iter %d)", first, i)
		}
	}

	// After cooldown the proxy comes back.
	time.Sleep(70 * time.Millisecond)
	if pr.LiveCount() != 3 {
		t.Fatalf("LiveCount after cooldown = %d, want 3", pr.LiveCount())
	}
}

func TestProxyRotatorAllDeadFallback(t *testing.T) {
	pr, _ := NewProxyRotator([]string{"1.1.1.1:8080", "2.2.2.2:8080"})
	pr.SetFailThreshold(1)
	pr.SetCooldown(time.Hour)

	for i := 0; i < 4; i++ {
		pr.MarkFailure(pr.NextEntry())
	}
	if pr.LiveCount() != 0 {
		t.Fatalf("expected all dead, LiveCount = %d", pr.LiveCount())
	}
	// Even with all dead, Next must return SOMETHING (not nil) so the caller
	// can still attempt a request rather than hard-failing.
	if pr.Next() == nil {
		t.Fatalf("Next returned nil with all proxies dead")
	}
}

func TestProxyRotatorSuccessClearsFailures(t *testing.T) {
	pr, _ := NewProxyRotator([]string{"1.1.1.1:8080"})
	pr.SetFailThreshold(3)

	e := pr.NextEntry()
	pr.MarkFailure(e)
	pr.MarkFailure(e)
	pr.MarkSuccess(e)
	pr.MarkFailure(e)
	pr.MarkFailure(e)

	if pr.LiveCount() != 1 {
		t.Errorf("proxy died after success reset; LiveCount = %d, want 1", pr.LiveCount())
	}
}
