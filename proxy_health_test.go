package gofire

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestProxyRotatorSettingsReachPinnedViews pins that the failure policy is
// shared. Pinned used to copy cooldown and failThreshold into each view, so a
// SetCooldown or SetFailThreshold call made after the views existed applied to
// none of them — every per-client view silently kept the defaults.
func TestProxyRotatorSettingsReachPinnedViews(t *testing.T) {
	pr, err := NewProxyRotator([]string{"1.2.3.4:8080", "5.6.7.8:8080"})
	if err != nil {
		t.Fatalf("NewProxyRotator: %v", err)
	}

	view := pr.Pinned(0)
	pr.SetFailThreshold(1)
	pr.SetCooldown(time.Hour)

	// One failure now has to be enough to take the proxy out of rotation.
	entry := view.NextEntry()
	if entry == nil {
		t.Fatal("NextEntry returned nil")
	}
	view.MarkFailure(entry)

	if got := view.LiveCount(); got != 1 {
		t.Fatalf("LiveCount = %d after one failure at threshold 1, want 1", got)
	}
	if next := view.NextEntry(); next == entry {
		t.Fatal("the failed proxy is still being handed out")
	}
}

// TestProxyRotatorConcurrentSettings is a race-detector target: the failure
// policy is read from dial goroutines while a caller may still be setting it.
func TestProxyRotatorConcurrentSettings(t *testing.T) {
	pr, err := NewProxyRotator([]string{"1.2.3.4:8080", "5.6.7.8:8080", "9.9.9.9:8080"})
	if err != nil {
		t.Fatalf("NewProxyRotator: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			pr.SetFailThreshold(1 + i%5)
			pr.SetCooldown(time.Duration(1+i%50) * time.Millisecond)
		}
	}()

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				e := pr.NextEntry()
				if j%2 == 0 {
					pr.MarkFailure(e)
				} else {
					pr.MarkSuccess(e)
				}
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestPinnedOnlyNeverRotates pins the difference between the two views. A
// client holding a cf_clearance issued to one exit must never present it from
// another, so a dead primary is a failed dial rather than a silent detour.
func TestPinnedOnlyNeverRotates(t *testing.T) {
	pr, err := NewProxyRotator([]string{"1.2.3.4:8080", "5.6.7.8:8080"})
	if err != nil {
		t.Fatalf("NewProxyRotator: %v", err)
	}
	pr.SetFailThreshold(1)
	pr.SetCooldown(time.Hour)

	strict := pr.PinnedOnly(0)
	primary := strict.NextEntry()
	if primary != pr.proxies[0] {
		t.Fatal("PinnedOnly(0) did not start on proxies[0]")
	}

	// Bench it. The sticky view is expected to find a backup; the strict one is
	// expected to keep handing back the exit its caller's cookie belongs to.
	strict.MarkFailure(primary)
	if pr.LiveCount() != 1 {
		t.Fatalf("LiveCount = %d after one failure at threshold 1, want 1", pr.LiveCount())
	}
	for i := 0; i < 3; i++ {
		if got := strict.NextEntry(); got != primary {
			t.Fatalf("call %d rotated off the pinned exit", i)
		}
	}
	if got := pr.Pinned(0).NextEntry(); got == primary {
		t.Error("the ordinary Pinned view stopped failing over")
	}

	// Health is still shared, so the failure is visible to -proxy-stats and to
	// every sibling rather than swallowed by the strict view.
	if stats := pr.Stats(); stats[0].Failed != 1 || stats[0].Alive {
		t.Errorf("stats[0] = %+v, want one failure and a benched proxy", stats[0])
	}
}

// TestProxyRotatorNextOnEmpty pins that Next does not dereference a nil entry.
func TestProxyRotatorNextOnEmpty(t *testing.T) {
	var pr ProxyRotator
	pr.primaryIdx = -1
	if got := pr.Next(); got != nil {
		t.Fatalf("Next on an empty rotator = %v, want nil", got)
	}
}

// TestSelectAddressFamily pins that a mixed A/AAAA answer is narrowed to one
// family. Round-robining across both sent a share of every host's requests to
// an address family the machine may have no route for, which showed up as a
// fraction of requests failing with "network unreachable".
func TestSelectAddressFamily(t *testing.T) {
	mixed := []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "93.184.216.35"}

	got := selectAddressFamily(mixed)
	if len(got) == 0 {
		t.Fatal("no addresses selected")
	}

	wantV6 := hasGlobalIPv6()
	for _, ip := range got {
		isV6 := net.ParseIP(ip).To4() == nil
		if isV6 != wantV6 {
			t.Fatalf("selected %v: mixes families (hasGlobalIPv6=%v)", got, wantV6)
		}
	}

	// A single-family answer must survive whichever family it is.
	onlyV4 := []string{"1.1.1.1", "8.8.8.8"}
	if got := selectAddressFamily(onlyV4); len(got) != 2 {
		t.Errorf("IPv4-only answer became %v", got)
	}
	onlyV6 := []string{"2606:4700:4700::1111"}
	if got := selectAddressFamily(onlyV6); len(got) != 1 {
		t.Errorf("IPv6-only answer became %v", got)
	}

	// Garbage entries are dropped rather than handed to the dialer.
	if got := selectAddressFamily([]string{"not-an-ip"}); len(got) != 0 {
		t.Errorf("unparseable address survived: %v", got)
	}
}
