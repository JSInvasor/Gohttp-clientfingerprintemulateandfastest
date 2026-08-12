package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// stats accumulates the outcome of a load run. Every field is written from
// request goroutines, so the counters are atomic and the maps are guarded.
type stats struct {
	mu       sync.Mutex
	statuses map[int]int
	failures map[string]int

	sent      atomic.Int64
	ok        atomic.Int64
	failed    atomic.Int64
	bodyBytes atomic.Int64

	// latencies holds a strided sample of per-request durations so a very long
	// run cannot turn percentile collection into its memory ceiling. The stride
	// is uniform over request index, so the sample is not biased toward the
	// start of the run the way a "keep the first N" cap would be.
	latencies []time.Duration
	stride    int64
}

const maxLatencySamples = 1 << 21 // ~2M samples, 16 MiB

// newStats sizes the latency sample for an expected request count. A duration
// run passes 0 because its count is not known ahead of time; the stride is
// widened as it goes instead.
func newStats(expected int) *stats {
	stride := int64(1)
	if int64(expected) > maxLatencySamples {
		stride = int64(expected) / maxLatencySamples
	}
	return &stats{
		statuses: make(map[int]int),
		failures: make(map[string]int),
		stride:   stride,
	}
}

func (s *stats) record(index int64, d time.Duration, code int, err error) {
	s.sent.Add(1)

	if index%s.stride == 0 {
		s.mu.Lock()
		s.latencies = append(s.latencies, d)
		// A duration run has no count to size the stride from, so it is
		// doubled whenever the sample fills and half the existing entries are
		// dropped. Keeping every second one preserves uniform coverage of the
		// run so far, which is what the percentiles need.
		if len(s.latencies) >= maxLatencySamples {
			kept := s.latencies[:0]
			for i := 0; i < len(s.latencies); i += 2 {
				kept = append(kept, s.latencies[i])
			}
			s.latencies = kept
			s.stride *= 2
		}
		s.mu.Unlock()
	}

	if err != nil {
		s.failed.Add(1)
		reason := classify(err)
		s.mu.Lock()
		// Distinct error strings are unbounded — each can carry a different
		// port or address — so the tail folds into one bucket rather than
		// letting the map grow with the run.
		if _, known := s.failures[reason]; !known && len(s.failures) >= 24 {
			reason = "other"
		}
		s.failures[reason]++
		s.mu.Unlock()
		return
	}

	s.ok.Add(1)
	s.mu.Lock()
	s.statuses[code]++
	s.mu.Unlock()
}

// classify trims the per-request noise out of an error so the summary groups by
// cause instead of listing one line per ephemeral port.
func classify(err error) string {
	msg := err.Error()
	for _, marker := range []string{
		"server alert:", "certificate", "tls handshake:", "proxy",
		"context deadline exceeded", "context canceled",
		"connection refused", "connection reset", "no such host",
		"i/o timeout", "GOAWAY", "stream error", "EOF",
	} {
		if strings.Contains(msg, marker) {
			return marker
		}
	}
	if len(msg) > 80 {
		return msg[:80]
	}
	return msg
}

// progress redraws a live line while the run is in flight, so a long or stalled
// run is visible rather than silent. It returns when the run finishes.
//
// The line is redrawn in place, which only works on a terminal — piped into a
// file the carriage returns and the erase sequence are literal bytes in the
// output — so anywhere else it is simply not drawn.
func progress(ctx context.Context, done <-chan struct{}, st *stats, o *options, start time.Time) {
	enabled := !o.asJSON && isTerminal(os.Stderr)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	drew := false
	for {
		select {
		case <-done:
			if drew {
				fmt.Fprint(os.Stderr, "\r\033[K")
			}
			return
		case <-ticker.C:
			if !enabled {
				continue
			}
			sent := st.sent.Load()
			elapsed := time.Since(start)
			scope := fmt.Sprintf("%d/%d", sent, o.count)
			if o.duration > 0 {
				remaining := o.duration - elapsed
				if remaining < 0 {
					remaining = 0
				}
				scope = fmt.Sprintf("%d sent, %s left", sent, remaining.Round(time.Second))
			}
			fmt.Fprintf(os.Stderr, "\r%s  %.0f req/s  %d failed   ",
				scope, float64(sent)/elapsed.Seconds(), st.failed.Load())
			drew = true
		}
	}
}

func report(st *stats, elapsed time.Duration, pool *sessionPool, o *options) error {
	st.mu.Lock()
	lat := append([]time.Duration(nil), st.latencies...)
	statuses := make(map[int]int, len(st.statuses))
	for k, v := range st.statuses {
		statuses[k] = v
	}
	failures := make(map[string]int, len(st.failures))
	for k, v := range st.failures {
		failures[k] = v
	}
	st.mu.Unlock()

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })

	sent := st.sent.Load()
	rps := 0.0
	if elapsed > 0 {
		rps = float64(sent) / elapsed.Seconds()
	}
	conns := pool.connections()

	if o.asJSON {
		out := map[string]any{
			"mode":        o.mode,
			"profile":     o.profile,
			"sessions":    o.sessions,
			"workers":     o.concurrency,
			"sent":        sent,
			"ok":          st.ok.Load(),
			"failed":      st.failed.Load(),
			"elapsed_ms":  elapsed.Milliseconds(),
			"rps":         rps,
			"body_bytes":  st.bodyBytes.Load(),
			"connections": conns,
			"statuses":    statuses,
			"failures":    failures,
			"latency_ms": map[string]float64{
				"min": ms(percentile(lat, 0)),
				"p50": ms(percentile(lat, 50)),
				"p90": ms(percentile(lat, 90)),
				"p99": ms(percentile(lat, 99)),
				"max": ms(percentile(lat, 100)),
			},
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Fprintf(os.Stderr, "\n%d requests in %s — %.0f req/s\n", sent, round(elapsed), rps)
	fmt.Fprintf(os.Stderr, "ok %d   failed %d   tls connections %d   body %s\n",
		st.ok.Load(), st.failed.Load(), conns, humanBytes(st.bodyBytes.Load()))

	if len(lat) > 0 {
		fmt.Fprintf(os.Stderr, "latency  min %s   p50 %s   p90 %s   p99 %s   max %s\n",
			round(percentile(lat, 0)), round(percentile(lat, 50)), round(percentile(lat, 90)),
			round(percentile(lat, 99)), round(percentile(lat, 100)))
	}

	if len(statuses) > 0 {
		codes := make([]int, 0, len(statuses))
		for code := range statuses {
			codes = append(codes, code)
		}
		sort.Ints(codes)
		fmt.Fprintln(os.Stderr, "\nstatus")
		for _, code := range codes {
			fmt.Fprintf(os.Stderr, "  %d %-24s %d\n", code, statusText(code), statuses[code])
		}
	}

	if len(failures) > 0 {
		type kv struct {
			reason string
			n      int
		}
		list := make([]kv, 0, len(failures))
		for reason, n := range failures {
			list = append(list, kv{reason, n})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
		fmt.Fprintln(os.Stderr, "\nfailures")
		for _, e := range list {
			fmt.Fprintf(os.Stderr, "  %-32s %d\n", e.reason, e.n)
		}
	}

	if o.proxyStats && pool.rotator != nil {
		reportProxies(pool)
	}
	return nil
}

func reportProxies(pool *sessionPool) {
	all := pool.rotator.Stats()
	sort.Slice(all, func(i, j int) bool { return all[i].Used > all[j].Used })
	fmt.Fprintf(os.Stderr, "\nproxies (%d of %d alive)\n", pool.rotator.LiveCount(), len(all))
	for _, p := range all {
		state := "alive"
		if !p.Alive {
			state = "benched"
			if rest := time.Until(p.CooldownEnd); rest > 0 {
				state = fmt.Sprintf("benched %s", rest.Round(time.Second))
			}
		}
		fmt.Fprintf(os.Stderr, "  %-40s used %-8d failed %-6d %s\n", p.URL, p.Used, p.Failed, state)
	}
}

// percentile returns the p-th percentile of a sorted slice. p is 0-100.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	// Nearest-rank: the smallest value at or above which p% of samples fall.
	idx := (p*len(sorted) + 99) / 100
	if idx > 0 {
		idx--
	}
	return sorted[idx]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// round trims a duration to a readable precision — nanoseconds in a latency
// report are noise.
func round(d time.Duration) time.Duration {
	switch {
	case d >= time.Second:
		return d.Round(10 * time.Millisecond)
	case d >= time.Millisecond:
		return d.Round(100 * time.Microsecond)
	default:
		return d.Round(time.Microsecond)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// isTerminal reports whether f is a character device, which is the difference
// between redrawing a progress line in place and writing carriage returns into
// somebody's log file.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// statusText names a status code, falling back to its class for codes net/http
// does not know — a WAF answering 418 or a vendor-specific 5xx should still
// read as something rather than as a bare number.
func statusText(code int) string {
	if text := http.StatusText(code); text != "" {
		return text
	}
	switch {
	case code >= 500:
		return "server error"
	case code >= 400:
		return "client error"
	case code >= 300:
		return "redirect"
	case code >= 200:
		return "success"
	default:
		return "unknown"
	}
}
