// Command fpcheck answers one question: does this client still look like the
// browser it claims to be?
//
// It sends a request with each profile to a TLS/HTTP2 fingerprinting endpoint,
// reads back what the server actually saw, and diffs that against the reference
// values in reference.go — the fingerprints captured from real devices. Every
// check prints PASS or FAIL with the expected and observed value, so a
// regression names itself instead of showing up later as an unexplained 403.
//
// The package's own tests verify the ClientHello and the HTTP/2 frames offline,
// but they can only prove the client emits the bytes it was written to emit.
// Whether those bytes are still what the browser sends needs a real device, and
// whether they survive the path to the server needs a real request. This
// command covers both.
//
// Usage:
//
//	go run ./cmd/fpcheck                     # both profiles
//	go run ./cmd/fpcheck -profile chrome
//	go run ./cmd/fpcheck -proxy socks5://user:pass@host:1080
//	go run ./cmd/fpcheck -save safari.json   # keep the raw capture
//	go run ./cmd/fpcheck -compare device.json -profile safari
//
// The -compare mode is how a reference gets refreshed. Open the same URL in the
// real browser, save the JSON it returns, then diff this client against it:
//
//	go run ./cmd/fpcheck -profile safari -compare iphone.json
//
// Exit status is 0 when every check passes and 1 otherwise, so it can gate CI.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// defaultURL returns both the TLS and the HTTP/2 view of a request in one
// response, which is what makes a single fetch enough to check every layer.
const defaultURL = "https://tls.peet.ws/api/all"

func main() {
	var (
		url        = flag.String("url", defaultURL, "fingerprinting endpoint returning JSON")
		profile    = flag.String("profile", "both", "safari, chrome, or both")
		proxy      = flag.String("proxy", "", "proxy URL (http://, socks5://); checks what the target sees through it")
		compare    = flag.String("compare", "", "path to a JSON capture from a real browser to diff against")
		save       = flag.String("save", "", "write the raw JSON response to this path")
		timeout    = flag.Duration("timeout", 30*time.Second, "request timeout")
		showFrames = flag.Bool("frames", false, "print the HTTP/2 frames the server recorded")
	)
	flag.Parse()

	profiles, err := selectProfiles(*profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fpcheck:", err)
		os.Exit(2)
	}
	flagProfiles = profiles
	if *compare != "" && len(profiles) != 1 {
		fmt.Fprintln(os.Stderr, "fpcheck: -compare needs a single -profile (safari or chrome)")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	ok := true
	for i, p := range profiles {
		if i > 0 {
			fmt.Println()
		}
		if err := run(ctx, p, *url, *proxy, *compare, *save, *showFrames); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", p, err)
			ok = false
		}
	}
	if !ok {
		os.Exit(1)
	}
}

func selectProfiles(name string) ([]gofire.BrowserProfile, error) {
	switch strings.ToLower(name) {
	case "safari", "ios":
		return []gofire.BrowserProfile{gofire.SafariIOS18}, nil
	case "chrome":
		return []gofire.BrowserProfile{gofire.Chrome150}, nil
	case "both", "all", "":
		return []gofire.BrowserProfile{gofire.SafariIOS18, gofire.Chrome150}, nil
	default:
		return nil, fmt.Errorf("unknown profile %q (want safari, chrome, or both)", name)
	}
}

func run(ctx context.Context, profile gofire.BrowserProfile, url, proxy, compare, save string, showFrames bool) error {
	opts := []gofire.Option{gofire.WithTimeout(25 * time.Second)}
	if proxy != "" {
		opts = append(opts, gofire.WithProxy(proxy))
	}

	client, err := gofire.Emulate(profile, opts...)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer client.Close()

	resp, err := client.GetWithContext(ctx, url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Close()

	raw, err := resp.Bytes()
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if code := resp.StatusCode(); code != 200 {
		return fmt.Errorf("HTTP %d from %s: %s", code, url, truncate(string(raw), 300))
	}

	var got capture
	if err := json.Unmarshal(raw, &got); err != nil {
		return fmt.Errorf("parse response (is %s a fingerprint API?): %w", url, err)
	}

	if save != "" {
		path := save
		if len(flagProfiles) > 1 {
			path = withSuffix(save, profileSlug(profile))
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			return fmt.Errorf("save capture: %w", err)
		}
		fmt.Printf("saved raw capture to %s\n", path)
	}

	header := fmt.Sprintf("%s  via %s", profile, url)
	if proxy != "" {
		header += "  (proxy)"
	}
	fmt.Println(header)
	fmt.Println(strings.Repeat("=", len(header)))

	var checks []check
	if compare != "" {
		want, err := loadCapture(compare)
		if err != nil {
			return err
		}
		fmt.Printf("comparing against %s\n\n", compare)
		checks = diffCaptures(*want, got)
	} else {
		ref := gofire.ReferenceFor(profile)
		fmt.Printf("reference device: %s\n\n", ref.Device)
		checks = checkAgainstReference(ref, got)
	}

	failed := report(checks)

	if showFrames {
		fmt.Println()
		printFrames(got)
	}

	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	return nil
}

// flagProfiles is set by main so run can tell whether -save needs a per-profile
// suffix. Kept package-level rather than threaded through because it exists
// purely for naming output files.
var flagProfiles []gofire.BrowserProfile

// ---------- the fingerprint API response ----------

// capture is the subset of a fingerprint API response fpcheck reads. The field
// names follow tls.peet.ws, which most equivalent services mirror; unknown
// fields are ignored, so a service returning a superset still works.
type capture struct {
	UserAgent string `json:"user_agent"`
	TLS       struct {
		JA3       string `json:"ja3"`
		JA3Hash   string `json:"ja3_hash"`
		JA4       string `json:"ja4"`
		JA4R      string `json:"ja4_r"`
		PeetPrint string `json:"peetprint_hash"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprint     string  `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string  `json:"akamai_fingerprint_hash"`
		SentFrames            []frame `json:"sent_frames"`
	} `json:"http2"`
}

type frame struct {
	FrameType string   `json:"frame_type"`
	StreamID  int      `json:"stream_id"`
	Flags     []string `json:"flags"`
	Headers   []string `json:"headers"`
	Priority  *struct {
		Weight    int `json:"weight"`
		DependsOn int `json:"depends_on"`
		Exclusive int `json:"exclusive"`
	} `json:"priority"`
}

func loadCapture(path string) (*capture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c capture
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// headersFrame returns the HEADERS frame for the request stream.
func (c capture) headersFrame() *frame {
	for i := range c.HTTP2.SentFrames {
		if strings.EqualFold(c.HTTP2.SentFrames[i].FrameType, "HEADERS") {
			return &c.HTTP2.SentFrames[i]
		}
	}
	return nil
}

// headerNames returns the request header names in wire order, pseudo-headers
// first. The API reports each header as "name: value"; only the name matters
// for order, and values like cookie or user-agent should not be printed.
func (f *frame) headerNames() (pseudo, regular []string) {
	for _, h := range f.Headers {
		name := h
		if i := strings.IndexByte(h, ':'); i > 0 {
			name = h[:i]
		} else if strings.HasPrefix(h, ":") {
			if j := strings.IndexByte(h[1:], ':'); j >= 0 {
				name = h[:j+1]
			}
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, ":") {
			pseudo = append(pseudo, name)
		} else {
			regular = append(regular, name)
		}
	}
	return pseudo, regular
}

// ---------- checks ----------

type check struct {
	name string
	want string
	got  string
	// skipped marks a check that cannot be made rather than one that passed,
	// so an endpoint that omits a field never reads as a green tick.
	skipped bool
	note    string
}

func (c check) ok() bool { return c.skipped || c.want == c.got }

func checkAgainstReference(ref gofire.Reference, got capture) []check {
	var checks []check

	add := func(name, want, actual string) {
		checks = append(checks, check{name: name, want: want, got: actual})
	}
	skip := func(name, note string) {
		checks = append(checks, check{name: name, skipped: true, note: note})
	}

	add("user-agent", ref.UserAgent, got.UserAgent)

	// JA3 is only meaningful for Safari. Chrome permutes its extension order
	// per connection, so its JA3 is a different value every time by design —
	// checking it against a fixed reference would fail on a correct client.
	if ref.JA3Hash != "" {
		if got.TLS.JA3Hash == "" {
			skip("tls.ja3_hash", "endpoint did not report ja3_hash")
		} else {
			add("tls.ja3_hash", ref.JA3Hash, got.TLS.JA3Hash)
			add("tls.ja3", ref.JA3, got.TLS.JA3)
		}
	} else {
		skip("tls.ja3_hash", "Chrome permutes extensions per connection; JA3 is expected to vary")
	}

	if got.TLS.JA4 == "" {
		skip("tls.ja4", "endpoint did not report ja4")
	} else {
		add("tls.ja4", ref.JA4, got.TLS.JA4)
	}

	if got.HTTP2.AkamaiFingerprint == "" {
		skip("http2.akamai_fingerprint", "endpoint did not report an HTTP/2 fingerprint")
	} else {
		add("http2.akamai_fingerprint", ref.AkamaiFingerprint, got.HTTP2.AkamaiFingerprint)
		if got.HTTP2.AkamaiFingerprintHash != "" {
			add("http2.akamai_hash", ref.AkamaiHash, got.HTTP2.AkamaiFingerprintHash)
		}
	}

	hf := got.headersFrame()
	if hf == nil {
		skip("http2.headers_frame", "endpoint did not report sent frames (HTTP/1.1 response?)")
		return checks
	}

	// The priority block on HEADERS is the check that catches a client
	// contradicting its own SETTINGS: advertising NO_RFC7540_PRIORITIES and
	// then attaching an RFC 7540 priority block anyway.
	wantPrio := "absent"
	if ref.HeadersPriority {
		wantPrio = "weight=256 depends_on=0 exclusive=1"
	}
	add("http2.headers_priority", wantPrio, describePriority(hf))

	pseudo, regular := hf.headerNames()
	add("http2.pseudo_header_order", strings.Join(ref.PseudoHeaderOrder, ","), strings.Join(pseudo, ","))

	// Compare only the reference headers, in order, ignoring any extra the
	// request happened to carry — the reference lists what the profile always
	// sends, not everything it may send.
	add("header_order", strings.Join(ref.HeaderOrder, ","),
		strings.Join(filterTo(regular, ref.HeaderOrder), ","))

	if extra := notIn(regular, ref.HeaderOrder); len(extra) > 0 {
		checks = append(checks, check{
			name:    "header_extras",
			skipped: true,
			note:    "request also carried: " + strings.Join(extra, ", "),
		})
	}

	return checks
}

func describePriority(f *frame) string {
	hasFlag := false
	for _, fl := range f.Flags {
		if strings.Contains(strings.ToLower(fl), "priority") {
			hasFlag = true
		}
	}
	if !hasFlag && f.Priority == nil {
		return "absent"
	}
	if f.Priority == nil {
		return "PRIORITY flag set but no priority block reported"
	}
	return fmt.Sprintf("weight=%d depends_on=%d exclusive=%d",
		f.Priority.Weight, f.Priority.DependsOn, f.Priority.Exclusive)
}

// diffCaptures compares this client's capture against one taken from a real
// browser hitting the same endpoint. This is the check that can actually move a
// reference: everything else compares the client to values already committed.
func diffCaptures(want, got capture) []check {
	checks := []check{
		{name: "user-agent", want: want.UserAgent, got: got.UserAgent},
		{name: "tls.ja4", want: want.TLS.JA4, got: got.TLS.JA4},
		{name: "tls.ja4_r", want: want.TLS.JA4R, got: got.TLS.JA4R},
		{name: "tls.ja3", want: want.TLS.JA3, got: got.TLS.JA3},
		{name: "tls.ja3_hash", want: want.TLS.JA3Hash, got: got.TLS.JA3Hash},
		{name: "tls.peetprint_hash", want: want.TLS.PeetPrint, got: got.TLS.PeetPrint},
		{name: "http2.akamai_fingerprint", want: want.HTTP2.AkamaiFingerprint, got: got.HTTP2.AkamaiFingerprint},
	}

	wf, gf := want.headersFrame(), got.headersFrame()
	if wf != nil && gf != nil {
		checks = append(checks,
			check{name: "http2.headers_priority", want: describePriority(wf), got: describePriority(gf)})
		wp, wr := wf.headerNames()
		gp, gr := gf.headerNames()
		checks = append(checks,
			check{name: "http2.pseudo_header_order", want: strings.Join(wp, ","), got: strings.Join(gp, ",")},
			check{name: "header_order", want: strings.Join(wr, ","), got: strings.Join(gr, ",")})
	}

	// A field the browser capture does not carry says nothing about this
	// client, so report it as unchecked rather than as a match.
	for i := range checks {
		if checks[i].want == "" {
			checks[i].skipped = true
			checks[i].note = "not present in the browser capture"
		}
	}
	return checks
}

func report(checks []check) (failed int) {
	width := 0
	for _, c := range checks {
		if len(c.name) > width {
			width = len(c.name)
		}
	}

	for _, c := range checks {
		switch {
		case c.skipped:
			fmt.Printf("SKIP  %-*s  %s\n", width, c.name, c.note)
		case c.ok():
			fmt.Printf("PASS  %-*s  %s\n", width, c.name, truncate(c.got, 96))
		default:
			failed++
			fmt.Printf("FAIL  %-*s\n", width, c.name)
			fmt.Printf("          want: %s\n", c.want)
			fmt.Printf("          got:  %s\n", c.got)
		}
	}

	fmt.Println()
	if failed == 0 {
		fmt.Printf("%d checks passed\n", countChecked(checks))
	} else {
		fmt.Printf("%d of %d checks FAILED\n", failed, countChecked(checks))
	}
	return failed
}

func countChecked(checks []check) int {
	n := 0
	for _, c := range checks {
		if !c.skipped {
			n++
		}
	}
	return n
}

func printFrames(c capture) {
	fmt.Println("HTTP/2 frames the server recorded:")
	for _, f := range c.HTTP2.SentFrames {
		fmt.Printf("  %-14s stream=%d flags=%s\n", f.FrameType, f.StreamID, strings.Join(f.Flags, "|"))
		if f.Priority != nil {
			fmt.Printf("      priority: weight=%d depends_on=%d exclusive=%d\n",
				f.Priority.Weight, f.Priority.DependsOn, f.Priority.Exclusive)
		}
		for _, h := range f.Headers {
			fmt.Printf("      %s\n", truncate(h, 110))
		}
	}
}

// ---------- helpers ----------

// filterTo keeps the entries of got that appear in want, preserving got's
// order, so a header order check compares like with like.
func filterTo(got, want []string) []string {
	set := make(map[string]bool, len(want))
	for _, w := range want {
		set[w] = true
	}
	out := make([]string, 0, len(want))
	for _, g := range got {
		if set[g] {
			out = append(out, g)
		}
	}
	return out
}

// notIn returns the entries of got absent from want, sorted.
func notIn(got, want []string) []string {
	set := make(map[string]bool, len(want))
	for _, w := range want {
		set[w] = true
	}
	var out []string
	for _, g := range got {
		if !set[g] {
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func withSuffix(path, suffix string) string {
	if i := strings.LastIndexByte(path, '.'); i > 0 {
		return path[:i] + "-" + suffix + path[i:]
	}
	return path + "-" + suffix
}

func profileSlug(p gofire.BrowserProfile) string {
	if p == gofire.Chrome150 {
		return "chrome"
	}
	return "safari"
}
