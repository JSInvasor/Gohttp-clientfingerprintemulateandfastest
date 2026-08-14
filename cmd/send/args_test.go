package main

import (
	"flag"
	"strings"
	"testing"
	"time"
)

// The positional dials are the first thing anyone types, and the order is only
// discoverable from the usage text — so these cases are exactly the ones that
// text advertises. A dial that shifts by one silently runs the wrong shape and
// still prints a confident summary, which is why the leftover check exists.
func TestPositionalDials(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantDur time.Duration
		threads int
		clients int
		rate    int
	}{
		{
			name: "url only", args: []string{"https://site.com"},
			threads: 1, clients: 1, // single shot: -n 1 collapses -c to 1
		},
		{
			name: "duration", args: []string{"https://site.com", "30s"},
			wantDur: 30 * time.Second, threads: 50, clients: 1,
		},
		{
			name: "threads", args: []string{"https://site.com", "30s", "100"},
			wantDur: 30 * time.Second, threads: 100, clients: 1,
		},
		{
			name: "clients", args: []string{"https://site.com", "30s", "100", "8"},
			wantDur: 30 * time.Second, threads: 100, clients: 8,
		},
		{
			name: "rate", args: []string{"https://site.com", "30s", "100", "8", "500"},
			wantDur: 30 * time.Second, threads: 100, clients: 8, rate: 500,
		},
		{
			name: "bare seconds", args: []string{"https://site.com", "60", "200"},
			wantDur: time.Minute, threads: 200, clients: 1,
		},
		{
			// A flag skips its slot, so the number after the URL is threads.
			name: "flag skips its dial", args: []string{"https://site.com", "100", "-t", "30s"},
			wantDur: 30 * time.Second, threads: 100, clients: 1,
		},
		{
			// -s defaults to 1, so "was it given" cannot be a zero check.
			name:    "explicit -s wins over the slot",
			args:    []string{"https://site.com", "30s", "100", "-s", "4"},
			wantDur: 30 * time.Second, threads: 100, clients: 4,
		},
		{
			name:    "flags after the dials",
			args:    []string{"https://site.com", "1m", "200", "50", "-proxy-file", "p.txt"},
			wantDur: time.Minute, threads: 200, clients: 50,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, target, err := parseFlags(tc.args)
			if err != nil {
				t.Fatalf("parseFlags(%v): %v", tc.args, err)
			}
			if target != "https://site.com" {
				t.Errorf("target = %q", target)
			}
			if o.duration != tc.wantDur {
				t.Errorf("duration = %s, want %s", o.duration, tc.wantDur)
			}
			if o.concurrency != tc.threads {
				t.Errorf("threads = %d, want %d", o.concurrency, tc.threads)
			}
			if o.sessions != tc.clients {
				t.Errorf("clients = %d, want %d", o.sessions, tc.clients)
			}
			if o.rate != tc.rate {
				t.Errorf("rate = %d, want %d", o.rate, tc.rate)
			}
		})
	}
}

// Anything the dials cannot place has to be reported. Dropping it is how
// `URL 30s 100 8 500` used to run as rate=8 with the 500 discarded, printing a
// summary for a shape nobody asked for.
func TestPositionalLeftoversAreRejected(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"one too many", []string{"https://site.com", "30s", "100", "8", "500", "999"}, `"999"`},
		{"typo mid-dials", []string{"https://site.com", "30s", "abc"}, `"abc"`},
		{"second url", []string{"https://site.com", "https://other.com"}, `"https://other.com"`},
		{"negative", []string{"https://site.com", "30s", "-1"}, ""}, // -1 parses as a flag
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseFlags(tc.args)
			if err == nil {
				t.Fatalf("parseFlags(%v) was accepted", tc.args)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the offending argument %s", err, tc.want)
			}
		})
	}
}

// The dials must not silently override a flag the user typed, in either order.
func TestPositionalDoesNotOverrideFlags(t *testing.T) {
	o, _, err := parseFlags([]string{"-t", "5s", "-c", "7", "-s", "2", "-rps", "9", "https://site.com"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if o.duration != 5*time.Second || o.concurrency != 7 || o.sessions != 2 || o.rate != 9 {
		t.Errorf("flags were disturbed: t=%s c=%d s=%d rate=%d",
			o.duration, o.concurrency, o.sessions, o.rate)
	}
}

// splitArgs pulls flags out before Parse, so a value that looks like a URL must
// still reach the flag it belongs to rather than being taken as the target.
func TestFlagValuesAreNotMistakenForPositionals(t *testing.T) {
	o, target, err := parseFlags([]string{"-proxy", "http://exit.test:8080", "https://site.com", "30s"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if target != "https://site.com" {
		t.Errorf("target = %q, want the real URL", target)
	}
	if o.proxy != "http://exit.test:8080" {
		t.Errorf("proxy = %q", o.proxy)
	}
	if o.duration != 30*time.Second {
		t.Errorf("duration = %s", o.duration)
	}
}

// Running send with nothing prints the usage, and that text is the only place
// the dial order is documented — so it has to actually name them.
func TestUsageDocumentsTheDials(t *testing.T) {
	var sb strings.Builder
	printUsage(&sb)
	usage := sb.String()

	for _, want := range []string{
		"URL [duration] [threads] [clients] [rate]",
		"send https://site.com 1m 200 8 500", // all four dials in one example
		"-solve",
		"-mode fast",
		"made by Arsene",
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("usage does not mention %q", want)
		}
	}
}

// Every flag the tool accepts needs a line in the help, or it may as well not
// exist: this text is the only reference there is.
func TestUsageDocumentsEveryFlag(t *testing.T) {
	var sb strings.Builder
	printUsage(&sb)
	usage := sb.String()

	// The two aliases are documented under the name they share with another
	// flag, so they have no line of their own.
	alias := map[string]bool{"profile": true, "rate": true}

	newFlagSet(&options{}).VisitAll(func(f *flag.Flag) {
		if alias[f.Name] {
			return
		}
		if !strings.Contains(usage, "-"+f.Name) {
			t.Errorf("-%s has no line in the usage text", f.Name)
		}
	})
}

// The help is colour only on a terminal. Redirected to a file, piped to a pager
// or captured by a test, escape codes are noise — and this is the writer every
// one of those looks like.
func TestUsageIsPlainWhenNotATerminal(t *testing.T) {
	var sb strings.Builder
	printUsage(&sb)
	if strings.Contains(sb.String(), "\033[") || strings.ContainsRune(sb.String(), 0x1b) {
		t.Error("the usage carried ANSI escape codes into a non-terminal writer")
	}
}
