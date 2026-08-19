package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// The help screen, in two colours.
//
// Colour is only ever written to a terminal. printUsage is handed a
// strings.Builder by the tests and a redirected stderr by anyone piping it to a
// file or a pager, and escape codes in either of those are noise rather than
// decoration — so the palette collapses to empty strings unless the writer is a
// terminal, and NO_COLOR turns it off everywhere.

// palette holds the codes for one destination. The zero value is the plain-text
// palette, which is what makes the not-a-terminal case free.
type palette struct {
	name  string // the tool's own name, and section headings
	cmd   string // the commands worth copying
	dim   string // descriptions, punctuation, everything supporting
	rule  string // the divider
	reset string
}

// paletteFor returns real codes for a terminal and empty ones for anything else.
func paletteFor(w io.Writer) palette {
	f, ok := w.(*os.File)
	if !ok || !isTerminal(f) || os.Getenv("NO_COLOR") != "" {
		return palette{}
	}
	return palette{
		// Two tones and nothing else: a soft red for what the eye should land
		// on, greys for the rest. Anything more starts competing with the
		// terminal's own theme.
		name:  "\033[38;5;203m",
		cmd:   "\033[38;5;252m",
		dim:   "\033[38;5;244m",
		rule:  "\033[38;5;238m",
		reset: "\033[0m",
	}
}

// The page is laid out to one width so the rule, the signature and every
// description line up. 76 leaves room inside an 80-column terminal.
const (
	pageWidth    = 76
	indent       = "  "
	exampleWidth = 46
)

// example renders one command with its description aligned.
//
// The padding is measured on the plain text, because the colour codes have no
// width on screen but do have length in the string — formatting with %-48s would
// count them and pull every description out of line.
func (p palette) example(cmd, desc string) string {
	pad := exampleWidth - len([]rune(cmd))
	if pad < 2 {
		pad = 2
	}
	line := indent + indent + p.cmd + cmd + p.reset
	if desc != "" {
		line += strings.Repeat(" ", pad) + p.dim + desc + p.reset
	}
	return line + "\n"
}

// note is a line of explanation under an example, set in from it.
func (p palette) note(text string) string {
	return indent + indent + indent + p.dim + text + p.reset + "\n"
}

// heading opens a section.
func (p palette) heading(text string) string {
	return "\n" + indent + p.name + text + p.reset + "\n"
}

// section renders a heading and the block of text under it, set in one level so
// the reference lists sit under their heading the way the examples do.
func (p palette) section(text, body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = indent + line
		}
	}
	return p.heading(text) + p.dim + strings.Join(lines, "\n") + p.reset + "\n"
}

func printUsage(w io.Writer) {
	p := paletteFor(w)

	// The signature line, padded so the byline ends where the rule does. The
	// widths are measured on the plain text: the colour codes take no columns
	// on screen, and the flag takes two rather than one.
	const (
		left     = "send — a browser-shaped HTTP client"
		byline   = "> made by Arsene "
		flagCols = 2
	)
	gap := pageWidth - len([]rune(left)) - len([]rune(byline)) - flagCols
	if gap < 1 {
		gap = 1
	}
	fmt.Fprintf(w, "\n%s%ssend%s %s— a browser-shaped HTTP client%s%s%s>%s %smade by%s %sArsene%s 🇺🇸\n",
		indent, p.name, p.reset, p.dim, p.reset, strings.Repeat(" ", gap),
		p.rule, p.reset, p.dim, p.reset, p.name, p.reset)
	fmt.Fprintf(w, "%s%s%s%s\n", indent, p.rule, strings.Repeat("─", pageWidth), p.reset)

	fmt.Fprintf(w, "\n%s%susage%s  %ssend URL [duration] [threads] [clients] [rate] [flags]%s\n",
		indent, p.dim, p.reset, p.cmd, p.reset)
	fmt.Fprintf(w, "%s%sA single request prints the response. Adding a duration — or -n — makes it\n"+
		"%sa load run and prints a summary instead.%s\n", indent, p.dim, indent, p.reset)

	fmt.Fprint(w, p.heading("start here"))
	fmt.Fprint(w, p.example("send -scout https://site.com", "look first, then say what to run"))
	fmt.Fprint(w, p.note("a few seconds of probing: who is in front, whether it challenges, how far"))
	fmt.Fprint(w, p.note("away it is — and a command with a reason beside every flag in it"))

	fmt.Fprint(w, p.heading("one request"))
	fmt.Fprint(w, p.example("send https://site.com", "prints the response"))
	fmt.Fprint(w, p.example("send -i -p chrome https://site.com", "Chrome profile, with headers"))
	fmt.Fprint(w, p.example("send -assets https://site.com", "the page, not just the document"))
	fmt.Fprint(w, p.example("send -fingerprint -p chrome", "the profile's reference values"))

	fmt.Fprint(w, p.heading("load"))
	fmt.Fprint(w, p.example("send https://site.com 30s 200 2", "30s, 200 threads, 2 clients"))
	fmt.Fprint(w, p.example("send -mode fast https://site.com 30s 256 2", "the fastest path — measured"))
	fmt.Fprint(w, p.example("send https://site.com 1m 200 8 500", "...held at 500 req/s"))
	fmt.Fprint(w, p.example("send -n 50000 -c 300 https://site.com", "a fixed count instead of a clock"))

	fmt.Fprint(w, p.heading("past a Cloudflare challenge"))
	fmt.Fprint(w, p.example("send -solve https://site.com", "earn a cf_clearance, then replay it"))
	fmt.Fprint(w, p.example("send -solve https://site.com 1m 200 8 -proxy-file p.txt", ""))
	fmt.Fprint(w, p.note("one solve per exit address, each session replaying only its own cookie"))

	fmt.Fprint(w, p.heading("a request with a body"))
	fmt.Fprint(w, p.example(`send -X POST -H 'Content-Type: application/json' \`, ""))
	fmt.Fprint(w, p.example(`     -d '{"a":1}' https://site.com/api`, ""))

	fmt.Fprint(w, p.section("getting the rate up", `-mode fast    the shortest path: no jar, no redirects, no retries
-s 2          one session is one HTTP/2 connection behind one write lock,
              and a second measured ~28% over the first
-c            about rate × round-trip time. More than that queues rather
              than flies, and costs throughput`))

	fmt.Fprint(w, p.section("load shape", `-n int          number of requests (default 1)
-t duration     [1st] run for this long instead, e.g. 30s, 5m
-c int          [2nd] threads: concurrent requests in flight
-s int          [3rd] clients: independent sessions, each with its own cookie
                jar, connection pool and pinned proxy
-rps int        [4th] hold the whole run at this many requests per second
-mode string    client | fast | pipeline (default client)
-warmup int     pre-open this many TLS connections per session first, so the
                numbers measure throughput rather than handshakes`))

	fmt.Fprint(w, p.section("identity", `-p string       browser profile: safari | chrome (default safari)
-lang string    Accept-Language. Worth setting: it is scored against where
                your exit IPs are, and the default is en-US
-cookie k=v     seed a cookie into every session (repeatable)
-assets         after each document, fetch the stylesheets, scripts, images
                and fonts it references — a document alone is not a page load
-fingerprint    print the profile's reference fingerprint and continue`))

	fmt.Fprint(w, p.section("cloudflare", `-solve                earn a cf_clearance by driving a real Chromium.
                      Implies -p chrome. Needs Chrome or Chromium installed
-chrome path          the browser to drive (default: the first one found,
                      or $SOLVER_CHROME)
-solve-replay         replay the cookies already earned for this target and
                      say whether they still work — the question a 403 after
                      a successful solve leaves open
-solve-refresh        ignore the cached solve and earn a new one
-solve-timeout dur    how long one solve may take (default 150s). Browser
                      startup comes out of this, so a small VPS needs more
-solve-parallel int   how many exits to solve at once (default 2)
-solve-ip-check url   measure where each proxy leaves from and solve once per
                      address, dropping the dead and the rotating ones. This
                      is what makes a hundred-proxy list affordable`))

	fmt.Fprint(w, p.section("request", `-X string       HTTP method (default GET)
-H 'K: v'       extra header (repeatable)
-d string       request body; @path reads it from a file`))

	fmt.Fprint(w, p.section("proxy", `-proxy url            single proxy, http:// or socks5://
-proxy-file path      file of proxies to rotate, one per line
-proxy-stats          per-proxy usage after the run — which exits carried the
                      run and which were benched`))

	fmt.Fprint(w, p.section("network", `-timeout dur          total per-request timeout (default 30s)
-retry int            retry on network errors and 429/502/503/504
-insecure             skip TLS certificate verification
-http1                force HTTP/1.1 instead of negotiating h2
-no-redirect          do not follow redirects
-max-streams int      HTTP/2 streams per connection before it is cycled. A long
                      monotonic stream-id sequence is its own passive signal
-tls-resume           offer a cached TLS 1.3 ticket on repeat connections, as a
                      browser does. Off by default: the PSK moves JA4 to
                      t13d1517h2, so connections after the first differ`))

	fmt.Fprint(w, p.section("output", `-scout          probe the target and print the command to run against it,
                with the measurement behind every flag. Reads -proxy-file
                and -lang if given, so it plans for the run you meant
-i              print response headers (single request only)
-o path         write the response body to a file
-silent         suppress the response body
-json           print the run summary as JSON`))

	// The rest still work; they are just not what anyone reaches for first.
	// Named rather than dropped, because a flag nothing mentions is a flag
	// nobody finds — and the tests require every one of them to appear here.
	fmt.Fprint(w, p.section("also accepted", `-ua  -accept  -referer  -asset-limit  -asset-parallel  -solve-cache
-solve-max-age  -solve-isolate  -solve-all-cookies  -proxy-cooldown  -proxy-fails
-max-body
-handshake-timeout  -dial-timeout  -header-timeout  -write-timeout  -dns-ttl
-max-redirects  -no-keepalive  -idle-conns  -idle-per-host  -conns-per-host
-sockbuf  -tfo`))

	fmt.Fprintln(w)
}
