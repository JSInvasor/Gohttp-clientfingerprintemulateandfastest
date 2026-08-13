package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// chromiumProbe is what solver/fingerprint.js prints: the identity of the real
// Chromium this repo drives, plus the fingerprint endpoint's view of it.
type chromiumProbe struct {
	Status          string  `json:"status"`
	Error           string  `json:"error"`
	Version         string  `json:"chromium_version"`
	Major           int     `json:"chromium_major"`
	NativeUserAgent string  `json:"native_user_agent"`
	SolverUserAgent string  `json:"solver_user_agent"`
	Capture         capture `json:"capture"`
}

// runChromiumProbe launches the solver's Chromium and captures its fingerprint.
//
// It shells out to solver/fingerprint.js rather than driving a browser from Go
// so the measured browser is the one the solver actually launches — same
// puppeteer-real-browser build, same flags, same stealth patches. A separately
// configured browser would answer a different question, and the question here
// is exactly "is the browser that earns cf_clearance the browser we emulate".
func runChromiumProbe(ctx context.Context, solverDir, url string, timeoutSec int) (*chromiumProbe, error) {
	script := filepath.Join(solverDir, "fingerprint.js")
	if _, err := os.Stat(script); err != nil {
		return nil, fmt.Errorf("%s not found: %w", script, err)
	}
	// The probe imports puppeteer-real-browser, so a missing install fails with
	// a Node module-resolution error that says nothing about how to fix it.
	if _, err := os.Stat(filepath.Join(solverDir, "node_modules")); err != nil {
		return nil, fmt.Errorf("%s/node_modules not found — run `npm install` in %s first",
			solverDir, solverDir)
	}

	cmd := exec.CommandContext(ctx, "node", script, url, strconv.Itoa(timeoutSec))
	cmd.Dir = "."
	cmd.Stderr = os.Stderr // puppeteer's launch diagnostics are worth seeing

	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("node not found in PATH; the Chromium probe needs Node.js")
		}
		return nil, fmt.Errorf("run %s: %w", script, err)
	}

	probe, perr := parseProbeOutput(out)
	if perr != nil {
		return nil, fmt.Errorf("parse %s output: %w", script, perr)
	}
	if probe.Status != "ok" {
		msg := probe.Error
		if msg == "" {
			msg = "status " + probe.Status
		}
		return nil, fmt.Errorf("chromium probe failed: %s", msg)
	}
	return probe, nil
}

// parseProbeOutput extracts the probe result from the script's stdout.
//
// fingerprint.js prints one JSON object and nothing else, so the whole output
// normally parses directly. The line fallback exists because a dependency deep
// in puppeteer's tree can print a deprecation banner first, and a run that
// worked should not be reported as a parse failure over a warning. Scanning
// backwards means the probe result — always last — wins over any preamble.
func parseProbeOutput(out []byte) (*chromiumProbe, error) {
	if probe, err := decodeProbe(out); err == nil {
		return probe, nil
	}

	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if probe, err := decodeProbe([]byte(line)); err == nil {
			return probe, nil
		}
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, errors.New("the script produced no output")
	}
	return nil, fmt.Errorf("no JSON object in %q", truncate(strings.TrimSpace(string(out)), 200))
}

// decodeProbe unmarshals one probe object, rejecting anything without a status
// so a stray JSON line from a dependency is not mistaken for the result.
func decodeProbe(b []byte) (*chromiumProbe, error) {
	var probe chromiumProbe
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, err
	}
	if probe.Status == "" {
		return nil, errors.New("JSON object has no status field")
	}
	return &probe, nil
}

// checkChromiumProbe compares the real browser against the profile gofire
// emulates.
//
// The checks are ordered by what actually breaks first in production. A UA
// mismatch invalidates cf_clearance immediately and is trivial to fix; a JA4
// mismatch invalidates it too but means the Go profile is pinned to a different
// Chrome release than the box has installed, which is a bigger job.
func checkChromiumProbe(ref gofire.Reference, probe *chromiumProbe) []check {
	var checks []check
	add := func(name, want, got string) {
		checks = append(checks, check{name: name, want: want, got: got})
	}
	skip := func(name, note string) {
		checks = append(checks, check{name: name, skipped: true, note: note})
	}

	// The UA the solver pins for the solved session must be the one gofire
	// replays with, or the cookie is issued to one identity and presented by
	// another.
	//
	// The comparison is against the pinned UA for the solver's own platform,
	// not against the profile's default one. The solver runs wherever it runs —
	// a Linux VPS, most often — and claiming an OS it is not running is a
	// mismatch a challenge can see from JS, so it pins the OS token it actually
	// has. What has to match is the browser identity, which is what this checks
	// once both sides are talking about the same platform.
	switch {
	case probe.SolverUserAgent == "":
		skip("solver.user_agent", "probe reported no solver_user_agent")
	default:
		platform := gofire.PlatformFromUserAgent(probe.SolverUserAgent)
		want, ok := gofire.ChromeUserAgentFor(platform)
		if !ok {
			skip("solver.user_agent", fmt.Sprintf(
				"the solver runs on %q, which this client has no pinned Chrome UA for",
				platform))
			break
		}
		add("solver.user_agent", want, probe.SolverUserAgent)
		if refPlatform := gofire.PlatformFromUserAgent(ref.UserAgent); refPlatform != platform {
			skip("solver.platform", fmt.Sprintf(
				"the solver runs on %s while the %s profile defaults to %s — replay with "+
					"WithUserAgent(%q) so both name the same OS, which `send -solve` does for you",
				platform, ref.Profile, refPlatform, want))
		}
	}

	// The installed Chromium's own major version against the one the Go profile
	// claims. These can legitimately differ for a while — Chrome's TLS layer was
	// unchanged across 146..151 — so this is reported, not failed, and the JA4
	// check below is what decides whether the difference matters.
	profileMajor := majorFromUA(ref.UserAgent)
	switch {
	case probe.Major == 0:
		skip("chromium.version", "probe could not read the Chromium version")
	case profileMajor == 0:
		skip("chromium.version", "could not parse a major version from the profile UA")
	case probe.Major == profileMajor:
		add("chromium.version", strconv.Itoa(profileMajor), strconv.Itoa(probe.Major))
	default:
		skip("chromium.version", fmt.Sprintf(
			"box has Chromium %d, profile emulates Chrome %d — harmless only while "+
				"their TLS layers agree, which the ja4 check below decides",
			probe.Major, profileMajor))
	}

	// The layers that actually bind the cookie. No page-level override can reach
	// these: they come from BoringSSL and Chromium's HTTP/2 stack.
	if probe.Capture.TLS.JA4 == "" {
		skip("chromium.ja4", "endpoint did not report ja4")
	} else {
		add("chromium.ja4", ref.JA4, probe.Capture.TLS.JA4)
	}
	if probe.Capture.TLS.JA4R == "" {
		skip("chromium.ja4_r", "endpoint did not report ja4_r")
	} else if ref.JA4R == "" {
		skip("chromium.ja4_r", "no ja4_r pinned for this profile")
	} else {
		add("chromium.ja4_r", ref.JA4R, probe.Capture.TLS.JA4R)
	}
	if probe.Capture.HTTP2.AkamaiFingerprint == "" {
		skip("chromium.akamai_fingerprint", "endpoint did not report an HTTP/2 fingerprint")
	} else {
		add("chromium.akamai_fingerprint", ref.AkamaiFingerprint, probe.Capture.HTTP2.AkamaiFingerprint)
	}

	return checks
}

// majorFromUA pulls the Chrome major version out of a User-Agent string.
// Returns 0 when there is no Chrome/N token, which is the Safari case.
func majorFromUA(ua string) int {
	const token = "Chrome/"
	i := strings.Index(ua, token)
	if i < 0 {
		return 0
	}
	rest := ua[i+len(token):]
	end := strings.IndexByte(rest, '.')
	if end < 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return n
}

// runViaChromium answers the question the solver's design depends on: is the
// browser that earns cf_clearance the same browser gofire replays it with?
//
// It measures three things and reports them in the order they matter:
//
//  1. the real Chromium against the pinned reference — is the profile even
//     describing the browser installed on this box?
//  2. this client against that same Chromium, field by field — the direct
//     answer, since these two are what actually exchange the cookie.
//  3. the solver's pinned UA against the Go profile's.
//
// Cloudflare binds cf_clearance to the issuing session's (UA, JA3/JA4, IP). A
// mismatch here does not fail loudly at runtime; it produces a cookie that
// works once, dies in seconds under load, and looks exactly like a solver bug.
func runViaChromium(ctx context.Context, profile gofire.BrowserProfile, url, proxy, save, solverDir string, timeout time.Duration) error {
	ref := gofire.ReferenceFor(profile)

	fmt.Printf("launching the solver's Chromium against %s\n", url)
	fmt.Println("(this opens a real browser and takes ~10-30s)")

	probe, err := runChromiumProbe(ctx, solverDir, url, int(timeout.Seconds()))
	if err != nil {
		return err
	}

	header := fmt.Sprintf("%s  vs the Chromium on this box", profile)
	fmt.Printf("\n%s\n%s\n", header, strings.Repeat("=", len(header)))
	fmt.Printf("chromium:  %s\n", probe.Version)
	if probe.NativeUserAgent != "" {
		fmt.Printf("native UA: %s\n", probe.NativeUserAgent)
	}
	fmt.Printf("reference: %s\n\n", ref.Device)

	if save != "" {
		raw, mErr := json.MarshalIndent(probe.Capture, "", "  ")
		if mErr != nil {
			return fmt.Errorf("serialise capture: %w", mErr)
		}
		if wErr := os.WriteFile(save, raw, 0o644); wErr != nil {
			return fmt.Errorf("save capture: %w", wErr)
		}
		fmt.Printf("saved the Chromium capture to %s\n\n", save)
	}

	fmt.Println("-- the installed browser against the pinned reference --")
	failed := report(checkChromiumProbe(ref, probe))

	// Now the client itself, diffed against the browser rather than against the
	// reference. This is the comparison that decides whether a solved cookie
	// survives being replayed.
	fmt.Println("\n-- this client against that same browser --")
	// Replay with the identity the solver actually presents, which is what
	// `send -solve` does. Measuring the profile default against a browser on
	// another OS would report a mismatch nothing at runtime has.
	client, err := buildClient(profile, proxy, probe.SolverUserAgent)
	if err != nil {
		return err
	}
	defer client.Close()

	ours, err := fetchCapture(ctx, client, url)
	if err != nil {
		return fmt.Errorf("capture this client's fingerprint: %w", err)
	}
	failed += report(diffCaptures(probe.Capture, *ours, profile == gofire.Chrome151))

	if failed > 0 {
		fmt.Printf("\n%d mismatch(es). Any of them can invalidate a cf_clearance issued by "+
			"this Chromium and replayed by this client.\n", failed)
		return fmt.Errorf("%d check(s) failed", failed)
	}
	fmt.Println("\nThe solver's browser and this client present the same identity.")
	return nil
}
