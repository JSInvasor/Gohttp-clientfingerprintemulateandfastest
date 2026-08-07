package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

// stubSolverDir writes a fingerprint.js that prints out verbatim, plus the
// node_modules directory runChromiumProbe checks for.
//
// Stubbing the script rather than launching a real browser is deliberate: this
// exercises the part that can actually be wrong in CI — process invocation,
// output parsing, error propagation and the comparison logic — without needing
// Chromium, a display, or network. Whether Chromium itself launches is what the
// command reports at runtime.
func stubSolverDir(t *testing.T, out string) string {
	t.Helper()
	dir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}

	script := "process.stdout.write(" + goStringToJS(out) + ");\n"
	if err := os.WriteFile(filepath.Join(dir, "fingerprint.js"), []byte(script), 0o644); err != nil {
		t.Fatalf("write fingerprint.js: %v", err)
	}
	return dir
}

// goStringToJS renders s as a JavaScript string literal.
func goStringToJS(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`, "\r", `\r`)
	return "'" + r.Replace(s) + "'"
}

// chromeProbeJSON wraps the committed Chrome device capture in the envelope
// solver/fingerprint.js emits, so the stub returns a realistic payload.
func chromeProbeJSON(t *testing.T, version string, major int, solverUA string) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/chrome151-windows.json")
	if err != nil {
		t.Fatalf("read capture: %v", err)
	}
	// fingerprint.js emits JSON.stringify output — one line — so compact the
	// pretty-printed fixture to match what the parser really sees.
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatalf("compact capture: %v", err)
	}
	raw = compact.Bytes()

	return `{"status":"ok",` +
		`"chromium_version":` + quote(version) + `,` +
		`"chromium_major":` + itoa(major) + `,` +
		`"native_user_agent":` + quote(gofire.Chrome151UserAgent) + `,` +
		`"solver_user_agent":` + quote(solverUA) + `,` +
		`"capture":` + string(raw) + `}`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestChromiumProbeAgreesWithProfile(t *testing.T) {
	dir := stubSolverDir(t, chromeProbeJSON(t, "HeadlessChrome/151.0.7204.50", 151, gofire.Chrome151UserAgent))

	probe, err := runChromiumProbe(context.Background(), dir, "https://tls.peet.ws/api/all", 30)
	if err != nil {
		t.Fatalf("runChromiumProbe: %v", err)
	}
	if probe.Major != 151 {
		t.Errorf("chromium major = %d, want 151", probe.Major)
	}

	for _, c := range checkChromiumProbe(gofire.ReferenceFor(gofire.Chrome151), probe) {
		if c.skipped {
			t.Logf("SKIP %s: %s", c.name, c.note)
			continue
		}
		if !c.ok() {
			t.Errorf("check %q failed against a matching browser\n want: %s\n got:  %s",
				c.name, c.want, c.got)
		}
	}
}

// TestChromiumProbeCatchesUADrift is the failure this command exists to catch.
//
// The solver pinned Chrome 147 while the Go profile moved to 151 — exactly the
// state this repo was in. cf_clearance is bound to the issuing session's UA, so
// the cookie is earned as one browser and presented as another: it works once,
// then dies under load, and looks like a solver bug rather than a version pin.
func TestChromiumProbeCatchesUADrift(t *testing.T) {
	const staleUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
	dir := stubSolverDir(t, chromeProbeJSON(t, "HeadlessChrome/151.0.7204.50", 151, staleUA))

	probe, err := runChromiumProbe(context.Background(), dir, "https://example.com", 30)
	if err != nil {
		t.Fatalf("runChromiumProbe: %v", err)
	}

	var found bool
	for _, c := range checkChromiumProbe(gofire.ReferenceFor(gofire.Chrome151), probe) {
		if c.name != "solver.user_agent" {
			continue
		}
		found = true
		if c.ok() {
			t.Error("a solver pinned to Chrome 147 passed against a Chrome 151 profile")
		}
	}
	if !found {
		t.Error("no solver.user_agent check ran")
	}
}

// TestChromiumProbeCatchesJA4Drift covers the harder half: the box has a
// Chromium whose TLS layer differs from the profile's. The cookie is bound to
// the JA4 too, so this kills it just as surely as a UA mismatch — but the fix is
// re-pinning the Go profile, not editing a string.
func TestChromiumProbeCatchesJA4Drift(t *testing.T) {
	payload := chromeProbeJSON(t, "HeadlessChrome/146.0.7000.10", 146, gofire.Chrome151UserAgent)
	// Chrome 146 predates the ML-DSA signature algorithms, which moved JA4_c.
	payload = mustReplace(t, payload,
		`"ja4":"t13d1516h2_8daaf6152771_806a8c22fdea"`,
		`"ja4":"t13d1516h2_8daaf6152771_d8a2da3f94cd"`)
	dir := stubSolverDir(t, payload)

	probe, err := runChromiumProbe(context.Background(), dir, "https://example.com", 30)
	if err != nil {
		t.Fatalf("runChromiumProbe: %v", err)
	}

	var found bool
	for _, c := range checkChromiumProbe(gofire.ReferenceFor(gofire.Chrome151), probe) {
		if c.name == "chromium.ja4" {
			found = true
			if c.ok() {
				t.Error("a Chromium with a different JA4 passed against the profile")
			}
		}
		// The version difference alone must not fail: Chrome's TLS layer was
		// unchanged across several releases, so the JA4 check is what decides.
		if c.name == "chromium.version" && !c.skipped {
			t.Errorf("chromium.version was compared rather than reported; a version "+
				"difference is only meaningful via the JA4 (got %q)", c.got)
		}
	}
	if !found {
		t.Error("no chromium.ja4 check ran")
	}
}

func TestChromiumProbeReportsScriptError(t *testing.T) {
	dir := stubSolverDir(t, `{"status":"error","error":"could not find Chrome binary"}`)

	_, err := runChromiumProbe(context.Background(), dir, "https://example.com", 30)
	if err == nil {
		t.Fatal("expected an error from a failing probe")
	}
	if !strings.Contains(err.Error(), "could not find Chrome binary") {
		t.Errorf("error %q does not carry the script's message", err)
	}
}

// TestChromiumProbeRequiresInstall checks the missing-dependency path names the
// fix. Without it the failure is a Node module-resolution stack trace.
func TestChromiumProbeRequiresInstall(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fingerprint.js"), []byte("//"), 0o644); err != nil {
		t.Fatalf("write fingerprint.js: %v", err)
	}

	_, err := runChromiumProbe(context.Background(), dir, "https://example.com", 30)
	if err == nil {
		t.Fatal("expected an error when node_modules is absent")
	}
	if !strings.Contains(err.Error(), "npm install") {
		t.Errorf("error %q does not tell the operator to run npm install", err)
	}
}

func TestChromiumProbeIgnoresStrayOutput(t *testing.T) {
	payload := "some dependency logged this\n" +
		chromeProbeJSON(t, "HeadlessChrome/151.0.7204.50", 151, gofire.Chrome151UserAgent) + "\n"
	dir := stubSolverDir(t, payload)

	probe, err := runChromiumProbe(context.Background(), dir, "https://example.com", 30)
	if err != nil {
		t.Fatalf("runChromiumProbe: %v", err)
	}
	if probe.Major != 151 {
		t.Errorf("chromium major = %d, want 151", probe.Major)
	}
}

func TestMajorFromUA(t *testing.T) {
	for _, tc := range []struct {
		ua   string
		want int
	}{
		{gofire.Chrome151UserAgent, 151},
		{gofire.SafariIOS18UserAgent, 0}, // no Chrome/N token
		{"Chrome/", 0},
		{"", 0},
	} {
		if got := majorFromUA(tc.ua); got != tc.want {
			t.Errorf("majorFromUA(%.40q) = %d, want %d", tc.ua, got, tc.want)
		}
	}
}

// mustReplace substitutes old for new and fails when nothing matched.
//
// A plain strings.Replace that silently misses turns a regression test into one
// that asserts nothing: the payload stays correct, the check passes, and the
// test reports success for a case it never exercised. That happened here — the
// fixture is pretty-printed but the probe envelope is compacted, so a pattern
// written with a space after the colon matched nothing.
func mustReplace(t *testing.T, s, old, new string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("fixture does not contain %q; the test would assert nothing", old)
	}
	return strings.Replace(s, old, new, 1)
}
