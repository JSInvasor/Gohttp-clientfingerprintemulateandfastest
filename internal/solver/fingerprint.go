package solver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Measures the real fingerprint of the Chromium this repo drives.
//
// Why this exists: the solver earns cf_clearance with a real browser and gofire
// replays it with an emulated ClientHello. Cloudflare binds the cookie to the
// issuing session's fingerprint, so those two have to be the same browser. That
// used to be an assumption maintained by hand — the solver pinned a UA in a
// comment and nothing checked it. This makes it measurable: `fpcheck
// -via-chromium` runs this, then diffs the result against what the Go client
// emits.
//
// Deliberately does NOT override the UA. The solve pins one so the session
// matches gofire; here the question is "what browser is actually installed on
// this box", so the browser answers for itself. The pinned identity rides along
// as SolverUserAgent and SolverSecChUA so a caller can check both.
//
// The TLS and HTTP/2 layers are unaffected by that either way: they come from
// BoringSSL and Chromium's own HTTP/2 stack, which no page-level override can
// reach. That is precisely what makes them worth measuring.

// FingerprintProbe is what a measurement run reports.
type FingerprintProbe struct {
	ChromiumVersion string          `json:"chromium_version"`
	ChromiumMajor   int             `json:"chromium_major"`
	NativeUserAgent string          `json:"native_user_agent"`
	SolverUserAgent string          `json:"solver_user_agent"`
	SolverSecChUA   string          `json:"solver_sec_ch_ua"`
	Capture         json.RawMessage `json:"capture"`
}

// Fingerprint drives the browser to a fingerprint endpoint and returns what it
// reported, alongside the browser's own identity.
//
// The launch flags are the profile's, so this measures the same browser
// configuration a solve runs. A flag can move the TLS layer — a
// --disable-features that switches off post-quantum key agreement would change
// the ClientHello and therefore the JA4 — so measuring a differently-flagged
// browser would answer the wrong question.
//
// proxy is honoured for the same reason the solve honours it: a proxy can change
// the egress path and the TLS the far end sees.
func Fingerprint(ctx context.Context, o Options, proxy string) (*FingerprintProbe, error) {
	parsed, err := ParseProxy(proxy)
	if err != nil {
		return nil, err
	}
	l := o.launcher()

	b, err := l.launch(ctx, parsed)
	if err != nil {
		return nil, err
	}
	defer b.Close()

	tab, err := b.DefaultContext().NewTab(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Its own context: the caller's is usually spent by the time a probe
		// finishes, and a close that inherits an expired deadline never reaches
		// the browser.
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = tab.Close(cctx)
	}()

	if parsed != nil && (parsed.Username != "" || parsed.Password != "") {
		if err := tab.AuthenticateProxy(ctx, parsed.Username, parsed.Password); err != nil {
			return nil, err
		}
	}

	probe := &FingerprintProbe{
		ChromiumVersion: b.Version.Product,
		ChromiumMajor:   ChromiumMajor(b.Version.Product),
		SolverUserAgent: l.Profile.UserAgent,
		SolverSecChUA:   l.Profile.SecChUA,
	}
	// The browser's own identity, before anything is pinned over it.
	_ = tab.Evaluate(ctx, "navigator.userAgent", &probe.NativeUserAgent)

	resp, err := tab.NavigateCapturing(ctx, o.Target)
	if err != nil {
		return nil, err
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.Status, o.Target)
	}
	if !json.Valid([]byte(resp.Body)) {
		return nil, fmt.Errorf("%s did not return JSON (is it a fingerprint API?)", o.Target)
	}
	probe.Capture = json.RawMessage(resp.Body)
	return probe, nil
}
