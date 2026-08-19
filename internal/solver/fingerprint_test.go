package solver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The probe measures the browser's own identity, not the pinned one, and reads
// the response from the network rather than the rendered document.
func TestFingerprintMeasuresTheInstalledBrowser(t *testing.T) {
	requireBrowser(t)

	var gotUA string
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user_agent":%q,"ja4":"t13d1516h2_8daaf6152771_b0da82dd1658"}`, gotUA)
	}))
	defer site.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	probe, err := Fingerprint(ctx, testOptions(t, site.URL+"/", 40*time.Second), "")
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	if probe.ChromiumMajor == 0 {
		t.Errorf("chromium_major = 0, want the installed build's major (%q)", probe.ChromiumVersion)
	}
	// The whole point: the browser answers for itself here, so the UA on the
	// wire must be its own and not the pinned Chrome 151.
	if gotUA == "" {
		t.Fatal("the endpoint saw no User-Agent")
	}
	if gotUA == probe.SolverUserAgent {
		t.Error("the probe pinned the solver's UA; it is meant to measure what is installed")
	}
	if probe.NativeUserAgent != gotUA {
		t.Errorf("native_user_agent = %q but the wire carried %q", probe.NativeUserAgent, gotUA)
	}
	// The pinned identity rides along so a caller can diff the two.
	if probe.SolverUserAgent != DefaultProfile().UserAgent {
		t.Errorf("solver_user_agent = %q", probe.SolverUserAgent)
	}
	if probe.SolverSecChUA == "" {
		t.Error("solver_sec_ch_ua was not reported")
	}

	// The capture is the endpoint's JSON, byte for byte.
	var capture map[string]any
	if err := json.Unmarshal(probe.Capture, &capture); err != nil {
		t.Fatalf("capture is not the endpoint's JSON: %v", err)
	}
	if capture["ja4"] != "t13d1516h2_8daaf6152771_b0da82dd1658" {
		t.Errorf("capture lost the endpoint's fields: %v", capture)
	}
}

// A large JSON body is exactly the case that scraping the DOM gets wrong:
// Chrome's JSON viewer wraps it in markup and truncates the visible text.
func TestFingerprintReadsTheRawBody(t *testing.T) {
	requireBrowser(t)

	filler := strings.Repeat("x", 200_000)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"filler":%q}`, filler)
	}))
	defer site.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	probe, err := Fingerprint(ctx, testOptions(t, site.URL+"/", 40*time.Second), "")
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	var capture struct {
		Filler string `json:"filler"`
	}
	if err := json.Unmarshal(probe.Capture, &capture); err != nil {
		t.Fatalf("capture did not parse: %v", err)
	}
	if len(capture.Filler) != len(filler) {
		t.Errorf("body came back %d bytes, want %d: it was read from the rendered document",
			len(capture.Filler), len(filler))
	}
}

// An endpoint that is not a fingerprint API has to be named as such, rather than
// producing a parse error somewhere downstream.
func TestFingerprintRejectsNonJSON(t *testing.T) {
	requireBrowser(t)

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>not an API</body></html>")
	}))
	defer site.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err := Fingerprint(ctx, testOptions(t, site.URL+"/", 40*time.Second), "")
	if err == nil {
		t.Fatal("Fingerprint accepted an HTML page as a capture")
	}
	if !strings.Contains(err.Error(), "fingerprint API") {
		t.Errorf("error = %v, want it to name the likely cause", err)
	}
}

func TestFingerprintReportsAnHTTPError(t *testing.T) {
	requireBrowser(t)

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer site.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err := Fingerprint(ctx, testOptions(t, site.URL+"/", 40*time.Second), "")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %v, want the status named", err)
	}
}
