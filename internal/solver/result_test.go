package solver

import "testing"

// A retry that fails to launch, or lands on a harder challenge variant, must not
// erase what the first attempt collected.
func TestBetterResultKeepsTheBestAttempt(t *testing.T) {
	cleared := &Result{Status: StatusOK, CookieList: []Cookie{{Name: "cf_clearance"}}}
	someCookies := &Result{Status: StatusNoClearance, CookieList: []Cookie{{Name: "__cf_bm"}, {Name: "x"}}}
	oneCookie := &Result{Status: StatusNoClearance, CookieList: []Cookie{{Name: "__cf_bm"}}}
	empty := &Result{Status: StatusError}

	if got := betterResult(cleared, someCookies); got != cleared {
		t.Error("a clearance lost to a result with more cookies")
	}
	if got := betterResult(someCookies, cleared); got != cleared {
		t.Error("a clearance did not beat a no_clearance result")
	}
	if got := betterResult(oneCookie, someCookies); got != someCookies {
		t.Error("more cookies did not win between two no_clearance results")
	}
	if got := betterResult(someCookies, empty); got != someCookies {
		t.Error("an empty retry erased an attempt that had collected cookies")
	}
	if got := betterResult(nil, empty); got != empty {
		t.Error("the first attempt was discarded")
	}
	if got := betterResult(nil, nil); got != nil {
		t.Error("two nils produced something")
	}
}

// A navigation that fails after the cookie was set is the ordinary case, not an
// exotic one: a challenge that clears navigates the frame out from under
// whatever was reading it.
func TestStatusAfterThrowReportsASalvagedSolve(t *testing.T) {
	salvaged := &Result{Status: StatusOK, CookieList: []Cookie{{Name: "cf_clearance"}}}
	if got := statusAfterThrow(salvaged); got != StatusOK {
		t.Errorf("a salvaged clearance reported %q, want ok", got)
	}
	if got := statusAfterThrow(&Result{Status: StatusNoClearance}); got != StatusError {
		t.Errorf("a salvage with no clearance reported %q, want error", got)
	}
	if got := statusAfterThrow(nil); got != StatusError {
		t.Errorf("nothing salvaged reported %q, want error", got)
	}
}

// On a zone with no UAM the __cf_bm the challenge page set is the whole of what
// a solve can produce, and it used to be thrown away with the error.
func TestExhaustedResultReportsWhatWasCollected(t *testing.T) {
	defaults := exhaustedDefaults{
		URL:            "https://target.example/",
		UserAgent:      defaultUA,
		AcceptLanguage: "en-US,en;q=0.9",
	}

	// Nothing collected: an error, and the reason it ended.
	got := exhaustedResult(&Result{Status: StatusError, Error: "navigation timeout"}, defaults)
	if got.Status != StatusError || got.Error != "navigation timeout" {
		t.Errorf("empty attempt = %+v, want an error carrying its cause", got)
	}
	if got := exhaustedResult(nil, defaults); got.Status != StatusError || got.Error != "solve failed" {
		t.Errorf("no attempt at all = %+v", got)
	}

	// Cookies collected by an attempt that failed: reported, whichever way that
	// attempt ended, with the error kept beside them.
	failed := &Result{
		Status:     StatusError,
		Error:      "navigation timeout",
		CookieList: []Cookie{{Name: "__cf_bm", Value: "bm1"}},
		Cookies:    "__cf_bm=bm1",
	}
	got = exhaustedResult(failed, defaults)
	if got.Status != StatusNoClearance {
		t.Errorf("status = %q, want no_clearance: the jar was not empty", got.Status)
	}
	if len(got.CookieList) != 1 || got.CookieList[0].Name != "__cf_bm" {
		t.Errorf("cookies = %+v, want the salvaged __cf_bm", got.CookieList)
	}
	if got.Error != "navigation timeout" {
		t.Errorf("error = %q, want it kept beside the cookies", got.Error)
	}
	// Defaults fill in what a failed attempt never reached.
	if got.URL != defaults.URL || got.UserAgent != defaults.UserAgent {
		t.Errorf("defaults did not fill in: %+v", got)
	}
	if got.AcceptLanguage != defaults.AcceptLanguage {
		t.Errorf("accept_language = %q, want the language the browser was launched to send", got.AcceptLanguage)
	}
}
