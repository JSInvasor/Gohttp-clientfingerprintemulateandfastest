package solver

// What a solve reports, what an attempt is worth, and what a run says when the
// attempts are spent.
//
// These are pure decisions about a value, and both of the bugs they encode were
// silent, and both threw away a cookie that had already been earned and paid
// for.

// Status is how a solve ended.
const (
	// StatusOK means the target let this session through: either it issued a
	// cf_clearance, or it stopped refusing and started serving. The second half
	// is what makes this mean anything off Cloudflare — an edge that answers a
	// proof-of-work interstitial with a 403 and then the page with a 200 has
	// cleared the session just as surely, and it never names a cookie.
	StatusOK = "ok"
	// StatusNoClearance means the run collected cookies but never got through —
	// a zone with Bot Fight Mode and no UAM produces exactly this, and the
	// __cf_bm it sets is worth reporting.
	StatusNoClearance = "no_clearance"
	// StatusError means the run has nothing to hand over.
	StatusError = "error"
)

// Cookie is one solved cookie, in the shape the Go side caches and replays.
type Cookie struct {
	Name    string  `json:"name"`
	Value   string  `json:"value"`
	Domain  string  `json:"domain"`
	Expires float64 `json:"expires"`
}

// Result is one exit's answer. The JSON tags are the wire format `send` already
// caches, kept byte-compatible with what the Node solver printed so an existing
// solve cache stays readable.
type Result struct {
	Exit           string   `json:"exit,omitempty"`
	Status         string   `json:"status"`
	URL            string   `json:"url,omitempty"`
	UserAgent      string   `json:"user_agent,omitempty"`
	AcceptLanguage string   `json:"accept_language,omitempty"`
	PageLanguages  []string `json:"page_languages,omitempty"`
	Timezone       string   `json:"timezone,omitempty"`
	Cookies        string   `json:"cookies,omitempty"`
	CookieList     []Cookie `json:"cookie_list,omitempty"`
	DurationMS     int64    `json:"duration_ms,omitempty"`
	Attempts       int      `json:"attempts,omitempty"`
	ChromiumVer    string   `json:"chromium_version,omitempty"`
	ChromiumMajor  int      `json:"chromium_major,omitempty"`
	Proxy          string   `json:"proxy"`
	LaunchMS       int64    `json:"launch_ms,omitempty"`
	// Error is why the attempt ended early. It is set on StatusError, and also
	// beside a usable result an attempt threw its way out of — nothing reads it
	// on a successful line, and throwing it away would lose the only record of
	// why the attempt ended where it did.
	Error string `json:"error,omitempty"`
}

// rank orders two attempts: a clearance beats anything, then more cookies, then
// anything at all over nothing.
//
// This is what makes the retry a second chance rather than a replacement. A
// retry that fails to launch, or lands on a harder challenge variant, must not
// erase what the first attempt collected.
func rank(r *Result) int {
	if r == nil {
		return -1
	}
	if r.Status == StatusOK {
		return 1_000_000
	}
	return len(r.CookieList)
}

// betterResult keeps the more valuable of two attempts.
func betterResult(a, b *Result) *Result {
	if rank(b) > rank(a) {
		return b
	}
	if a == nil {
		return b
	}
	return a
}

// statusAfterThrow decides what an attempt that failed should report, given
// whatever its jar still held.
//
// The status used to be pinned to error regardless, and that made the one case
// the salvage exists for the one case it could not report. Navigation is what
// fails here, and the failure is ordinary rather than exotic: a challenge that
// clears navigates the frame out from under it, surfacing as net::ERR_ABORTED or
// a detached context — after cf_clearance has been set. So the jar held the
// cookie, the line said error, and a successful solve was reported as an aborted
// run.
func statusAfterThrow(salvaged *Result) string {
	if salvaged != nil && salvaged.Status == StatusOK {
		return StatusOK
	}
	return StatusError
}

// exhaustedDefaults are what the caller knows and a failed attempt may not have
// reached.
type exhaustedDefaults struct {
	URL            string
	UserAgent      string
	AcceptLanguage string
}

// exhaustedResult shapes the answer a run gives once every attempt is spent.
//
// It reports whatever the best attempt collected, whichever way that attempt
// ended. The previous version keyed on status alone — only a no_clearance result
// had its cookies forwarded — so an attempt that failed was reported as a bare
// error with the jar discarded. Ranking attempts by how many cookies they
// collected was then work done for nothing: the winner's cookies were dropped
// one function later unless its status happened to be the right one. On a zone
// with no UAM the __cf_bm the challenge page set is the whole of what a solve can
// produce, and a navigation that timed out after it arrived turned that into
// "solver: navigation timeout" and no cookie at all.
func exhaustedResult(last *Result, d exhaustedDefaults) *Result {
	if last == nil || len(last.CookieList) == 0 {
		msg := "solve failed"
		if last != nil && last.Error != "" {
			msg = last.Error
		}
		return &Result{Status: StatusError, Error: msg}
	}
	out := &Result{
		Status:         StatusNoClearance,
		URL:            firstNonEmpty(last.URL, d.URL),
		UserAgent:      firstNonEmpty(last.UserAgent, d.UserAgent),
		AcceptLanguage: firstNonEmpty(last.AcceptLanguage, d.AcceptLanguage),
		PageLanguages:  last.PageLanguages,
		Timezone:       last.Timezone,
		Cookies:        last.Cookies,
		CookieList:     last.CookieList,
		Error:          last.Error,
	}
	if out.PageLanguages == nil {
		out.PageLanguages = []string{}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
