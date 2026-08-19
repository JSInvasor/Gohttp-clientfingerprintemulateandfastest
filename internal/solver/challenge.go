package solver

import "regexp"

// Is this page still sitting on a Cloudflare challenge?
//
// The answer used to be a regex over the page title, in English:
//
//	just a moment|attention required|checking your browser|verify you are human
//
// and a title that did not match was taken as proof the challenge was over. That
// is the wrong way round. Cloudflare localises the interstitial — it follows
// Accept-Language, so a solve routed through an exit that asks for anything but
// English gets "Un momento…", "Bir dakika…", "Einen Moment…" — and it rewords it
// between releases. Either way the title stops matching, the solver concludes it
// was never challenged, and it gives up in under a second on a challenge it had
// two minutes of budget to solve. The failure looks identical to a site that
// simply has no UAM, which is why it would never be noticed.
//
// So there are two probes. The structural one below is language-independent and
// decides; the title is the cheap second opinion that catches an interstitial
// whose markup changed but whose wording did not.

// challengeTitleRe is the wording half. The non-English entries are there
// because a localised interstitial is exactly the case the markers were added
// for, and agreeing with them costs nothing.
var challengeTitleRe = regexp.MustCompile(
	`(?i)just a moment|attention required|checking your browser|verify you are human|` +
		`un momento|bir dakika|einen moment|un instant|um momento|один момент|请稍候|しばらく`)

// IsChallengeTitle reports whether a page title reads like an interstitial.
func IsChallengeTitle(title string) bool {
	return challengeTitleRe.MatchString(title)
}

// IsChallengeStatus reports whether an edge answering a document with this
// status is refusing rather than serving.
//
// This is the half of the detection that belongs to no vendor. Everything else
// in this file describes Cloudflare — its element ids, its bootstrap global, its
// wording — and against anything else those all read as the absence of a
// challenge, which is the loudest way to be wrong: the solver concludes it was
// never challenged and gives up in about a second with its whole budget left.
// That is not hypothetical. A Turkish WAF serving a proof-of-work interstitial
// under its own markup (`#capca-grid`, `/__ka/verify`, an inline script and no
// `src` to match) trips none of the markers and none of the wording, and the
// only thing about it that says "this is not the page you asked for" is the 403
// it arrives with.
//
// 401 is not here. It is an origin asking for credentials, which is a thing to
// report rather than a thing to wait out — nothing a browser does unattended
// turns a 401 into a 200. The three that are here all describe an edge that
// expects the client to do something and come back.
func IsChallengeStatus(status int) bool {
	switch status {
	case 403, // the common interstitial answer, Cloudflare and otherwise
		429, // rate limited: a wait may genuinely clear it
		503: // "under attack", the other Cloudflare answer
		return true
	}
	return false
}

// DetectChallengeScript runs inside the page and answers whether it carries any
// Cloudflare challenge structure.
//
// The markers are structural rather than prose — the challenge platform's
// orchestrate script, the form and stage elements it builds, the Turnstile
// iframe, and the _cf_chl_opt object its bootstrap defines — so none of them
// move with the page's language.
//
// False here is not proof of a solved page, only the absence of these markers,
// so the caller pairs it with the title check before deciding to stop waiting.
//
// The script selector is where structural stops being unambiguous, and it is
// worth the exclusion it carries. Matching the whole of
// /cdn-cgi/challenge-platform/ was the first cut and is wrong in the direction
// that costs most: Cloudflare injects its JS-detection script
// (/cdn-cgi/challenge-platform/scripts/jsd/main.js) into ordinary 200 responses
// on any zone with bot management on, challenge or not. Matching it makes a
// cleared page read as challenged for as long as the caller is willing to wait —
// and the caller waits until its deadline, so a site that never challenges would
// burn the whole budget, twice, and report no_clearance. A false negative here
// only costs the title check.
const DetectChallengeScript = `(() => {
  const selectors = [
    "#challenge-form",
    "#challenge-running",
    "#challenge-stage",
    "#cf-challenge-running",
    "#turnstile-wrapper",
    'script[src*="/cdn-cgi/challenge-platform/"]:not([src*="/scripts/jsd/"])',
    'iframe[src*="challenges.cloudflare.com"]',
  ];
  for (const selector of selectors) {
    try {
      if (document.querySelector(selector)) return true;
    } catch {}
  }
  // The bootstrap script defines this before it builds anything, so it is the
  // earliest signal available — and the one that survives a challenge whose
  // element ids change.
  return typeof window._cf_chl_opt === "object" && window._cf_chl_opt !== null;
})()`

// IdentityScript reads back the half of the identity that no header carries, in
// one round trip.
//
// navigator.languages is here because it is the half of the language the wire
// cannot show: a solve where the header and this disagree is a browser
// advertising a language it does not list, which no ordinary Chrome install
// produces. The timezone rides along rather than being assumed from what was
// pinned — Intl answers it from ICU, and the value an unconfigured container
// reports is "Etc/Unknown", which no installed browser produces. Reading them
// back is how a run says whether the pin took.
const IdentityScript = `({
  userAgent: navigator.userAgent,
  languages: navigator.languages,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
})`
