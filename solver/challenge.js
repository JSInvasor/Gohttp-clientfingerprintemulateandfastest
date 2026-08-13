// Is this page still sitting on a Cloudflare challenge?
//
// The answer used to be a regex over the page title, in English:
//
//   /just a moment|attention required|checking your browser|verify you are human/i
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
// The markers below are structural instead: the challenge platform's script
// path, the form and stage elements it builds, the Turnstile iframe, and the
// _cf_chl_opt object its bootstrap defines. None of them are prose, so none of
// them move with the page's language.
//
// The title check stays as a second opinion — it costs one CDP round trip and
// catches an interstitial whose markup changed but whose wording did not.

// CHALLENGE_TITLE_RE is the wording half, kept for the fallback path. The
// non-English entries are there because a localised interstitial is exactly the
// case the markers were added for, and agreeing with them costs nothing.
export const CHALLENGE_TITLE_RE =
  /just a moment|attention required|checking your browser|verify you are human|un momento|bir dakika|einen moment|un instant|um momento|один момент|请稍候|しばらく/i;

export function isChallengeTitle(title) {
  return CHALLENGE_TITLE_RE.test(String(title || ""));
}

// detectChallengeInPage runs inside the page, so it is serialised and evaluated
// in the browser: it can close over nothing and must reference only what the
// document provides.
//
// Returns true when the page carries any Cloudflare challenge structure. False
// is not proof of a solved page — it is only the absence of these markers — so
// the caller pairs it with the title check before deciding to stop waiting.
export function detectChallengeInPage() {
  const selectors = [
    "#challenge-form",
    "#challenge-running",
    "#challenge-stage",
    "#cf-challenge-running",
    "#turnstile-wrapper",
    'script[src*="/cdn-cgi/challenge-platform/"]',
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
}
