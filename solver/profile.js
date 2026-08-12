// Shared browser identity for everything in solver/.
//
// This file exists because the solver and the Go client have to agree on which
// browser they are. Cloudflare binds cf_clearance to the (UA, JA3/JA4, IP) of
// the session that was issued it. The solver drives a real Chromium to earn the
// cookie; gofire then replays that cookie with its own emulated ClientHello. If
// the two are not the same browser, the cookie is issued to one identity and
// presented by another, and it dies — usually within seconds under load, and
// with no diagnostic beyond a wall of 403s.
//
// Keeping the UA, its Client Hints and the launch flags in one module means
// index.js (which solves) and fingerprint.js (which measures) cannot drift
// apart, and `fpcheck -via-chromium` measures the browser the solver actually
// launches rather than a differently-configured one.

// TARGET_UA must match gofire's Chrome151UserAgent in headers.go.
//
// `fpcheck -via-chromium` checks this for you and fails when it drifts; that
// check is the reason this constant is worth pinning rather than leaving to
// whatever Chromium happens to report. Override with SOLVER_UA when your box
// runs a different Chrome major and you have re-pinned the Go profile to match.
export const TARGET_UA =
  process.env.SOLVER_UA ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";

// The Client Hint half of the same identity. These must match gofire's
// Chrome151SecChUa and the Sec-Ch-Ua-Mobile / Sec-Ch-Ua-Platform defaults in
// headers.go.
//
// Pinning the UA string alone is not enough, and getting this wrong is worse
// than leaving the UA stale. page.setUserAgent(ua) without the metadata
// argument does not leave Chromium's native hints in place — it clears them.
// Measured against the Chromium in this repo's toolchain:
//
//   no setUserAgent:  sec-ch-ua: "Chromium";v="141", "Not?A_Brand";v="8"
//                     sec-ch-ua-platform: "Linux"
//   setUserAgent(ua): sec-ch-ua: (header absent)
//                     sec-ch-ua-platform: (header absent)
//                     navigator.userAgentData.brands: []
//
// A request claiming Chrome 151 while sending no Client Hints at all is a
// combination no real Chrome produces, and it is the session Cloudflare binds
// cf_clearance to. userAgentMetadata() below rebuilds the hints so the solved
// session presents the same identity gofire replays with.
export const TARGET_SEC_CH_UA =
  process.env.SOLVER_SEC_CH_UA ||
  `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`;

// Sec-Ch-Ua-Platform, without the quotes the header carries. Windows 10 and 11
// both report "Windows"; the platformVersion is what separates them (1-14 is
// Windows 10, 15+ is Windows 11), and the pinned UA says Windows NT 10.0.
export const TARGET_PLATFORM = process.env.SOLVER_PLATFORM || "Windows";
export const TARGET_PLATFORM_VERSION =
  process.env.SOLVER_PLATFORM_VERSION || "10.0.0";

// LAUNCH_ARGS and CONNECT_OPTIONS are shared so the fingerprint probe measures
// the same browser configuration the solver runs. Launch flags can move the
// TLS layer — a --disable-features that switches off post-quantum key agreement
// would change the ClientHello and therefore the JA4 — so measuring a
// differently-flagged browser would answer the wrong question.
export const LAUNCH_ARGS = [
  "--no-sandbox",
  "--disable-setuid-sandbox",
  "--disable-dev-shm-usage",
  "--disable-gpu",
  "--disable-blink-features=AutomationControlled",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-features=IsolateOrigins,site-per-process",
  "--window-size=1920,1080",
];

export const CONNECT_OPTIONS = {
  headless: false,
  turnstile: true,
  args: LAUNCH_ARGS,
  connectOption: { defaultViewport: null },
  disableXvfb: false,
  ignoreAllFlags: false,
};

// chromiumMajor extracts the major version from a browser.version() string
// such as "HeadlessChrome/151.0.7204.50". Returns 0 when it cannot be parsed.
export function chromiumMajor(version) {
  const m = String(version || "").match(/(\d+)\.\d+\.\d+\.\d+/);
  return m ? parseInt(m[1], 10) : 0;
}

// chromeVersionFromUA pulls the full Chrome version out of a User-Agent, e.g.
// "151.0.0.0". Returns "" when there is no Chrome/N token.
export function chromeVersionFromUA(ua) {
  const m = String(ua || "").match(/Chrome\/(\d+(?:\.\d+)*)/);
  return m ? m[1] : "";
}

// parseSecChUa turns a sec-ch-ua header value into the brand list CDP wants:
//
//   '"Not=A?Brand";v="99", "Google Chrome";v="151"'
//     -> [{brand: "Not=A?Brand", version: "99"}, {brand: "Google Chrome", version: "151"}]
//
// Order is preserved. Chrome 151 puts the greased entry first and UAM checks
// the ordering, so this must not sort.
export function parseSecChUa(value) {
  const brands = [];
  const re = /"((?:[^"\\]|\\.)*)"\s*;\s*v\s*=\s*"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(String(value || ""))) !== null) {
    brands.push({ brand: m[1], version: m[2] });
  }
  return brands;
}

// A greased brand is the deliberately-mangled entry Chrome rotates each release
// ("Not=A?Brand", "Not;A=Brand", "Not.A/Brand", ...). It carries its own
// unrelated version, so it is exempt from the consistency check below.
function isGreasedBrand(brand) {
  return /[^A-Za-z0-9 ]/.test(brand);
}

// userAgentMetadata builds the Emulation.UserAgentMetadata that has to accompany
// a UA override, and refuses to build an inconsistent one.
//
// Every real brand's version must equal the UA's Chrome major. Emitting a UA
// that says 151 alongside hints that say something else is precisely the signal
// this whole module exists to avoid, and a silent mismatch here would cost a
// full solve to discover. Throwing means SOLVER_UA and SOLVER_SEC_CH_UA have to
// be re-pinned together.
export function userAgentMetadata(
  ua = TARGET_UA,
  secChUa = TARGET_SEC_CH_UA,
  platform = TARGET_PLATFORM,
  platformVersion = TARGET_PLATFORM_VERSION
) {
  const fullVersion = chromeVersionFromUA(ua);
  if (!fullVersion) {
    throw new Error(`cannot build Client Hints: no Chrome/<version> in UA ${JSON.stringify(ua)}`);
  }
  const major = fullVersion.split(".")[0];

  const brands = parseSecChUa(secChUa);
  if (brands.length === 0) {
    throw new Error(`cannot build Client Hints: no brands parsed from ${JSON.stringify(secChUa)}`);
  }
  for (const { brand, version } of brands) {
    if (!isGreasedBrand(brand) && version !== major) {
      throw new Error(
        `Client Hint drift: sec-ch-ua says ${brand} v${version} but the UA says Chrome ${major}. ` +
          `Re-pin SOLVER_UA and SOLVER_SEC_CH_UA together.`
      );
    }
  }

  // fullVersionList carries the four-part version; brands carries the major
  // only, which is what sec-ch-ua puts on the wire.
  const fullVersionList = brands.map(({ brand, version }) => ({
    brand,
    version: isGreasedBrand(brand) ? `${version}.0.0.0` : fullVersion,
  }));

  const windows = /Windows/i.test(ua) || platform === "Windows";
  return {
    brands,
    fullVersionList,
    fullVersion,
    platform,
    platformVersion,
    architecture: "x86",
    bitness: /Win64|x64|x86_64/.test(ua) || windows ? "64" : "",
    model: "",
    mobile: false,
    wow64: false,
  };
}
