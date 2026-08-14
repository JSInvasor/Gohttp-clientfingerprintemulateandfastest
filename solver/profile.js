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

// TARGET_UA must match the UA gofire replays with — Chrome151LinuxUserAgent in
// headers.go, which is the same Chrome 151 identity with the OS token this box
// actually runs.
//
// Claiming Windows was measurably wrong here. The headers said Windows while
// the JS environment said otherwise, and a challenge reads both:
//
//   navigator.platform          Linux x86_64   (real Chrome on Windows: Win32)
//   fonts                       Calibri and Segoe UI absent, DejaVu Sans present
//
// No page-level override fixes that honestly — patching navigator.platform
// leaves its own tells, exactly as the plugins shim in index.js did. The TLS
// and HTTP/2 layers are untouched by the choice: BoringSSL sends the same
// ClientHello on every platform, so the pinned JA4 and Akamai fingerprint stay
// valid either way. Only the OS token and the platform hint move.
//
// Set SOLVER_UA (and SOLVER_SEC_CH_UA, SOLVER_PLATFORM) when solving from a
// machine whose OS or Chrome major differs; `fpcheck -via-chromium` checks the
// pin for you and fails when it drifts.
export const TARGET_UA =
  process.env.SOLVER_UA ||
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";

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

// Sec-Ch-Ua-Platform, without the quotes the header carries, and the
// platformVersion that accompanies it. These must agree with the OS token in
// TARGET_UA — that pairing is checked in userAgentMetadata().
//
// platformVersion is empty on Linux, and that is not an omission. Chrome only
// populates it on Windows, macOS and Android; asked for high-entropy hints on
// Linux a real browser answers "". Measured here against an untouched Chromium:
//
//   {"platform":"Linux","platformVersion":"", ...}
//
// Filling in a kernel release would be a value no Chrome on Linux reports.
export const TARGET_PLATFORM = process.env.SOLVER_PLATFORM || "Linux";
export const TARGET_PLATFORM_VERSION =
  process.env.SOLVER_PLATFORM_VERSION ?? (TARGET_PLATFORM === "Linux" ? "" : "10.0.0");

// TARGET_LANG is the Accept-Language the solve advertises, and like the UA it
// has to be the one gofire replays with — send passes its own value in through
// SOLVER_LANG so the two cannot drift.
//
// It was previously nothing at all: Chromium sent whatever the box's locale
// produced. On the usual en-US image that happened to match gofire's default and
// nobody noticed. On a localised image it does not, and it breaks two things at
// once. The replay advertises a language the solve never did — one more leg of
// the handover that silently differs — and index.js's navigator.languages shim
// hardcoded ["en-US", "en"], so the page object contradicted the browser's own
// header. That shim exists to remove exactly that contradiction; on a de_DE or
// tr_TR box it was manufacturing it.
//
// Pinning it here also makes the README's advice actionable rather than
// aspirational: match the language to where the exit is, and both halves of the
// handover follow.
export const TARGET_LANG = process.env.SOLVER_LANG || "en-US,en;q=0.9";

// languageList turns an Accept-Language header into the array
// navigator.languages reports: quality values dropped, order kept, duplicates
// removed. "en-US,en;q=0.9" -> ["en-US", "en"].
export function languageList(header) {
  const tags = String(header || "")
    .split(",")
    .map((part) => part.split(";")[0].trim())
    .filter(Boolean);
  return [...new Set(tags)];
}

// primaryLanguage is the first tag, which is what --lang takes.
export function primaryLanguage(header) {
  return languageList(header)[0] || "";
}

// preferenceList turns an Accept-Language header into what --accept-lang and
// CDP's Emulation.setUserAgentOverride both want, which is not an
// Accept-Language header: the language *preference list*, the codes in order
// with no quality values. Chromium generates the header from it, and
// navigator.languages reports it back almost verbatim.
//
// Handing it a finished header instead makes it read the q-values as part of the
// codes. Measured against Chrome 151.0.7922.108 with
// --accept-lang=en-US,en;q=0.9:
//
//   accept-language: en-US,en;q=0.9,en;q=0.9;q=0.8
//
// and against Chromium 141 through setUserAgentOverride with the same string,
// where it is navigator.languages that takes the damage:
//
//   accept-language: en-US,en;q=0.9;q=0.9
//   navigator.languages: ["en-US", "en;q=0.9"]
//
// So: codes only. What is emphatically *not* dropped is a tag implied by an
// earlier one — "en" after "en-US". This used to remove it, on the reasoning
// that Chrome re-adds the base language when it builds the header. It does, and
// that is why the bug was invisible on the wire and expensive off it. Measured,
// Chromium 141, one value per row:
//
//   preference list   header sent      navigator.languages
//   en-US             en-US,en;q=0.9   ["en-US"]
//   en-US,en          en-US,en;q=0.9   ["en-US", "en"]
//
// Identical headers, different page objects — and ["en-US"] beside a header
// advertising "en" is a contradiction no ordinary Chrome shows, on the one
// request that earns cf_clearance. The list is passed through whole so the two
// halves agree.
export function preferenceList(header) {
  return languageList(header).join(",");
}

// LAUNCH_ARGS and CONNECT_OPTIONS are shared so the fingerprint probe measures
// the same browser configuration the solver runs. Launch flags can move the
// TLS layer — a --disable-features that switches off post-quantum key agreement
// would change the ClientHello and therefore the JA4 — so measuring a
// differently-flagged browser would answer the wrong question.
export const LAUNCH_ARGS = [
  "--no-sandbox",
  "--disable-setuid-sandbox",
  "--disable-dev-shm-usage",
  "--disable-blink-features=AutomationControlled",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-features=IsolateOrigins,site-per-process",
  "--window-size=1920,1080",
  // Software WebGL. A headless box has no GPU, and without these the canvas
  // hands back no WebGL context at all — measured here, with and without
  // --disable-gpu, which turned out not to be the cause:
  //
  //   as shipped (--disable-gpu)   -> NO WEBGL
  //   --use-gl=angle --use-angle=swiftshader
  //                                -> ANGLE (Google, Vulkan 1.3.0 (SwiftShader
  //                                   Device (Subzero)), SwiftShader driver)
  //
  // Every real Chrome has a WebGL context. A browser that has none is a far
  // stronger signal than one rendering in software, which is what any VM or
  // RDP session looks like. --disable-gpu is gone because it is redundant next
  // to an explicit software renderer and only invites the two to disagree.
  "--use-gl=angle",
  "--use-angle=swiftshader",
  // The language, from one value, in the form each flag actually takes.
  //
  // --accept-lang is the preference list, not the header: see preferenceList
  // for what handing it a finished header does. --lang is the UI locale, and it
  // takes one tag; Intl and the date formats follow it, so it is set too rather
  // than leaving the UI disagreeing with the language being asked for.
  //
  // These pin the header, and only the header. Measured on Chromium 141, a
  // fresh profile reports navigator.languages ["en-US"] whatever these say —
  // en-US, en-US,en and no flag at all are indistinguishable in the page. The
  // page object is set where it does move, in preparePage's
  // Emulation.setUserAgentOverride, which is also where it can be set without
  // leaving an own property on navigator. These stay because the flags apply
  // from process start, which is earlier than any override can reach.
  `--accept-lang=${preferenceList(TARGET_LANG)}`,
  `--lang=${primaryLanguage(TARGET_LANG) || "en-US"}`,
];

export const CONNECT_OPTIONS = {
  headless: false,
  turnstile: true,
  args: LAUNCH_ARGS,
  connectOption: { defaultViewport: null },
  disableXvfb: false,
  ignoreAllFlags: false,
};

// parseProxyURL turns a proxy URL into the {host, port, username, password}
// shape puppeteer-real-browser wants.
//
// It builds --proxy-server=${host}:${port}, and Chrome only assumes HTTP when
// the value carries no scheme — so anything that is not a plain HTTP proxy has
// to keep its scheme inside the host field or a SOCKS proxy is silently dialled
// as HTTP. Credentials are handled separately, by page.authenticate.
export function parseProxyURL(raw) {
  if (!raw) return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`invalid proxy URL ${JSON.stringify(raw)}: want scheme://[user:pass@]host:port`);
  }
  const scheme = u.protocol.replace(/:$/, "").toLowerCase();
  if (!u.hostname) throw new Error(`proxy URL ${JSON.stringify(raw)} has no host`);
  if (!u.port) throw new Error(`proxy URL ${JSON.stringify(raw)} has no port`);
  return {
    host: scheme === "http" ? u.hostname : `${scheme}://${u.hostname}`,
    port: u.port,
    username: percentDecode(u.username),
    password: percentDecode(u.password),
  };
}

// percentDecode undoes the escaping the URL parser applies to credentials, and
// keeps the raw value when there is nothing valid to undo.
//
// decodeURIComponent throws URIError on a lone '%', which a password is entitled
// to contain — the parser stores it verbatim rather than escaping it, so the
// round trip is not symmetric. Throwing there rejected a working proxy with
// "URI malformed", a message that names neither the proxy nor the field.
function percentDecode(value) {
  const raw = String(value || "");
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

// connectOptions is CONNECT_OPTIONS plus an optional proxy.
//
// Routing the solve through the same proxy the replay will use is not a
// convenience: Cloudflare binds cf_clearance to (UA, JA3/JA4, IP). A cookie
// earned from this box and replayed from an exit node is presented by an
// address it was never issued to, which fails the same way a UA mismatch does.
export function connectOptions({ proxy } = {}) {
  const parsed = parseProxyURL(proxy);
  return parsed ? { ...CONNECT_OPTIONS, proxy: parsed } : { ...CONNECT_OPTIONS };
}

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
  platformVersion = TARGET_PLATFORM_VERSION,
  browserVersion = ""
) {
  const uaVersion = chromeVersionFromUA(ua);
  if (!uaVersion) {
    throw new Error(`cannot build Client Hints: no Chrome/<version> in UA ${JSON.stringify(ua)}`);
  }
  const major = uaVersion.split(".")[0];

  // The UA string freezes the build to <major>.0.0.0 — Chrome has done that
  // since 101 — but the high-entropy hints do not. Asked for fullVersionList or
  // uaFullVersion, a real browser answers with its actual build. Measured
  // against an untouched Chromium:
  //
  //   uaFullVersion "141.0.7390.37", fullVersionList Chromium 141.0.7390.37
  //
  // Reporting <major>.0.0.0 there is a build number no Chrome ships, on a call
  // a managed challenge makes. browserVersion is browser.version(), used when
  // its major agrees with the identity being claimed; when it does not, the
  // frozen value is the safer answer and fpcheck's chromium.version check is
  // what reports the underlying mismatch.
  const realVersion = chromeVersionFromUA(browserVersion) || String(browserVersion || "").match(/\d+(?:\.\d+){3}/)?.[0] || "";
  const fullVersion = realVersion.split(".")[0] === major ? realVersion : uaVersion;

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

  // The OS token and the platform hint have to name the same system. Getting
  // this pair wrong is what made the old Windows pin detectable: the headers
  // said one OS while navigator.platform and the installed fonts said another.
  const uaPlatform = platformFromUA(ua);
  if (uaPlatform && uaPlatform !== platform) {
    throw new Error(
      `platform drift: the UA's OS token says ${uaPlatform} but the platform hint says ${platform}. ` +
        `Re-pin SOLVER_UA and SOLVER_PLATFORM together.`
    );
  }

  // fullVersionList carries the four-part version; brands carries the major
  // only, which is what sec-ch-ua puts on the wire.
  const fullVersionList = brands.map(({ brand, version }) => ({
    brand,
    version: isGreasedBrand(brand) ? `${version}.0.0.0` : fullVersion,
  }));

  return {
    brands,
    fullVersionList,
    fullVersion,
    platform,
    platformVersion,
    architecture: "x86",
    bitness: /Win64|x64|x86_64|amd64/i.test(ua) ? "64" : "",
    model: "",
    mobile: false,
    wow64: false,
  };
}

// platformFromUA reads the OS token out of a User-Agent and returns it in the
// spelling Sec-Ch-Ua-Platform uses. Returns "" when the UA names no OS it
// recognises, which leaves the caller's platform unchallenged rather than
// guessed at.
export function platformFromUA(ua) {
  const s = String(ua || "");
  if (/Windows NT/i.test(s)) return "Windows";
  if (/Android/i.test(s)) return "Android"; // before Linux: Android UAs say both
  if (/iPhone|iPad|iPod/i.test(s)) return "iOS";
  if (/Macintosh|Mac OS X/i.test(s)) return "macOS";
  if (/X11|Linux/i.test(s)) return "Linux";
  return "";
}
