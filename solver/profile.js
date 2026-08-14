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

// preferenceList turns an Accept-Language header into what --accept-lang wants,
// which is not an Accept-Language header: the language *preference list*, the
// codes in order with no quality values.
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
// So: codes only. Nothing here builds the flag from this any more —
// primaryLanguage does, for the reason expectedAcceptLanguage records — but the
// shape is still what the flag takes, and the two measurements above are the
// reason a header must never be handed to it.
export function preferenceList(header) {
  return languageList(header).join(",");
}

// expectedAcceptLanguage is the header Chromium will actually send once
// --accept-lang is set to primaryLanguage(header).
//
// It exists because everything else in this solver was keyed off the *asked for*
// value while the browser sent something else entirely, and the checks meant to
// catch that were fed the asked-for value too — so they could never fire. Three
// separate things have to agree on one request, and until now they agreed only
// on an en_US box:
//
//   the Accept-Language header      the edge reads it
//   navigator.languages             the challenge's JavaScript reads it
//   what the solve reports back     gofire replays the cookie with it
//
// The browser does not send a preference list back verbatim. Measured against
// Chromium 141.0.7390.37, one row per run, LANG/LC_ALL varied:
//
//   --accept-lang        header sent        navigator.languages
//   (absent), en_US box  en-US,en;q=0.9     ["en-US"]
//   (absent), tr_TR box  tr-TR,tr;q=0.9     ["tr-TR"]
//   en-US                en-US,en;q=0.9     ["en-US"]
//   en-US,en             en-US,en;q=0.9     ["en-US"]
//   en-US,en,de          en-US,en;q=0.9     ["en-US"]
//   tr-TR,en-US,en       tr-TR,tr;q=0.9     ["tr-TR"]
//   de,en                de                 ["de"]
//   pt-BR                pt-BR,pt;q=0.9     ["pt-BR"]
//   es-419               es-419,es;q=0.9    ["es-419"]
//
// Two things fall out of that table and both were being got wrong. Everything
// after the first entry is discarded — a list is not reproducible on the wire,
// so promising one is a lie. And the header is derived: a tag carrying a region
// gains its base language at q=0.9, a bare tag stands alone.
//
// So this is the single value the flag, the shim and the report are all built
// from, and they cannot drift from each other by construction. Whether a future
// Chromium changes the derivation is the one unknown left, and it is the one
// send's reportLanguageDrift already exists to name.
export function expectedAcceptLanguage(header) {
  const primary = primaryLanguage(header);
  if (!primary) return "";
  const base = primary.split("-")[0];
  return base && base !== primary ? `${primary},${base};q=0.9` : primary;
}

// localeEnv is the process locale a browser speaking this language would run
// under, for the half of the identity no launch flag reaches.
//
// --accept-lang moves the header and navigator.languages. It does not move ICU,
// which is what Intl answers from, and ICU follows LC_ALL/LANG. Measured on the
// same Chromium, tr_TR box throughout:
//
//   flags / env                              header          languages    Intl
//   (none)                                   tr-TR,tr;q=0.9  ["tr-TR"]    tr
//   --accept-lang=en-US                      en-US,en;q=0.9  ["en-US"]    tr
//   --accept-lang=en-US --lang=en-US         en-US,en;q=0.9  ["en-US"]    tr
//   --accept-lang=en-US  LC_ALL=en_US.UTF-8  en-US,en;q=0.9  ["en-US"]    en-US
//
// --lang buys nothing here, which is why it is not in the launch list. The
// environment is what closes it, and it does not need the locale to be generated
// on the box: this was measured on an image whose `locale -a` lists only C,
// C.utf8 and POSIX, and Chromium still answered Intl "en-US" — ICU carries its
// own data and reads the variable directly.
export function localeEnv(header) {
  const primary = primaryLanguage(header);
  if (!primary) return null;
  const posix = primary.replace(/-/g, "_");
  return {
    LANG: `${posix}.UTF-8`,
    LC_ALL: `${posix}.UTF-8`,
    LANGUAGE: languageList(header)
      .map((tag) => tag.replace(/-/g, "_"))
      .join(":"),
  };
}

// pinProcessLocale applies localeEnv() to this process, so the Chromium it
// launches inherits it.
//
// Called explicitly by each entry point rather than run on import: a module that
// rewrites the environment merely by being imported would do it to the test
// runner too, and the point of this file is that its effects are inspectable.
//
// SOLVER_PIN_LOCALE=0 leaves the box alone, for anyone who wants the machine's
// own locale to reach the browser and has read the table above.
export function pinProcessLocale(env = process.env) {
  if (env.SOLVER_PIN_LOCALE === "0") return null;
  const locale = localeEnv(TARGET_LANG);
  if (!locale) return null;
  Object.assign(env, locale);
  return locale;
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
  // --accept-lang, which was here, was removed, and is back — this time with the
  // measurement that decides it rather than an argument about parity.
  //
  // It was removed because the version of this solver that passes a live Under
  // Attack zone does not set it, and because it looked like a no-op. It is a
  // no-op, on exactly one configuration: an en_US box. Measured on Chromium
  // 141.0.7390.37, en_US box, with the flag and without it —
  //
  //   header en-US,en;q=0.9   navigator.languages ["en-US"]   Intl en-US
  //
  // byte-identical either way. So on the configuration the working version was
  // validated on, adding this changes nothing a page or the edge can see, which
  // is the whole of the parity rule.
  //
  // Off that configuration it is not a no-op, and what it removes is a
  // contradiction rather than a preference. Without it the header follows the
  // box's locale while preparePage's shim asserts navigator.languages from
  // SOLVER_LANG — so a tr_TR box sent `Accept-Language: tr-TR,tr;q=0.9` while
  // telling the challenge's own JavaScript it was ["en-US", "en"]. A browser
  // advertising one language on the wire and listing another in the page object
  // is not a browser that exists, and it was doing it on the one request that
  // earns cf_clearance.
  //
  // primaryLanguage, not preferenceList: everything after the first tag is
  // discarded by the browser, so passing more of them promises a header that
  // will not be sent. See expectedAcceptLanguage for the table.
  //
  // --lang is still absent, and now for a measured reason rather than parity: it
  // moves neither the header nor Intl. pinProcessLocale is what reaches Intl.
  ...(primaryLanguage(TARGET_LANG) ? [`--accept-lang=${primaryLanguage(TARGET_LANG)}`] : []),
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
