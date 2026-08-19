// Package solver earns a Cloudflare clearance cookie with a real browser.
//
// It drives the Chromium in internal/cdp through a challenge and hands back the
// cookies, the identity that earned them, and enough context for the caller to
// tell a solve that will replay from one that will not.
//
// The whole package exists because of one binding: Cloudflare ties cf_clearance
// to the (User-Agent, JA3/JA4, IP) of the session it was issued to. A real
// browser answers the challenge; gofire then replays the cookie with its own
// emulated ClientHello. If those two are not the same browser from the same
// address, the cookie is issued to one identity and presented by another, and it
// dies — usually within seconds under load, with no diagnostic beyond a wall of
// 403s. Everything here is in service of making the two the same.
package solver

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/cdp"
)

// The browser identity the solve presents, and the one gofire has to replay
// with. These are the Go side of what solver/profile.js pinned.
//
// TARGET_UA must match the UA gofire replays with — Chrome151LinuxUserAgent in
// headers.go, the same Chrome 151 identity with the OS token this box runs.
//
// Claiming Windows was measurably wrong here. The headers said Windows while the
// JS environment said otherwise, and a challenge reads both:
//
//	navigator.platform   Linux x86_64   (real Chrome on Windows: Win32)
//	fonts                Calibri and Segoe UI absent, DejaVu Sans present
//
// No page-level override fixes that honestly. The TLS and HTTP/2 layers are
// untouched by the choice — BoringSSL sends the same ClientHello on every
// platform, so the pinned JA4 and Akamai fingerprint stay valid either way. Only
// the OS token and the platform hint move.
const (
	defaultUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) " +
		"Chrome/151.0.0.0 Safari/537.36"

	// The Client Hint half of the same identity. It must match gofire's
	// Chrome151SecChUa and the Sec-Ch-Ua-Mobile / Sec-Ch-Ua-Platform defaults in
	// headers.go.
	//
	// Pinning the UA string alone is not enough, and getting this wrong is worse
	// than leaving the UA stale: overriding the UA does not leave Chromium's
	// native hints in place, it clears them. A request claiming Chrome 151 while
	// sending no Client Hints at all is a combination no real Chrome produces,
	// and it is the session Cloudflare binds cf_clearance to.
	defaultSecChUA = `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`

	defaultPlatform = "Linux"

	// The Accept-Language the solve advertises. Like the UA it has to be the one
	// gofire replays with; send passes its own value in so the two cannot drift.
	defaultLang = "en-US,en;q=0.9"
)

// Profile is the identity one solve runs under: what it claims to be, what
// language it speaks, and where it claims to be.
type Profile struct {
	UserAgent string
	SecChUA   string
	Platform  string
	// PlatformVersion accompanies the platform hint. It is empty on Linux and
	// that is not an omission: Chrome only populates it on Windows, macOS and
	// Android, and asked for high-entropy hints on Linux a real browser answers
	// "". Filling in a kernel release would be a value no Chrome reports.
	PlatformVersion string
	// Language is the Accept-Language header this solve intends to advertise,
	// e.g. "en-US,en;q=0.9" — a header, not a preference list. The conversion to
	// what each mechanism wants happens at the edges: LanguagePreference for
	// CDP, primaryLanguage for the launch flag.
	Language string
	// Timezone is the IANA zone Intl will answer with.
	Timezone string
}

// DefaultProfile is the pinned identity, with the environment applied over it.
//
// SOLVER_UA, SOLVER_SEC_CH_UA and SOLVER_PLATFORM re-pin the identity when
// solving from a box whose OS or Chrome major differs; they have to move
// together and Metadata refuses to build an inconsistent set.
func DefaultProfile() Profile {
	p := Profile{
		UserAgent: envOr("SOLVER_UA", defaultUA),
		SecChUA:   envOr("SOLVER_SEC_CH_UA", defaultSecChUA),
		Platform:  envOr("SOLVER_PLATFORM", defaultPlatform),
		Language:  envOr("SOLVER_LANG", defaultLang),
	}
	if v, ok := os.LookupEnv("SOLVER_PLATFORM_VERSION"); ok {
		p.PlatformVersion = v
	} else if p.Platform != "Linux" {
		p.PlatformVersion = "10.0.0"
	}
	p.Timezone = resolveTimezone(os.Getenv("SOLVER_TZ"), p.Language)
	return p
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// LanguageList turns an Accept-Language header into the codes it names, quality
// values dropped, order kept, duplicates removed:
//
//	"en-US,en;q=0.9" -> ["en-US", "en"]
func LanguageList(header string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, part := range strings.Split(header, ",") {
		tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	return out
}

// PrimaryLanguage is the first tag, which is what --accept-lang takes.
func PrimaryLanguage(header string) string {
	list := LanguageList(header)
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

// LanguagePreference is what CDP's setUserAgentOverride wants: the codes of the
// header, comma-joined, with no quality values.
//
// Handing that call a finished header instead makes it read the q-values as part
// of the codes — see cdp.Tab.SetUserAgent and TestAcceptLanguageDerivation for
// the measurement. This is the conversion that prevents it.
func LanguagePreference(header string) string {
	return strings.Join(LanguageList(header), ",")
}

// ExpectedAcceptLanguage is the header the browser will actually send, given the
// preference list derived from this one.
//
// It exists because everything in the solver used to be keyed off the value that
// was *asked for* while the browser sent something else, and the checks meant to
// catch that were fed the asked-for value too — so they compared it against
// itself and agreed every time. Three things have to agree on one request:
//
//	the Accept-Language header    the edge reads it
//	navigator.languages           the challenge's JavaScript reads it
//	what the solve reports back    gofire replays the cookie with it
//
// Through CDP the browser derives the header from the codes by giving every
// entry after the first q=0.9, so "en-US,en" becomes "en-US,en;q=0.9". A tag
// carrying a region also implies its base language, which a real browser adds;
// callers that pass only "en-US" would advertise a header a browser does not
// send, so this normalises to the full list first.
func ExpectedAcceptLanguage(header string) string {
	list := LanguageList(header)
	if len(list) == 0 {
		return ""
	}
	// A region tag implies its base language at q=0.9, which is what Chrome
	// sends and what --accept-lang derives on its own.
	primary := list[0]
	if base, _, found := strings.Cut(primary, "-"); found && base != "" {
		if len(list) == 1 || list[1] != base {
			list = append([]string{primary, base}, list[1:]...)
		}
	}
	out := list[0]
	for _, tag := range list[1:] {
		out += "," + tag + ";q=0.9"
	}
	return out
}

// SentLanguages is navigator.languages as the browser will report it, which is
// the codes of the header it sends. The two come from one value on purpose: a
// browser advertising one language on the wire and listing another in the page
// object is not a browser that exists, and the previous solver produced exactly
// that on any box whose locale was not en_US.
func SentLanguages(header string) []string {
	return LanguageList(ExpectedAcceptLanguage(header))
}

// Metadata builds the Client Hints that have to accompany a UA override, and
// refuses to build an inconsistent set.
//
// Every real brand's version must equal the UA's Chrome major. Emitting a UA
// that says 151 alongside hints that say something else is precisely the signal
// this package exists to avoid, and a silent mismatch would cost a full solve to
// discover. An error means SOLVER_UA and SOLVER_SEC_CH_UA have to be re-pinned
// together.
//
// browserVersion is the real build, from Browser.getVersion. The UA string
// freezes it to <major>.0.0.0 — Chrome has done that since 101 — but the
// high-entropy hints do not: asked for fullVersionList or uaFullVersion a real
// browser answers with its actual build. Reporting <major>.0.0.0 there is a
// build number no Chrome ships, on a call a managed challenge makes.
func (p Profile) Metadata(browserVersion string) (*cdp.UserAgentMetadata, error) {
	uaVersion := chromeVersionFromUA(p.UserAgent)
	if uaVersion == "" {
		return nil, fmt.Errorf("cannot build Client Hints: no Chrome/<version> in UA %q", p.UserAgent)
	}
	major, _, _ := strings.Cut(uaVersion, ".")

	brands := ParseSecChUA(p.SecChUA)
	if len(brands) == 0 {
		return nil, fmt.Errorf("cannot build Client Hints: no brands parsed from %q", p.SecChUA)
	}
	for _, b := range brands {
		if !isGreasedBrand(b.Brand) && b.Version != major {
			return nil, fmt.Errorf(
				"Client Hint drift: sec-ch-ua says %s v%s but the UA says Chrome %s; "+
					"re-pin SOLVER_UA and SOLVER_SEC_CH_UA together", b.Brand, b.Version, major)
		}
	}

	// The OS token and the platform hint have to name the same system. Getting
	// this pair wrong is what made the old Windows pin detectable.
	if uaPlatform := PlatformFromUA(p.UserAgent); uaPlatform != "" && uaPlatform != p.Platform {
		return nil, fmt.Errorf(
			"platform drift: the UA's OS token says %s but the platform hint says %s; "+
				"re-pin SOLVER_UA and SOLVER_PLATFORM together", uaPlatform, p.Platform)
	}

	// The real build is used only when its major agrees with the identity being
	// claimed; when it does not, the frozen value is the safer answer and
	// fpcheck's version check is what reports the underlying mismatch.
	fullVersion := uaVersion
	if real := fullBuildFrom(browserVersion); real != "" {
		if realMajor, _, _ := strings.Cut(real, "."); realMajor == major {
			fullVersion = real
		}
	}

	fullList := make([]cdp.Brand, 0, len(brands))
	for _, b := range brands {
		v := fullVersion
		if isGreasedBrand(b.Brand) {
			v = b.Version + ".0.0.0"
		}
		fullList = append(fullList, cdp.Brand{Brand: b.Brand, Version: v})
	}

	return &cdp.UserAgentMetadata{
		Brands:          brands,
		FullVersionList: fullList,
		FullVersion:     fullVersion,
		Platform:        p.Platform,
		PlatformVersion: p.PlatformVersion,
		Architecture:    "x86",
		Bitness:         bitnessFromUA(p.UserAgent),
		Model:           "",
		Mobile:          false,
	}, nil
}

var secChUARe = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"\s*;\s*v\s*=\s*"((?:[^"\\]|\\.)*)"`)

// ParseSecChUA turns a sec-ch-ua header value into the brand list CDP wants.
// Order is preserved: Chrome puts the greased entry first and the ordering is
// itself observable, so this must not sort.
func ParseSecChUA(value string) []cdp.Brand {
	var brands []cdp.Brand
	for _, m := range secChUARe.FindAllStringSubmatch(value, -1) {
		brands = append(brands, cdp.Brand{Brand: m[1], Version: m[2]})
	}
	return brands
}

// A greased brand is the deliberately-mangled entry Chrome rotates each release
// ("Not=A?Brand", "Not;A=Brand", "Not.A/Brand"). It carries its own unrelated
// version, so it is exempt from the consistency check.
var greasedRe = regexp.MustCompile(`[^A-Za-z0-9 ]`)

func isGreasedBrand(brand string) bool { return greasedRe.MatchString(brand) }

var chromeVersionRe = regexp.MustCompile(`Chrome/(\d+(?:\.\d+)*)`)

// chromeVersionFromUA pulls the full Chrome version out of a User-Agent.
func chromeVersionFromUA(ua string) string {
	if m := chromeVersionRe.FindStringSubmatch(ua); m != nil {
		return m[1]
	}
	return ""
}

var fourPartRe = regexp.MustCompile(`\d+(?:\.\d+){3}`)

// fullBuildFrom reads a four-part build out of a Browser.getVersion product
// string such as "HeadlessChrome/141.0.7390.37".
func fullBuildFrom(version string) string {
	if v := chromeVersionFromUA(version); strings.Count(v, ".") == 3 {
		return v
	}
	return fourPartRe.FindString(version)
}

// ChromiumMajor extracts the major version from a Browser.getVersion product
// string. Returns 0 when it cannot be parsed.
func ChromiumMajor(version string) int {
	build := fourPartRe.FindString(version)
	if build == "" {
		return 0
	}
	major, _, _ := strings.Cut(build, ".")
	n := 0
	for _, r := range major {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

var bitness64Re = regexp.MustCompile(`(?i)Win64|x64|x86_64|amd64`)

func bitnessFromUA(ua string) string {
	if bitness64Re.MatchString(ua) {
		return "64"
	}
	return ""
}

// PlatformFromUA reads the OS token out of a User-Agent and returns it in the
// spelling Sec-Ch-Ua-Platform uses. An empty result leaves the caller's platform
// unchallenged rather than guessed at.
func PlatformFromUA(ua string) string {
	switch {
	case regexp.MustCompile(`(?i)Windows NT`).MatchString(ua):
		return "Windows"
	case regexp.MustCompile(`(?i)Android`).MatchString(ua):
		// Before Linux: Android UAs say both.
		return "Android"
	case regexp.MustCompile(`(?i)iPhone|iPad|iPod`).MatchString(ua):
		return "iOS"
	case regexp.MustCompile(`(?i)Macintosh|Mac OS X`).MatchString(ua):
		return "macOS"
	case regexp.MustCompile(`(?i)X11|Linux`).MatchString(ua):
		return "Linux"
	}
	return ""
}

// Proxy is a parsed SOLVER_PROXY or exit URL.
type Proxy struct {
	// Server is Chrome's --proxy-server value: "host:port" for a plain HTTP
	// proxy, "scheme://host:port" for anything else. Chrome only assumes HTTP
	// when the value carries no scheme, so a SOCKS exit that loses its scheme is
	// silently dialled as HTTP.
	Server   string
	Host     string
	Port     string
	Username string
	Password string
}

// Label names an exit without its credentials, for output that ends up in logs.
func (p *Proxy) Label() string {
	if p == nil {
		return ""
	}
	return p.Host + ":" + p.Port
}

// ParseProxy turns a proxy URL into what Chrome and the Fetch domain each need.
// An empty string is not an error — it is a direct solve.
func ParseProxy(raw string) (*Proxy, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: want scheme://[user:pass@]host:port", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	if u.Hostname() == "" {
		return nil, fmt.Errorf("proxy URL %q has no host", raw)
	}
	if u.Port() == "" {
		return nil, fmt.Errorf("proxy URL %q has no port", raw)
	}
	p := &Proxy{Host: u.Hostname(), Port: u.Port()}
	if scheme == "http" || scheme == "" {
		p.Server = p.Host + ":" + p.Port
	} else {
		p.Server = scheme + "://" + p.Host + ":" + p.Port
	}
	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}
	return p, nil
}

// LaunchArgs are the flags the browser starts with.
//
// They are here rather than at the call site so the fingerprint probe measures
// the same browser configuration the solver runs. A launch flag can move the TLS
// layer — a --disable-features that switches off post-quantum key agreement
// would change the ClientHello and therefore the JA4 — so measuring a
// differently-flagged browser answers the wrong question.
func (p Profile) LaunchArgs() []string {
	return []string{
		"--no-sandbox",
		"--disable-setuid-sandbox",
		"--disable-dev-shm-usage",
		"--disable-blink-features=AutomationControlled",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-features=IsolateOrigins,site-per-process",
		"--window-size=1920,1080",
		// Software WebGL. A headless box has no GPU, and without these the
		// canvas hands back no WebGL context at all — measured with and without
		// --disable-gpu, which turned out not to be the cause:
		//
		//   as shipped (--disable-gpu)  -> NO WEBGL
		//   --use-gl=angle --use-angle=swiftshader
		//                               -> ANGLE (Google, Vulkan 1.3.0
		//                                  (SwiftShader Device (Subzero)))
		//
		// Every real Chrome has a WebGL context. A browser that has none is a
		// far stronger signal than one rendering in software, which is what any
		// VM or RDP session looks like. --disable-gpu is gone because it is
		// redundant beside an explicit software renderer and only invites the
		// two to disagree.
		"--use-gl=angle",
		"--use-angle=swiftshader",
		// The browser-level language, beside the per-tab override every prepared
		// tab also carries. It is here so that a request made before a tab is
		// prepared — or by anything in the browser that is not a tab we drive —
		// still advertises the language the run intends, rather than whatever
		// the box's locale produces.
		//
		// primaryLanguage, not the whole list: the flag discards everything
		// after the first tag and derives the base language itself, so
		// --accept-lang=en-US sends "en-US,en;q=0.9". Passing more tags promises
		// a header that will not be sent. That derivation is the flag's, and it
		// differs from the CDP override's — see cdp.Tab.SetUserAgent.
		"--accept-lang=" + PrimaryLanguage(p.Language),
	}
}
