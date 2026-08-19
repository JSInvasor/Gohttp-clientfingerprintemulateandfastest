package solver

import (
	"strings"
	"testing"
)

func TestLanguageList(t *testing.T) {
	cases := []struct {
		header string
		want   []string
	}{
		{"en-US,en;q=0.9", []string{"en-US", "en"}},
		{"tr-TR,tr;q=0.9,en-US;q=0.8", []string{"tr-TR", "tr", "en-US"}},
		{"  en-US , en ", []string{"en-US", "en"}},
		{"en,en,en", []string{"en"}}, // duplicates collapse, order kept
		{"", nil},
		{",,", nil},
	}
	for _, tc := range cases {
		got := LanguageList(tc.header)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("LanguageList(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

// The header a run reports has to be the one the browser sends, or every check
// downstream compares a value against itself.
func TestExpectedAcceptLanguage(t *testing.T) {
	cases := []struct{ in, want string }{
		// A region tag implies its base language at q=0.9.
		{"en-US", "en-US,en;q=0.9"},
		{"en-US,en;q=0.9", "en-US,en;q=0.9"},
		{"tr-TR", "tr-TR,tr;q=0.9"},
		{"pt-BR,pt", "pt-BR,pt;q=0.9"},
		// A bare tag stands alone: there is no region to strip.
		{"de", "de"},
		{"en", "en"},
		// Extra tags keep their place rather than being discarded, which is what
		// the CDP override actually sends.
		{"tr-TR,en-US", "tr-TR,tr;q=0.9,en-US;q=0.9"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := ExpectedAcceptLanguage(tc.in); got != tc.want {
			t.Errorf("ExpectedAcceptLanguage(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The preference list handed to CDP must never carry quality values: the browser
// reads them as part of the language codes. See TestAcceptLanguageDerivation in
// internal/cdp for the measurement this guards.
func TestLanguagePreferenceCarriesNoQualityValues(t *testing.T) {
	for _, header := range []string{"en-US,en;q=0.9", "tr-TR,tr;q=0.9,en;q=0.8", "de"} {
		got := LanguagePreference(header)
		if strings.Contains(got, "q=") || strings.Contains(got, ";") {
			t.Errorf("LanguagePreference(%q) = %q, want no quality values", header, got)
		}
	}
	if got := LanguagePreference("en-US,en;q=0.9"); got != "en-US,en" {
		t.Errorf("LanguagePreference = %q, want en-US,en", got)
	}
}

// The header and navigator.languages are two views of one value, and a run where
// they disagree is the bug this pairing exists to make impossible.
func TestSentLanguagesMatchTheHeader(t *testing.T) {
	for _, header := range []string{"en-US,en;q=0.9", "tr-TR", "de", "pt-BR,pt"} {
		sent := ExpectedAcceptLanguage(header)
		langs := SentLanguages(header)
		if strings.Join(langs, "|") != strings.Join(LanguageList(sent), "|") {
			t.Errorf("for %q: languages %v do not match header %q", header, langs, sent)
		}
	}
}

func TestParseSecChUAKeepsOrder(t *testing.T) {
	brands := ParseSecChUA(`"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`)
	if len(brands) != 3 {
		t.Fatalf("parsed %d brands, want 3", len(brands))
	}
	// Chrome puts the greased entry first and UAM checks the ordering.
	if brands[0].Brand != "Not=A?Brand" || brands[0].Version != "99" {
		t.Errorf("first brand = %+v, want the greased entry", brands[0])
	}
	if brands[1].Brand != "Google Chrome" || brands[1].Version != "151" {
		t.Errorf("second brand = %+v", brands[1])
	}
	if got := ParseSecChUA("not a header"); len(got) != 0 {
		t.Errorf("ParseSecChUA(garbage) = %v, want nothing", got)
	}
}

// A UA that says one Chrome major beside hints that say another is the signal
// this package exists to avoid, and a silent mismatch would cost a full solve to
// discover.
func TestMetadataRefusesDrift(t *testing.T) {
	base := Profile{
		UserAgent: defaultUA,
		SecChUA:   defaultSecChUA,
		Platform:  "Linux",
		Language:  defaultLang,
	}

	if _, err := base.Metadata("HeadlessChrome/151.0.7204.50"); err != nil {
		t.Fatalf("the pinned profile does not build: %v", err)
	}

	drifted := base
	drifted.SecChUA = `"Not=A?Brand";v="99", "Google Chrome";v="147", "Chromium";v="147"`
	if _, err := drifted.Metadata(""); err == nil {
		t.Error("Metadata accepted sec-ch-ua v147 beside a Chrome 151 UA")
	} else if !strings.Contains(err.Error(), "Client Hint drift") {
		t.Errorf("wrong error for hint drift: %v", err)
	}

	// The OS token and the platform hint have to name the same system: getting
	// this pair wrong is what made the old Windows pin detectable.
	wrongPlatform := base
	wrongPlatform.Platform = "Windows"
	if _, err := wrongPlatform.Metadata(""); err == nil {
		t.Error("Metadata accepted a Windows platform hint beside an X11 UA")
	} else if !strings.Contains(err.Error(), "platform drift") {
		t.Errorf("wrong error for platform drift: %v", err)
	}

	noChrome := base
	noChrome.UserAgent = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/130.0"
	if _, err := noChrome.Metadata(""); err == nil {
		t.Error("Metadata built hints from a UA with no Chrome version")
	}

	noBrands := base
	noBrands.SecChUA = ""
	if _, err := noBrands.Metadata(""); err == nil {
		t.Error("Metadata built hints from an empty sec-ch-ua")
	}
}

// The UA freezes the build to <major>.0.0.0; the high-entropy hints do not. A
// real browser answers fullVersionList with its actual build, so reporting the
// frozen value there is a build number no Chrome ships.
func TestMetadataCarriesTheRealBuild(t *testing.T) {
	p := Profile{UserAgent: defaultUA, SecChUA: defaultSecChUA, Platform: "Linux"}

	meta, err := p.Metadata("HeadlessChrome/151.0.7204.50")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if meta.FullVersion != "151.0.7204.50" {
		t.Errorf("fullVersion = %q, want the browser's real build", meta.FullVersion)
	}
	// brands carries the major only, which is what sec-ch-ua puts on the wire.
	if meta.Brands[1].Version != "151" {
		t.Errorf("brands version = %q, want the major only", meta.Brands[1].Version)
	}
	// The greased entry keeps its own unrelated version.
	if meta.FullVersionList[0].Version != "99.0.0.0" {
		t.Errorf("greased fullVersionList entry = %q, want 99.0.0.0", meta.FullVersionList[0].Version)
	}
	if meta.FullVersionList[1].Version != "151.0.7204.50" {
		t.Errorf("real fullVersionList entry = %q", meta.FullVersionList[1].Version)
	}

	// A browser whose major disagrees with the claimed identity falls back to
	// the frozen value; fpcheck reports the underlying mismatch separately.
	meta, err = p.Metadata("HeadlessChrome/141.0.7390.37")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if meta.FullVersion != "151.0.0.0" {
		t.Errorf("fullVersion = %q, want the frozen 151.0.0.0 when the build disagrees", meta.FullVersion)
	}

	// platformVersion is empty on Linux, which is what a real browser answers.
	if meta.PlatformVersion != "" {
		t.Errorf("platformVersion = %q, want empty on Linux", meta.PlatformVersion)
	}
	if meta.Bitness != "64" {
		t.Errorf("bitness = %q, want 64 for an x86_64 UA", meta.Bitness)
	}
}

func TestPlatformFromUA(t *testing.T) {
	cases := []struct{ ua, want string }{
		{defaultUA, "Linux"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/151.0.0.0", "Windows"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/151.0.0.0", "macOS"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Version/18.0", "iOS"},
		// Android UAs say Linux too, so the order of the checks is the answer.
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/151.0.0.0 Mobile", "Android"},
		{"something else entirely", ""},
	}
	for _, tc := range cases {
		if got := PlatformFromUA(tc.ua); got != tc.want {
			t.Errorf("PlatformFromUA(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

func TestChromiumMajor(t *testing.T) {
	cases := []struct {
		version string
		want    int
	}{
		{"HeadlessChrome/151.0.7204.50", 151},
		{"Chrome/141.0.7390.37", 141},
		{"", 0},
		{"Chrome/151", 0}, // not a four-part build
	}
	for _, tc := range cases {
		if got := ChromiumMajor(tc.version); got != tc.want {
			t.Errorf("ChromiumMajor(%q) = %d, want %d", tc.version, got, tc.want)
		}
	}
}

// Chrome only assumes HTTP when the value carries no scheme, so anything else
// has to keep its scheme or a SOCKS exit is silently dialled as HTTP.
func TestParseProxy(t *testing.T) {
	p, err := ParseProxy("http://user:pass@10.0.0.1:8080")
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	if p.Server != "10.0.0.1:8080" {
		t.Errorf("Server = %q, want a bare host:port for an HTTP proxy", p.Server)
	}
	if p.Username != "user" || p.Password != "pass" {
		t.Errorf("credentials = %q/%q", p.Username, p.Password)
	}
	if p.Label() != "10.0.0.1:8080" {
		t.Errorf("Label() = %q, want the credentials left out", p.Label())
	}

	socks, err := ParseProxy("socks5://10.0.0.2:1080")
	if err != nil {
		t.Fatalf("ParseProxy(socks5): %v", err)
	}
	if socks.Server != "socks5://10.0.0.2:1080" {
		t.Errorf("Server = %q, want the scheme kept", socks.Server)
	}

	// A password is entitled to contain characters the URL parser escapes, and
	// rejecting one would name neither the proxy nor the field.
	esc, err := ParseProxy("http://user:p%40ss%3Aword@10.0.0.3:3128")
	if err != nil {
		t.Fatalf("ParseProxy(escaped): %v", err)
	}
	if esc.Password != "p@ss:word" {
		t.Errorf("Password = %q, want the decoded value", esc.Password)
	}

	if p, err := ParseProxy(""); err != nil || p != nil {
		t.Errorf("ParseProxy(\"\") = %v, %v; want nil, nil — that is a direct solve", p, err)
	}

	for _, bad := range []string{"http://nohost", "http://10.0.0.1", "://x:1"} {
		if _, err := ParseProxy(bad); err == nil {
			t.Errorf("ParseProxy(%q) accepted a URL with no host or port", bad)
		}
	}
}

// The launch flags and the fingerprint probe have to name the same browser, so
// the flags live on the profile rather than at a call site.
func TestLaunchArgsPinTheLanguage(t *testing.T) {
	p := Profile{Language: "tr-TR,tr;q=0.9"}
	args := strings.Join(p.LaunchArgs(), " ")
	// The flag discards everything after the first tag, so passing more of them
	// promises a header that will not be sent.
	if !strings.Contains(args, "--accept-lang=tr-TR ") && !strings.HasSuffix(args, "--accept-lang=tr-TR") {
		t.Errorf("launch args = %q, want --accept-lang=tr-TR", args)
	}
	if strings.Contains(args, "q=0.9") {
		t.Error("the launch flag carries quality values, which it reads as part of the codes")
	}
	// A browser with no WebGL context at all is a far stronger signal than one
	// rendering in software.
	if !strings.Contains(args, "--use-angle=swiftshader") {
		t.Error("launch args dropped the software WebGL renderer")
	}
	if strings.Contains(args, "--disable-gpu") {
		t.Error("--disable-gpu is redundant beside an explicit renderer and invites the two to disagree")
	}
}
