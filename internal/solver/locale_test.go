package solver

import (
	"strings"
	"testing"
)

func TestTimezoneForLanguage(t *testing.T) {
	cases := []struct{ header, want string }{
		{"en-US,en;q=0.9", "America/New_York"},
		{"tr-TR", "Europe/Istanbul"},
		{"pt-BR", "America/Sao_Paulo"},
		{"de-AT", "Europe/Vienna"},
		// No region to read: the zone the largest population of that language
		// sits in.
		{"de", "Europe/Berlin"},
		{"ja", "Asia/Tokyo"},
		// A region nothing knows falls back to the bare language.
		{"en-ZZ", "America/New_York"},
		{"xx", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := TimezoneForLanguage(tc.header); got != tc.want {
			t.Errorf("TimezoneForLanguage(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

// An invalid zone must fall back to a real one rather than silently becoming
// Etc/Unknown, which is what an unconfigured container reports and what no
// installed browser produces.
func TestResolveTimezone(t *testing.T) {
	if got := resolveTimezone("Europe/Istanbul", "en-US"); got != "Europe/Istanbul" {
		t.Errorf("a valid configured zone was ignored: %q", got)
	}
	if got := resolveTimezone("Nonsense/Bogus", "tr-TR"); got != "Europe/Istanbul" {
		t.Errorf("an invalid zone did not fall back to the derived one: %q", got)
	}
	if got := resolveTimezone("", "de"); got != "Europe/Berlin" {
		t.Errorf("no configured zone did not derive one: %q", got)
	}
	// A language nothing maps still has to produce a zone a browser could report.
	if got := resolveTimezone("", "xx"); got != "UTC" {
		t.Errorf("an unmappable language = %q, want UTC", got)
	}
	if !IsValidTimezone(resolveTimezone("", "xx")) {
		t.Error("the fallback is not a zone the database knows")
	}
}

func TestIsValidTimezone(t *testing.T) {
	for _, tz := range []string{"Europe/Istanbul", "America/New_York", "UTC"} {
		if !IsValidTimezone(tz) {
			t.Errorf("IsValidTimezone(%q) = false", tz)
		}
	}
	for _, tz := range []string{"", "Nonsense/Bogus", "Etc/Unknown-ish"} {
		if IsValidTimezone(tz) {
			t.Errorf("IsValidTimezone(%q) = true", tz)
		}
	}
}

// ICU reads LC_ALL and TZ, and nothing else reaches Intl. The environment is
// applied to the browser rather than to this process, so a test can check it
// without the check changing the runner's own locale.
func TestEnvPinsLocaleAndTimezone(t *testing.T) {
	p := Profile{Language: "tr-TR,tr;q=0.9", Timezone: "Europe/Istanbul"}
	env := envMap(p.Env())

	if env["LANG"] != "tr_TR.UTF-8" || env["LC_ALL"] != "tr_TR.UTF-8" {
		t.Errorf("LANG/LC_ALL = %q/%q, want tr_TR.UTF-8", env["LANG"], env["LC_ALL"])
	}
	if env["LANGUAGE"] != "tr_TR:tr" {
		t.Errorf("LANGUAGE = %q, want tr_TR:tr", env["LANGUAGE"])
	}
	if env["TZ"] != "Europe/Istanbul" {
		t.Errorf("TZ = %q", env["TZ"])
	}
}

// The opt-out exists for anyone whose box already matches its exit. It is an
// opt-out rather than the default because the unconfigured state is not neutral.
func TestEnvHonoursThePinOptOut(t *testing.T) {
	t.Setenv("SOLVER_PIN_LOCALE", "0")
	t.Setenv("LANG", "C.UTF-8")

	p := Profile{Language: "tr-TR", Timezone: "Europe/Istanbul"}
	env := envMap(p.Env())
	if env["LANG"] != "C.UTF-8" {
		t.Errorf("LANG = %q, want the box's own value left alone", env["LANG"])
	}
	if _, set := env["TZ"]; set && env["TZ"] == "Europe/Istanbul" {
		t.Error("TZ was pinned despite SOLVER_PIN_LOCALE=0")
	}
}

// The environment must not gain a second copy of a variable it replaces: the
// last one wins on Linux, but relying on that is how a pin silently stops taking.
func TestEnvReplacesRatherThanAppends(t *testing.T) {
	t.Setenv("LANG", "en_GB.UTF-8")
	t.Setenv("TZ", "America/Chicago")

	p := Profile{Language: "tr-TR", Timezone: "Europe/Istanbul"}
	counts := map[string]int{}
	for _, kv := range p.Env() {
		key, _, _ := strings.Cut(kv, "=")
		counts[key]++
	}
	for _, key := range []string{"LANG", "LC_ALL", "LANGUAGE", "TZ"} {
		if counts[key] != 1 {
			t.Errorf("%s appears %d times in the browser environment, want 1", key, counts[key])
		}
	}
}

func TestDefaultProfileDerivesATimezone(t *testing.T) {
	t.Setenv("SOLVER_LANG", "tr-TR,tr;q=0.9")
	t.Setenv("SOLVER_TZ", "")

	p := DefaultProfile()
	if p.Timezone != "Europe/Istanbul" {
		t.Errorf("timezone = %q, want the zone derived from the language", p.Timezone)
	}
	// platformVersion is empty on Linux, which is what a real browser answers.
	if p.Platform == "Linux" && p.PlatformVersion != "" {
		t.Errorf("platformVersion = %q, want empty on Linux", p.PlatformVersion)
	}

	t.Setenv("SOLVER_TZ", "America/Denver")
	if got := DefaultProfile().Timezone; got != "America/Denver" {
		t.Errorf("SOLVER_TZ was ignored: %q", got)
	}
}

func envMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		key, value, _ := strings.Cut(kv, "=")
		out[key] = value
	}
	return out
}
