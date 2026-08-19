package solver

import (
	"os"
	"strings"
	"time"
)

// Where the solve claims to be, and the half of that no header carries.
//
// --accept-lang moves the header and navigator.languages. It does not move ICU,
// which is what Intl answers from, and ICU follows LC_ALL/LANG and TZ. Measured
// on Chromium 141, tr_TR box throughout:
//
//	flags / env                             header          languages   Intl
//	(none)                                  tr-TR,tr;q=0.9  ["tr-TR"]   tr
//	--accept-lang=en-US                     en-US,en;q=0.9  ["en-US"]   tr
//	--accept-lang=en-US --lang=en-US        en-US,en;q=0.9  ["en-US"]   tr
//	--accept-lang=en-US LC_ALL=en_US.UTF-8  en-US,en;q=0.9  ["en-US"]   en-US
//
// --lang buys nothing, which is why it is not in the launch list. The
// environment is what closes it, and it does not need the locale to be generated
// on the box: this was measured on an image whose `locale -a` lists only C,
// C.utf8 and POSIX, and Chromium still answered Intl "en-US" — ICU carries its
// own data and reads the variable directly.

// regionTimezones maps the region subtag of a language to the IANA zone a
// browser in that region most often reports.
//
// One zone per region, deliberately: several of these cover countries with more
// than one, and picking the most populous is the whole ambition. The point is not
// to be right about where the exit is — nothing here can know that — it is to
// report a zone a real browser could report, in a region the run has already said
// it is pretending to be in.
var regionTimezones = map[string]string{
	"US": "America/New_York", "CA": "America/Toronto", "MX": "America/Mexico_City",
	"BR": "America/Sao_Paulo", "AR": "America/Argentina/Buenos_Aires",
	"GB": "Europe/London", "IE": "Europe/Dublin", "FR": "Europe/Paris",
	"DE": "Europe/Berlin", "AT": "Europe/Vienna", "CH": "Europe/Zurich",
	"NL": "Europe/Amsterdam", "BE": "Europe/Brussels", "ES": "Europe/Madrid",
	"PT": "Europe/Lisbon", "IT": "Europe/Rome", "PL": "Europe/Warsaw",
	"SE": "Europe/Stockholm", "NO": "Europe/Oslo", "DK": "Europe/Copenhagen",
	"FI": "Europe/Helsinki", "CZ": "Europe/Prague", "GR": "Europe/Athens",
	"RO": "Europe/Bucharest", "UA": "Europe/Kyiv", "RU": "Europe/Moscow",
	"TR": "Europe/Istanbul", "IL": "Asia/Jerusalem", "SA": "Asia/Riyadh",
	"AE": "Asia/Dubai", "IN": "Asia/Kolkata", "PK": "Asia/Karachi",
	"ID": "Asia/Jakarta", "TH": "Asia/Bangkok", "VN": "Asia/Ho_Chi_Minh",
	"CN": "Asia/Shanghai", "HK": "Asia/Hong_Kong", "TW": "Asia/Taipei",
	"SG": "Asia/Singapore", "JP": "Asia/Tokyo", "KR": "Asia/Seoul",
	"AU": "Australia/Sydney", "NZ": "Pacific/Auckland",
	"ZA": "Africa/Johannesburg", "NG": "Africa/Lagos", "EG": "Africa/Cairo",
}

// languageTimezones covers the bare tags, where there is no region to read. The
// zone is the one the largest population of that language sits in.
var languageTimezones = map[string]string{
	"en": "America/New_York", "es": "Europe/Madrid", "pt": "America/Sao_Paulo",
	"fr": "Europe/Paris", "de": "Europe/Berlin", "it": "Europe/Rome",
	"nl": "Europe/Amsterdam", "pl": "Europe/Warsaw", "sv": "Europe/Stockholm",
	"tr": "Europe/Istanbul", "ru": "Europe/Moscow", "uk": "Europe/Kyiv",
	"ar": "Asia/Riyadh", "he": "Asia/Jerusalem", "hi": "Asia/Kolkata",
	"id": "Asia/Jakarta", "th": "Asia/Bangkok", "vi": "Asia/Ho_Chi_Minh",
	"zh": "Asia/Shanghai", "ja": "Asia/Tokyo", "ko": "Asia/Seoul",
}

// IsValidTimezone reports whether the zone database knows this zone.
//
// Worth checking rather than trusting, because the failure is silent and it is
// the worst possible value: measured on Chromium 141, TZ=Nonsense/Bogus does not
// error, it reports Etc/Unknown — the same thing an unset TZ reports, and the
// thing this whole mechanism exists to stop reporting.
func IsValidTimezone(tz string) bool {
	if tz == "" {
		return false
	}
	_, err := time.LoadLocation(tz)
	return err == nil
}

// TimezoneForLanguage picks the IANA zone that goes with an Accept-Language.
//
// Derived from the language rather than configured separately, for the same
// reason the header and navigator.languages are: they are all claims about the
// same imagined user, and a browser asking for tr-TR from a machine set to
// America/New_York is a combination worth not producing when the alternative
// costs nothing. SOLVER_TZ overrides it for anyone who knows where their exit
// actually is — which is the better answer, and the one this cannot compute.
func TimezoneForLanguage(header string) string {
	primary := PrimaryLanguage(header)
	if primary == "" {
		return ""
	}
	language, region, _ := strings.Cut(primary, "-")
	if region != "" {
		if tz, ok := regionTimezones[strings.ToUpper(region)]; ok {
			return tz
		}
	}
	return languageTimezones[strings.ToLower(language)]
}

// resolveTimezone is the zone the solve runs in.
//
// It exists because the default on the machines this runs on is not a timezone
// at all. Measured on Chromium 141.0.7390.37 in a container with no
// /etc/localtime and no TZ — which is every minimal Docker image and most small
// VPS builds:
//
//	TZ unset             Intl timeZone "Etc/Unknown"      offset 0
//	TZ=Europe/Istanbul   Intl timeZone "Europe/Istanbul"  offset -180
//	TZ=America/New_York  Intl timeZone "America/New_York" offset 240
//	TZ=Nonsense/Bogus    Intl timeZone "Etc/Unknown"      offset 0
//
// Etc/Unknown is not a zone any installed browser reports; it is what ICU says
// when it was given nothing to work with. A page that asks — and a challenge
// does, it is one property read — gets an answer no real client produces, on the
// request that earns cf_clearance.
//
// So the default is a real zone derived from the language, and an invalid
// configured value falls back to it rather than silently becoming Etc/Unknown.
func resolveTimezone(configured, language string) string {
	if IsValidTimezone(configured) {
		return configured
	}
	if derived := TimezoneForLanguage(language); IsValidTimezone(derived) {
		return derived
	}
	return "UTC"
}

// Env is the environment the browser is launched with.
//
// The locale is set on the child rather than on this process, which is the one
// place this improves on the version it replaces: pinning it there meant a
// module rewrote the environment of whatever imported it, test runner included.
// Here it reaches exactly the browser it is meant for, and a batch solving a
// hundred exits through one browser gets one consistent answer from Intl.
//
// SOLVER_PIN_LOCALE=0 leaves the box's own locale and timezone alone, for anyone
// whose machine is already configured to match its exit. It is an opt-out rather
// than the default because the unconfigured state is not neutral: a container
// reports Etc/Unknown, which is worse than any zone this could pick.
func (p Profile) Env() []string {
	env := os.Environ()
	if os.Getenv("SOLVER_PIN_LOCALE") == "0" {
		return env
	}
	primary := PrimaryLanguage(p.Language)
	if primary == "" {
		return env
	}
	posix := strings.ReplaceAll(primary, "-", "_")

	tags := LanguageList(p.Language)
	for i, tag := range tags {
		tags[i] = strings.ReplaceAll(tag, "-", "_")
	}

	set := map[string]string{
		"LANG":     posix + ".UTF-8",
		"LC_ALL":   posix + ".UTF-8",
		"LANGUAGE": strings.Join(tags, ":"),
		"TZ":       p.Timezone,
	}

	out := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		if _, replaced := set[key]; !replaced {
			out = append(out, kv)
		}
	}
	for key, value := range set {
		if value != "" {
			out = append(out, key+"="+value)
		}
	}
	return out
}
