package cdp

import (
	"context"
	"strings"
	"testing"
	"time"
)

// What Chromium derives from the acceptLanguage handed to setUserAgentOverride.
//
// This is measured rather than assumed because the two mechanisms available
// derive differently, and the difference is invisible until something reads the
// header. Against Chromium 141 through this call, beside the --accept-lang
// command-line flag whose table profile.go carries:
//
//	value              CDP header            CDP languages    flag header
//	"en-US"            en-US                 ["en-US"]        en-US,en;q=0.9
//	"en-US,en"         en-US,en;q=0.9        ["en-US","en"]   en-US,en;q=0.9
//	"en-US,en;q=0.9"   en-US,en;q=0.9;q=0.9  ["en-US","en;q=0.9"]  —
//	"de"               de                    ["de"]           de
//
// Three things fall out of that and all three matter to a solve:
//
//   - The value is a preference list. A finished header handed to it has its
//     q-values read as part of the language codes, which is the third row: a
//     header no browser sends, beside a navigator.languages entry — "en;q=0.9" —
//     that is not a language tag at all. That is the failure this table exists
//     to make impossible to ship.
//   - Unlike the flag, CDP keeps the whole list rather than collapsing to the
//     first tag, and it puts that same list in navigator.languages. So the
//     header and the page object agree by construction, with no shim.
//   - Every entry after the first gets q=0.9. Passing the codes of the header
//     you intend — "en-US,en" for "en-US,en;q=0.9" — is what reproduces it.
func TestAcceptLanguageDerivation(t *testing.T) {
	b := testBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	site := newOrigin(t)

	cases := []struct {
		value     string
		header    string
		languages []string
	}{
		{"en-US", "en-US", []string{"en-US"}},
		{"en-US,en", "en-US,en;q=0.9", []string{"en-US", "en"}},
		{"tr-TR,tr", "tr-TR,tr;q=0.9", []string{"tr-TR", "tr"}},
		{"pt-BR,pt", "pt-BR,pt;q=0.9", []string{"pt-BR", "pt"}},
		{"de", "de", []string{"de"}},
		// The one that is a caller bug rather than a configuration: a finished
		// header, whose q-values become part of the codes.
		{"en-US,en;q=0.9", "en-US,en;q=0.9;q=0.9", []string{"en-US", "en;q=0.9"}},
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			tab, err := b.DefaultContext().NewTab(ctx)
			if err != nil {
				t.Fatalf("tab: %v", err)
			}
			defer tab.Close(ctx)

			if err := tab.SetUserAgent(ctx, "", tc.value, "", nil); err != nil {
				t.Fatalf("set user agent: %v", err)
			}
			if err := tab.Navigate(ctx, site.server.URL); err != nil {
				t.Fatalf("navigate: %v", err)
			}
			if got := site.header("Accept-Language"); got != tc.header {
				t.Errorf("Accept-Language = %q, want %q", got, tc.header)
			}
			var langs []string
			if err := tab.Evaluate(ctx, "navigator.languages", &langs); err != nil {
				t.Fatalf("read languages: %v", err)
			}
			if strings.Join(langs, ",") != strings.Join(tc.languages, ",") {
				t.Errorf("navigator.languages = %v, want %v", langs, tc.languages)
			}
		})
	}
}

// The header and the page object have to agree, and through this mechanism they
// do without a shim.
//
// That is worth an assertion of its own because the alternative is what the Node
// solver shipped: an Object.defineProperty on navigator.languages, which leaves
// an own property where Navigator.prototype is the only place one belongs, and a
// getter that stringifies as an arrow function where every native one reads
// [native code]. Both are one probe away on the request that earns cf_clearance.
// Here the browser sets both halves itself, so there is nothing to detect.
func TestAcceptLanguageNeedsNoShim(t *testing.T) {
	b := testBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	site := newOrigin(t)

	tab, err := b.DefaultContext().NewTab(ctx)
	if err != nil {
		t.Fatalf("tab: %v", err)
	}
	defer tab.Close(ctx)

	if err := tab.SetUserAgent(ctx, "", "tr-TR,tr", "", nil); err != nil {
		t.Fatalf("set user agent: %v", err)
	}
	if err := tab.Navigate(ctx, site.server.URL); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	// The header the edge reads and the list the challenge's JavaScript reads
	// name the same languages in the same order.
	if got := site.header("Accept-Language"); got != "tr-TR,tr;q=0.9" {
		t.Fatalf("Accept-Language = %q, want tr-TR,tr;q=0.9", got)
	}

	// And navigator.languages is still the native accessor: no own property on
	// the instance, and a getter that reads [native code].
	var own bool
	if err := tab.Evaluate(ctx,
		`Object.prototype.hasOwnProperty.call(navigator, "languages")`, &own); err != nil {
		t.Fatalf("read own property: %v", err)
	}
	if own {
		t.Error("navigator has an own 'languages' property: something shimmed it")
	}

	var getterSource string
	err = tab.Evaluate(ctx,
		`String(Object.getOwnPropertyDescriptor(Navigator.prototype, "languages").get)`,
		&getterSource)
	if err != nil {
		t.Fatalf("read getter: %v", err)
	}
	if !strings.Contains(getterSource, "[native code]") {
		t.Errorf("navigator.languages getter = %q, want a native one", getterSource)
	}
}
