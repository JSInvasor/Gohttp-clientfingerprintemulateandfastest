package solver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// What a page can see about the fact that it is being driven.
//
// This lives here rather than in internal/cdp because it has to measure the
// configuration that actually ships — the profile's launch flags — and the
// driver package cannot reach them. A surface probe against bare flags measures
// a browser nobody runs, which is how the first version of this test reported a
// leak the real solve does not have.
//
// Every entry is something a challenge reads. The point of the driver's design
// is that the honest answer to each is the one an ordinary browser gives, so
// this prints the whole surface: a change to the flags or the transport then
// shows up as a diff here rather than as a live 403 three weeks later.
func TestAutomationSurface(t *testing.T) {
	requireBrowser(t)

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer site.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The shipped launch flags, headless only because CI has no display.
	p := DefaultProfile()
	l := Launcher{Profile: p, Headless: true}
	b, err := l.launch(ctx, nil)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer b.Close()

	tab, err := b.DefaultContext().NewTab(ctx)
	if err != nil {
		t.Fatalf("tab: %v", err)
	}
	defer tab.Close(ctx)
	if err := l.prepare(ctx, tab, b.Version.Product); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := tab.Navigate(ctx, site.URL); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	var got struct {
		Webdriver      *bool    `json:"webdriver"`
		HasChrome      bool     `json:"hasChrome"`
		Plugins        int      `json:"plugins"`
		Languages      []string `json:"languages"`
		Permissions    string   `json:"permissions"`
		WebGLVendor    string   `json:"webglVendor"`
		WebGLRenderer  string   `json:"webglRenderer"`
		Platform       string   `json:"platform"`
		Timezone       string   `json:"timezone"`
		AutomationVars []string `json:"automationVars"`
		LanguagesOwn   bool     `json:"languagesOwn"`
	}

	err = tab.Evaluate(ctx, `(async () => {
	  // Variables the common automation stacks leave on window. rebrowser-patches
	  // exists largely to remove these; a driver that never injects a world has
	  // nothing to remove.
	  const suspects = [
	    "cdc_adoQpoasnfa76pfcZLmcfl_Array", "cdc_adoQpoasnfa76pfcZLmcfl_Promise",
	    "cdc_adoQpoasnfa76pfcZLmcfl_Symbol", "__webdriver_evaluate", "__selenium_evaluate",
	    "__webdriver_script_function", "__driver_evaluate", "__fxdriver_evaluate",
	    "__puppeteer_utility_world__", "__playwright__binding__", "_playwright_target_",
	    "__nightmare", "domAutomation", "domAutomationController",
	  ];

	  let permissions = "unavailable";
	  try {
	    const s = await navigator.permissions.query({name: "notifications"});
	    permissions = s.state + "/" + Notification.permission;
	  } catch (err) { permissions = "error"; }

	  let vendor = "", renderer = "";
	  try {
	    const gl = document.createElement("canvas").getContext("webgl");
	    const dbg = gl && gl.getExtension("WEBGL_debug_renderer_info");
	    if (dbg) {
	      vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
	      renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
	    }
	  } catch {}

	  return {
	    webdriver: navigator.webdriver,
	    hasChrome: typeof window.chrome === "object" && window.chrome !== null,
	    plugins: navigator.plugins.length,
	    languages: Array.from(navigator.languages),
	    permissions,
	    webglVendor: vendor,
	    webglRenderer: renderer,
	    platform: navigator.platform,
	    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
	    automationVars: suspects.filter((k) => k in window),
	    languagesOwn: Object.prototype.hasOwnProperty.call(navigator, "languages"),
	  };
	})()`, &got)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	pretty, _ := json.MarshalIndent(got, "", "  ")
	t.Logf("automation surface under the shipped launch flags:\n%s", pretty)

	// The one that decides, and the one this is a regression test for.
	//
	// navigator.webdriver is the most-read automation tell there is, and it is
	// true by default under --remote-debugging-*. What makes it false is
	// --disable-blink-features=AutomationControlled in Profile.LaunchArgs.
	// Measured on Chromium 141 through this driver's own transport:
	//
	//	pipe alone                                     navigator.webdriver = true
	//	pipe + --disable-blink-features=AutomationControlled            false
	//
	// So dropping that flag silently makes every solve announce itself, and
	// nothing else in the tree would catch it.
	if got.Webdriver == nil {
		t.Error("navigator.webdriver is undefined, which no Chrome reports")
	} else if *got.Webdriver {
		t.Error("navigator.webdriver is true — the page can see it is being driven; " +
			"--disable-blink-features=AutomationControlled is what makes it false")
	}

	// A driver that never injects a world leaves nothing behind. If this fires,
	// something started injecting one.
	if len(got.AutomationVars) > 0 {
		t.Errorf("automation variables on window: %v", got.AutomationVars)
	}

	// navigator.languages has to stay the native accessor. The Node solver
	// shimmed it with Object.defineProperty, which leaves exactly this.
	if got.LanguagesOwn {
		t.Error("navigator has an own 'languages' property: something shimmed it")
	}
	if len(got.Languages) == 0 {
		t.Error("navigator.languages is empty")
	}

	// Etc/Unknown is what an unconfigured container reports and what no installed
	// browser produces. The environment pin and the per-tab override both exist
	// to keep this a real zone.
	if got.Timezone == "" || got.Timezone == "Etc/Unknown" {
		t.Errorf("Intl timeZone = %q, want a zone a real browser could report", got.Timezone)
	}

	// Every real Chrome has a WebGL context. A browser with none is a far
	// stronger signal than one rendering in software, which is what any VM looks
	// like — hence --use-gl=angle --use-angle=swiftshader.
	if got.WebGLRenderer == "" {
		t.Error("no WebGL renderer: the software GL flags did not take")
	}

	// window.chrome is absent under --headless and present headful. It is a
	// property every real desktop Chrome has, which is why the solve runs headful
	// under Xvfb by default. These tests are headless, so this is reported rather
	// than failed — the value is the point.
	if !got.HasChrome {
		t.Logf("NOTE: window.chrome absent and plugins=%d — both are headless artefacts, "+
			"and the reason Launcher.Headless defaults to false", got.Plugins)
	}
}
