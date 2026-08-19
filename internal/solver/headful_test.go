package solver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/cdp"
)

// The configuration that actually ships: headful, under a virtual display.
//
// Every other test in this package runs headless, because CI may have no X
// server and the thing under test is usually the orchestration. But headless is
// not the browser the solve runs — Launcher.Headless defaults to false — and a
// suite that only ever exercises headless leaves the shipped path untested. That
// is how the Xvfb bring-up, the DISPLAY handover and the flags' behaviour under
// a compositor stay unverified until a live run finds them.
//
// It also measures the difference, which is the reason for the default:
// window.chrome and navigator.plugins are present headful and absent or reduced
// headless, and both are properties every real desktop Chrome has.
func TestHeadfulUnderXvfb(t *testing.T) {
	requireBrowser(t)
	if _, err := exec.LookPath("Xvfb"); err != nil {
		t.Skip("Xvfb not installed; the headful path needs a display")
	}
	// startXvfb only runs when there is no DISPLAY, which is the case this is
	// about. A box that has one is already covered by the launch itself.
	if os.Getenv("DISPLAY") != "" {
		t.Skip("DISPLAY is already set; this covers the no-display path")
	}

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<html><head><title>headful</title></head><body>ok</body></html>"))
	}))
	defer site.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	p := DefaultProfile()
	l := Launcher{Profile: p} // Headless false: the shipped default
	b, err := l.launch(ctx, nil)
	if err != nil {
		t.Fatalf("headful launch: %v", err)
	}
	defer b.Close()

	// A headful browser reports itself as Chrome, not HeadlessChrome. That is one
	// string a challenge can read directly from Browser.getVersion's UA, and the
	// difference is the whole reason for the default.
	t.Logf("browser: %s", b.Version.Product)
	t.Logf("native UA: %s", b.Version.UserAgent)

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
		HasChrome   bool     `json:"hasChrome"`
		ChromeKeys  []string `json:"chromeKeys"`
		Plugins     int      `json:"plugins"`
		MimeTypes   int      `json:"mimeTypes"`
		Webdriver   *bool    `json:"webdriver"`
		ScreenW     int      `json:"screenW"`
		ScreenH     int      `json:"screenH"`
		OuterW      int      `json:"outerW"`
		ColorDepth  int      `json:"colorDepth"`
		UserAgent   string   `json:"userAgent"`
		WebGLVendor string   `json:"webglVendor"`
	}
	err = tab.Evaluate(ctx, `(() => {
	  let vendor = "";
	  try {
	    const gl = document.createElement("canvas").getContext("webgl");
	    const dbg = gl && gl.getExtension("WEBGL_debug_renderer_info");
	    if (dbg) vendor = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
	  } catch {}
	  return {
	    hasChrome: typeof window.chrome === "object" && window.chrome !== null,
	    chromeKeys: window.chrome ? Object.keys(window.chrome) : [],
	    plugins: navigator.plugins.length,
	    mimeTypes: navigator.mimeTypes.length,
	    webdriver: navigator.webdriver,
	    screenW: screen.width, screenH: screen.height,
	    outerW: window.outerWidth,
	    colorDepth: screen.colorDepth,
	    userAgent: navigator.userAgent,
	    webglVendor: vendor,
	  };
	})()`, &got)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	t.Logf("headful surface: chrome=%v keys=%v plugins=%d mimeTypes=%d screen=%dx%d depth=%d webgl=%q",
		got.HasChrome, got.ChromeKeys, got.Plugins, got.MimeTypes,
		got.ScreenW, got.ScreenH, got.ColorDepth, got.WebGLVendor)

	// The identity pin has to survive the headful path exactly as it does
	// headless — it is applied per tab, so nothing about the display should
	// touch it, and asserting that is cheap.
	if got.UserAgent != p.UserAgent {
		t.Errorf("navigator.userAgent = %q, want the pinned identity", got.UserAgent)
	}
	if got.Webdriver == nil || *got.Webdriver {
		t.Error("navigator.webdriver is not false under the headful flags")
	}

	// window.chrome is the property headless drops. Its presence here is what
	// the default buys, so this is the one assertion that would notice the
	// headful path silently falling back.
	if !got.HasChrome {
		t.Error("window.chrome is absent under the headful launch: the fallback to " +
			"headless took, or the flags changed")
	}

	// The screen has to match the window the flags ask for. A 1920x1080 window on
	// an 800x600 root is a window reporting itself clipped, and outerWidth against
	// screen.availWidth is one property read.
	if got.ScreenW < 1920 || got.ScreenH < 1080 {
		t.Errorf("screen = %dx%d, want at least the 1920x1080 the Xvfb root is sized to",
			got.ScreenW, got.ScreenH)
	}
	if got.ColorDepth != 24 {
		t.Errorf("screen.colorDepth = %d, want 24", got.ColorDepth)
	}
}

// A batch through the headful path, because that is how a proxy list solves and
// it is the combination nothing else covers: one browser under Xvfb, a context
// per exit, and the isolation the pairing depends on.
func TestHeadfulBatchKeepsExitsApart(t *testing.T) {
	requireBrowser(t)
	if _, err := exec.LookPath("Xvfb"); err != nil {
		t.Skip("Xvfb not installed")
	}
	if os.Getenv("DISPLAY") != "" {
		t.Skip("DISPLAY is already set")
	}

	edge := newFakeEdge(t, 1200*time.Millisecond, "Just a moment...")

	batch, err := NewBatch([]Exit{{ID: "first"}, {ID: "second"}}, 2)
	if err != nil {
		t.Fatalf("NewBatch: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	p := DefaultProfile()
	opts := Options{Target: edge.server.URL + "/", Timeout: 60 * time.Second, Profile: &p}

	results := map[string]*Result{}
	var order []string
	err = SolveBatch(ctx, opts, batch, func(r BatchResult) {
		results[r.Exit.ID] = r.Result
		order = append(order, r.Exit.ID)
	})
	if err != nil {
		t.Fatalf("SolveBatch headful: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("reported %d exits, want 2 (%v)", len(results), order)
	}
	for id, res := range results {
		if res == nil || res.Status != StatusOK {
			t.Errorf("exit %s did not solve headful: %+v", id, res)
			continue
		}
		if res.ChromiumMajor == 0 {
			t.Errorf("exit %s reported no chromium version", id)
		}
	}
}

// The browser the solver drives has to have a WebGL context.
//
// Not a good one — a VPS has no GPU and software rendering is what any VM or
// RDP session looks like, which is fine. What is not fine is having none at
// all: a challenge reads the renderer, and every real Chrome answers. Chrome
// has deprecated the silent fallback to software WebGL and warns about it on
// every page load, so the launch args carry --enable-unsafe-swiftshader to opt
// back in. When that flag is no longer enough, this fails here rather than as a
// solve that earns a clearance the edge then refuses for reasons nothing prints.
func TestLaunchArgsKeepAWebGLContext(t *testing.T) {
	if _, err := cdp.Find(); err != nil {
		t.Skip("no browser:", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	b, err := cdp.Launch(ctx, cdp.LaunchConfig{
		Args:     DefaultProfile().LaunchArgs(),
		Headless: true, // the renderer question is the same either way
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer b.Close()

	tab, err := b.DefaultContext().NewTab(ctx)
	if err != nil {
		t.Fatalf("tab: %v", err)
	}
	defer tab.Close(ctx)

	var out struct {
		Context  bool   `json:"context"`
		Renderer string `json:"renderer"`
		Error    string `json:"error"`
	}
	err = tab.Evaluate(ctx, `(() => {
		const out = {context: false, renderer: "", error: ""};
		try {
			const c = document.createElement("canvas");
			const g = c.getContext("webgl") || c.getContext("experimental-webgl");
			if (!g) { out.error = "no webgl context"; return out; }
			out.context = true;
			const ext = g.getExtension("WEBGL_debug_renderer_info");
			out.renderer = String((ext && g.getParameter(ext.UNMASKED_RENDERER_WEBGL)) ||
				g.getParameter(g.RENDERER) || "");
		} catch (e) { out.error = String(e); }
		return out;
	})()`, &out)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	if !out.Context {
		t.Fatalf("the solver's browser has no WebGL context (%s) — every real Chrome has one, "+
			"and a challenge that reads the renderer sees the difference", out.Error)
	}
	if out.Renderer == "" {
		t.Errorf("WebGL context reports an empty renderer; a real browser names one")
	}
	t.Logf("renderer %q", out.Renderer)
}
