package cdp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// LaunchConfig is everything the browser needs to come up.
type LaunchConfig struct {
	// ExecPath is the browser binary. Empty means Find() picks one.
	ExecPath string
	// Args are the command line flags, minus the ones this package owns
	// (--remote-debugging-pipe, --user-data-dir, the headless switch).
	Args []string
	// UserDataDir is the profile. Empty means a temporary one, removed on Close.
	UserDataDir string
	// Headless runs without a display. The default is a headful browser, because
	// that is what the identity being claimed is — see Headless below.
	Headless bool
	// Env is the browser's environment. nil inherits this process's.
	Env []string
	// Stderr receives the browser's diagnostics. nil discards them.
	Stderr *os.File
}

// Browser is a running Chromium and the connection to it.
type Browser struct {
	cfg     LaunchConfig
	cmd     *exec.Cmd
	conn    *conn
	xvfb    *xvfbDisplay
	tmpDir  string
	Version Version

	closeOnce chan struct{}
}

// Version is what Browser.getVersion reports.
type Version struct {
	ProtocolVersion string `json:"protocolVersion"`
	Product         string `json:"product"` // "Chrome/141.0.7390.37"
	Revision        string `json:"revision"`
	UserAgent       string `json:"userAgent"` // the browser's own, before any override
	JSVersion       string `json:"jsVersion"`
}

// candidates are the binaries a Chromium is usually installed as, most specific
// first. Chrome for Testing and the Playwright download live under paths that
// are not on PATH at all, which is why the list carries absolute entries too:
// the box this runs on is as likely to have one of those as a packaged browser.
var candidates = []string{
	"google-chrome-stable",
	"google-chrome",
	"chromium-browser",
	"chromium",
	"chrome",
	"/opt/google/chrome/chrome",
	"/usr/bin/chromium",
	"/usr/bin/chromium-browser",
	"/snap/bin/chromium",
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
}

// Find locates a browser to drive.
//
// SOLVER_CHROME wins outright, because a box with several Chromiums installed
// is exactly the box where the one this picks matters: cf_clearance is bound to
// the JA4 of the session that issued it, and two builds do not necessarily send
// the same ClientHello.
func Find() (string, error) {
	if p := os.Getenv("SOLVER_CHROME"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("SOLVER_CHROME=%s: %w", p, err)
		}
		return p, nil
	}
	// PLAYWRIGHT_BROWSERS_PATH holds a Chromium on any box that has ever run
	// Playwright, and it is a full browser rather than a headless shell.
	if root := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); root != "" {
		matches, _ := filepath.Glob(filepath.Join(root, "chromium-*", "chrome-linux", "chrome"))
		if len(matches) > 0 {
			return matches[len(matches)-1], nil
		}
	}
	for _, c := range candidates {
		if strings.ContainsRune(c, os.PathSeparator) {
			if _, err := os.Stat(c); err == nil {
				return c, nil
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no Chrome or Chromium found: install one, or set SOLVER_CHROME to its path")
}

// Launch starts a browser and connects to it.
func Launch(ctx context.Context, cfg LaunchConfig) (*Browser, error) {
	if cfg.ExecPath == "" {
		p, err := Find()
		if err != nil {
			return nil, err
		}
		cfg.ExecPath = p
	}

	b := &Browser{cfg: cfg, closeOnce: make(chan struct{})}

	if cfg.UserDataDir == "" {
		// A profile per launch, and a fresh one. A shared profile carries the
		// previous solve's cookies into this one, which in a batch is how one
		// exit ends up presenting another exit's cf_clearance.
		dir, err := os.MkdirTemp("", "gofire-solver-")
		if err != nil {
			return nil, fmt.Errorf("profile dir: %w", err)
		}
		b.tmpDir = dir
		cfg.UserDataDir = dir
	}

	env := cfg.Env
	if env == nil {
		env = os.Environ()
	}

	// A headful browser with nowhere to draw fails to start, so the display is
	// arranged before the launch rather than diagnosed after it.
	if !cfg.Headless && runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" {
		x, err := startXvfb()
		if err != nil {
			// No Xvfb and no display: headless is the honest fallback. It is a
			// worse browser to solve from — see Headless — and saying so is
			// better than a launch that dies with "Missing X server".
			cfg.Headless = true
			fmt.Fprintf(os.Stderr, "solver: no DISPLAY and no Xvfb (%v); falling back to headless\n", err)
		} else {
			b.xvfb = x
			env = append(env, "DISPLAY="+x.display)
		}
	}

	args := []string{
		"--remote-debugging-pipe",
		"--user-data-dir=" + cfg.UserDataDir,
	}
	if cfg.Headless {
		args = append(args, "--headless=new")
	}
	args = append(args, cfg.Args...)
	args = append(args, "about:blank")

	// fd 3 is the browser's input (we write commands), fd 4 its output (we read
	// responses and events). ExtraFiles[0] becomes fd 3 because 0,1,2 are taken.
	inR, inW, err := os.Pipe()
	if err != nil {
		b.cleanup()
		return nil, fmt.Errorf("devtools pipe: %w", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		b.cleanup()
		return nil, fmt.Errorf("devtools pipe: %w", err)
	}

	cmd := exec.Command(cfg.ExecPath, args...)
	cmd.Env = env
	cmd.ExtraFiles = []*os.File{inR, outW}
	if cfg.Stderr != nil {
		cmd.Stderr = cfg.Stderr
	}
	// Its own process group, so killing it kills the renderers and the GPU
	// process with it. Chromium's children outlive a bare kill of the parent,
	// and on the small boxes this runs on that is the difference between one
	// browser and a machine full of them.
	setProcessGroup(cmd)

	if err := cmd.Start(); err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		b.cleanup()
		return nil, fmt.Errorf("launch %s: %w", cfg.ExecPath, err)
	}
	// The child holds its own ends now; ours would keep the pipes open past the
	// browser's exit and turn a dead browser into a read that never returns.
	inR.Close()
	outW.Close()

	b.cmd = cmd
	b.conn = newConn(inW, outR)

	// The first command is also the liveness check: a browser that died on its
	// command line answers nothing, and finding that out here names the launch
	// rather than the first navigation.
	verCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := b.conn.call(verCtx, "", "Browser.getVersion", nil, &b.Version); err != nil {
		b.Close()
		return nil, fmt.Errorf("browser did not answer after launch: %w", err)
	}
	return b, nil
}

// Close ends the browser and everything it started.
func (b *Browser) Close() error {
	select {
	case <-b.closeOnce:
		return nil
	default:
		close(b.closeOnce)
	}

	if b.conn != nil {
		// Ask first: a graceful Browser.close lets Chromium flush its profile,
		// which matters when the profile is not temporary.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = b.conn.call(ctx, "", "Browser.close", nil, nil)
		cancel()
		b.conn.close()
	}

	if b.cmd != nil && b.cmd.Process != nil {
		done := make(chan struct{})
		go func() { _, _ = b.cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			killProcessGroup(b.cmd)
			<-done
		}
	}
	b.cleanup()
	return nil
}

func (b *Browser) cleanup() {
	if b.xvfb != nil {
		b.xvfb.stop()
		b.xvfb = nil
	}
	if b.tmpDir != "" {
		os.RemoveAll(b.tmpDir)
		b.tmpDir = ""
	}
}

// PID is the browser process, for callers that track process trees.
func (b *Browser) PID() int {
	if b.cmd == nil || b.cmd.Process == nil {
		return 0
	}
	return b.cmd.Process.Pid
}
