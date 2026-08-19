package cdp

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// A headful browser on a box with no display.
//
// The solve runs headful on purpose. --headless=new is close to a real browser
// and getting closer, but it is not the same browser: it reports a different
// build in Browser.getVersion, it takes different code paths in the compositor,
// and the surfaces a challenge can reach into — window.chrome, the permissions
// stack, screen metrics under a compositor that never composited — differ in
// ways nobody in this repo can enumerate from a sandbox. puppeteer-real-browser
// ran headful under Xvfb and that is the configuration this solver was measured
// passing a live Under Attack zone with, so it is the configuration kept.
//
// Xvfb is started here rather than through xvfb-run because the browser inherits
// file descriptors 3 and 4 from us and the wrapper script is not guaranteed to
// pass them through — some implementations exec, some run the command in a
// subshell, and the failure mode of the second is a browser that comes up and
// then answers nothing.
type xvfbDisplay struct {
	cmd     *exec.Cmd
	display string
	lock    string

	// exited closes once the reaper below has collected the process, and
	// waitErr is what it collected. There is exactly one cmd.Wait() per process
	// and it lives in that goroutine: Wait is the only thing that populates
	// ProcessState, and a second reap racing it — which is what stop() used to
	// do with Process.Wait — is undefined.
	exited  chan struct{}
	waitErr error
}

// startXvfb brings up a virtual display and returns the DISPLAY to point at it.
func startXvfb() (*xvfbDisplay, error) {
	bin, err := exec.LookPath("Xvfb")
	if err != nil {
		return nil, errors.New("Xvfb not installed")
	}

	// Display numbers are a global namespace on the box and two solves can run
	// at once, so a free one is searched for rather than assumed. The lock file
	// is X's own claim on the number; its absence is the cheap half of the test
	// and the server refusing to start is the other half.
	var lastErr error
	for i := 0; i < 20; i++ {
		num := 90 + rand.Intn(400)
		lock := fmt.Sprintf("/tmp/.X%d-lock", num)
		if _, err := os.Stat(lock); err == nil {
			continue
		}
		display := ":" + strconv.Itoa(num)

		// The geometry matches --window-size in the launch args. A screen
		// smaller than the window is a window that reports being clipped, and
		// window.outerWidth against screen.availWidth is one property read.
		cmd := exec.Command(bin, display, "-screen", "0", "1920x1080x24", "-nolisten", "tcp", "-ac")
		setProcessGroup(cmd)
		if err := cmd.Start(); err != nil {
			lastErr = err
			continue
		}

		x := &xvfbDisplay{cmd: cmd, display: display, lock: lock, exited: make(chan struct{})}
		go func() { x.waitErr = cmd.Wait(); close(x.exited) }()

		if err := x.waitReady(); err != nil {
			x.stop()
			lastErr = err
			continue
		}
		return x, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no free display number")
	}
	return nil, lastErr
}

// waitReady blocks until the server has claimed its lock file, or gives up.
//
// Xvfb forks and returns before it is listening, so a browser started on the
// strength of Start() alone races it and dies with "Missing X server". The lock
// file is what the server itself creates when it is ready to serve.
//
// A server that dies during startup has to end the wait, and the version this
// replaces could not see that happen: it tested cmd.ProcessState, which stays
// nil until cmd.Wait() is called and nothing here called it. So the guard never
// fired once, and an Xvfb that exited immediately — a display number claimed
// between the Stat and the Start, a missing font path, no permission on /tmp —
// cost the full ten seconds instead of the few milliseconds it took to fail.
// Twenty of those is the caller's whole budget spent finding out nothing.
// The signal is the reaper goroutine now, which is the only thing that can
// observe an exit without racing it.
func (x *xvfbDisplay) waitReady() error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(x.lock); err == nil {
			return nil
		}
		select {
		case <-x.exited:
			// The lock is re-read rather than assumed absent: a server that
			// came up and only then died still served, and reporting that as a
			// failed startup would send the caller to the next display number
			// for a reason that is not the one it would be told.
			if _, err := os.Stat(x.lock); err == nil {
				return nil
			}
			if x.waitErr != nil {
				return fmt.Errorf("Xvfb on %s exited during startup: %w", x.display, x.waitErr)
			}
			return fmt.Errorf("Xvfb on %s exited during startup", x.display)
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("Xvfb on %s did not come up within 10s", x.display)
}

// stop kills the server and waits for the reaper to collect it.
//
// It waits on the channel rather than reaping itself. Two Waits on one process
// is a race whichever way it lands, and the goroutine started in startXvfb owns
// this one.
func (x *xvfbDisplay) stop() {
	if x == nil || x.cmd == nil {
		return
	}
	killProcessGroup(x.cmd)
	if x.exited != nil {
		<-x.exited
	}
}
