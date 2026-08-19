//go:build windows

package cdp

import "os/exec"

// Windows has no process groups in the POSIX sense, so the browser is started
// and killed as an ordinary process. Its children are reaped by the browser's
// own shutdown; a hard kill can leave them, which is the platform's behaviour
// rather than something this package can fix from here.
func setProcessGroup(cmd *exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
