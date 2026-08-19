//go:build !windows

package cdp

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the browser in a process group of its own.
//
// Chromium is a tree — a zygote, a renderer per tab, a GPU process — and none of
// those are children of ours, so killing the process we started leaves them
// running. A group is the handle that reaches all of them at once, and on the
// small VPS this is tuned for that is the difference between one browser and a
// box full of orphans.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup kills the group setProcessGroup created. A negative pid is
// the group; the plain Kill is the fallback for a browser that somehow never
// got one.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
