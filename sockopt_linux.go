//go:build linux

package gofire

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setSocketOpts(fd uintptr) error {
	// TCP_NODELAY - disable Nagle's algorithm for lower latency
	if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
		return err
	}

	// TCP_QUICKACK - send ACKs immediately
	if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, unix.TCP_QUICKACK, 1); err != nil {
		return err
	}

	// SO_REUSEADDR
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}

	// Increase socket buffer sizes
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256*1024)
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 256*1024)

	return nil
}
