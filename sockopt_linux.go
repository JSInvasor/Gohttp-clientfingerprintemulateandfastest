//go:build linux

package gofire

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setSocketOpts(fd uintptr, rcvBuf, sndBuf int, fastOpen bool) error {
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

	// TCP_FASTOPEN_CONNECT - lets the kernel send the SYN with payload when
	// reconnecting to a host we've seen before. Saves one RTT on repeat dials
	// to the same edge, which is the common pattern for sustained-load RPS
	// against a single target. Best-effort: many kernels/proxies will silently
	// fall back to a normal handshake if the cookie isn't cached.
	//
	// Off unless the caller asks for it. TFO is not a browser behaviour: Chrome
	// removed client support in 2020 and Safari does not use it for HTTPS, so a
	// SYN carrying TLS bytes is a transport-layer contradiction of the browser
	// this client spends the TLS and HTTP/2 layers impersonating. Enabling it
	// by default traded that away for an RTT without the caller ever seeing the
	// choice.
	if fastOpen {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
	}

	// Socket buffer sizes — configurable so callers can raise to multi-MB on
	// fat pipes (large bandwidth-delay product); defaults to 256KB.
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvBuf)
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, sndBuf)

	return nil
}
