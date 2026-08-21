//go:build unix

package main

import "syscall"

// fdConnBudget is how many TLS connections the process can afford to hold open
// at once: most of the file-descriptor soft limit, with a slice reserved for
// stdio, DNS sockets and the fds in-flight requests need of their own. It is the
// ceiling a bare -tls maxes out to — "as many as the VPS allows".
func fdConnBudget() int {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return fallbackConnBudget
	}
	// int64 covers both the uint64 Cur on Linux/Darwin and the int64 on the BSDs.
	cur := int64(lim.Cur)
	// Three-quarters of the limit, less a fixed reserve.
	budget := cur - cur/4 - fdReserve
	switch {
	case budget < 1:
		return 1
	case budget > maxAutoConns:
		return maxAutoConns
	default:
		return int(budget)
	}
}
