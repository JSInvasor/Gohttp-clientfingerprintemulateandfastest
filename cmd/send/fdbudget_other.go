//go:build !unix

package main

// fdConnBudget falls back to a fixed budget on platforms without an
// RLIMIT_NOFILE to read (Windows). A bare -tls still opens a healthy pool, just
// not one measured from the machine's descriptor limit.
func fdConnBudget() int {
	return fallbackConnBudget
}
