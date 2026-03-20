//go:build !linux

package gofire

func setSocketOpts(fd uintptr) error {
	return nil
}
