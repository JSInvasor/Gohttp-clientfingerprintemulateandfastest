//go:build !linux

package gofire

func setSocketOpts(fd uintptr, rcvBuf, sndBuf int, fastOpen bool) error {
	_ = rcvBuf
	_ = sndBuf
	_ = fastOpen
	return nil
}
