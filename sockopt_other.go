//go:build !linux

package gofire

func setSocketOpts(fd uintptr, rcvBuf, sndBuf int) error {
	_ = rcvBuf
	_ = sndBuf
	return nil
}
