// SPDX-License-Identifier: Apache-2.0
//go:build linux

package path

import "syscall"

type liveSocket struct{ fd int }

func (s *liveSocket) FD() int      { return s.fd }
func (s *liveSocket) Close() error { return syscall.Close(s.fd) }

func openSocketFD() (*liveSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	return &liveSocket{fd: fd}, nil
}
