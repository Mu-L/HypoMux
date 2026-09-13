//go:build !windows

package proxy

import (
	"syscall"
	"testing"
)

func TestLocalConnectErrnoClassifiesUnixCodes(t *testing.T) {
	local := map[string]syscall.Errno{
		"EADDRNOTAVAIL": syscall.EADDRNOTAVAIL,
		"ENETDOWN":      syscall.ENETDOWN,
		"ENETUNREACH":   syscall.ENETUNREACH,
		"ENETRESET":     syscall.ENETRESET,
		"EHOSTDOWN":     syscall.EHOSTDOWN,
		"EHOSTUNREACH":  syscall.EHOSTUNREACH,
	}
	for name, errno := range local {
		if !isLocalConnectErrno(errno) {
			t.Errorf("%s (%d) was not classified as a local failure", name, uintptr(errno))
		}
	}
	remote := map[string]syscall.Errno{
		"ECONNREFUSED": syscall.ECONNREFUSED,
		"ECONNRESET":   syscall.ECONNRESET,
		"ETIMEDOUT":    syscall.ETIMEDOUT,
	}
	for name, errno := range remote {
		if isLocalConnectErrno(errno) {
			t.Errorf("%s (%d) was classified as a local failure", name, uintptr(errno))
		}
	}
}
