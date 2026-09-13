//go:build windows

package proxy

import (
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLocalConnectErrnoClassifiesWindowsCodes(t *testing.T) {
	local := map[string]syscall.Errno{
		"WSAEINVAL":                 windows.WSAEINVAL,
		"WSAEADDRNOTAVAIL":          windows.WSAEADDRNOTAVAIL,
		"WSAENETDOWN":               windows.WSAENETDOWN,
		"WSAENETUNREACH":            windows.WSAENETUNREACH,
		"WSAENETRESET":              windows.WSAENETRESET,
		"WSAEHOSTDOWN":              windows.WSAEHOSTDOWN,
		"WSAEHOSTUNREACH":           windows.WSAEHOSTUNREACH,
		"ERROR_INVALID_NETNAME":     windows.ERROR_INVALID_NETNAME,
		"ERROR_NO_NETWORK":          windows.ERROR_NO_NETWORK,
		"ERROR_NETWORK_UNREACHABLE": windows.ERROR_NETWORK_UNREACHABLE,
		"ERROR_HOST_UNREACHABLE":    windows.ERROR_HOST_UNREACHABLE,
	}
	for name, errno := range local {
		if !isLocalConnectErrno(errno) {
			t.Errorf("%s (%d) was not classified as a local failure", name, uintptr(errno))
		}
	}
	remote := map[string]syscall.Errno{
		"WSAECONNREFUSED": windows.WSAECONNREFUSED,
		"WSAECONNRESET":   windows.WSAECONNRESET,
		"WSAECONNABORTED": windows.WSAECONNABORTED,
		"WSAETIMEDOUT":    windows.WSAETIMEDOUT,
	}
	for name, errno := range remote {
		if isLocalConnectErrno(errno) {
			t.Errorf("%s (%d) was classified as a local failure", name, uintptr(errno))
		}
	}
}
