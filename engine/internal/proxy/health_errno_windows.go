//go:build windows

package proxy

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// isLocalConnectErrno reports whether a connect failure came from the local
// stack or from an interface disappearing underneath a pinned socket, rather
// than from the remote target. Only the former may cool an adapter down:
// blaming the adapter for one unreachable destination would drain the pool.
func isLocalConnectErrno(errno syscall.Errno) bool {
	switch errno {
	// WSAEINVAL is what Windows reports when dialing a socket still pinned to
	// an interface that has just been disabled.
	case windows.WSAEINVAL,
		windows.WSAEADDRNOTAVAIL,
		windows.WSAENETDOWN,
		windows.WSAENETUNREACH,
		windows.WSAENETRESET,
		windows.WSAEHOSTDOWN,
		windows.WSAEHOSTUNREACH:
		return true
	// Win32 codes surface on the same conditions when probing with ICMP.
	case windows.ERROR_INVALID_NETNAME,
		windows.ERROR_NO_NETWORK,
		windows.ERROR_NETWORK_UNREACHABLE,
		windows.ERROR_HOST_UNREACHABLE:
		return true
	}
	return false
}
