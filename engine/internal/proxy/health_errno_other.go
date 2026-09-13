//go:build !windows

package proxy

import "syscall"

// isLocalConnectErrno reports whether a connect failure came from the local
// stack or from an interface disappearing underneath a pinned socket, rather
// than from the remote target. Only the former may cool an adapter down:
// blaming the adapter for one unreachable destination would drain the pool.
func isLocalConnectErrno(errno syscall.Errno) bool {
	switch errno {
	// EINVAL is deliberately absent: unlike WSAEINVAL on Windows, Unix connect
	// does not use it to signal a disabled local interface.
	case syscall.EADDRNOTAVAIL,
		syscall.ENETDOWN,
		syscall.ENETUNREACH,
		syscall.ENETRESET,
		syscall.EHOSTDOWN,
		syscall.EHOSTUNREACH:
		return true
	}
	return false
}
