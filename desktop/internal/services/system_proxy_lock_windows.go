//go:build windows

package services

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

const (
	proxySettingsLockTimeout = 2 * time.Second
	proxySettingsLockRetry   = 25 * time.Millisecond
)

func proxySettingsLockPath() string {
	return filepath.Join(settingsDirectory(), "proxy-settings.lock")
}

// acquireProxySettingsLock serializes proxy marker and registry updates across
// processes. --recover-network runs in its own process and the installer runs it
// too, so the UI process's in-process lifecycle gate cannot keep either from
// interleaving with a proxy enable that is already in flight.
//
// The lock is a Windows byte-range lock, which the OS drops when the owning
// process exits, so a crash can never leave network recovery permanently
// blocked. When the lock cannot be acquired the returned release is a no-op and
// the caller proceeds anyway: refusing to restore the user's proxy is a worse
// outcome than the narrow check-then-write race the lock removes.
func acquireProxySettingsLock() (release func()) {
	if err := os.MkdirAll(filepath.Dir(proxySettingsLockPath()), 0o755); err != nil {
		return func() {}
	}
	file, err := os.OpenFile(proxySettingsLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}
	}
	handle := windows.Handle(file.Fd())
	overlapped := new(windows.Overlapped)
	deadline := time.Now().Add(proxySettingsLockTimeout)
	for {
		err := windows.LockFileEx(
			handle,
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0, 1, 0, overlapped,
		)
		if err == nil {
			return func() {
				_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
				_ = file.Close()
			}
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) || !time.Now().Before(deadline) {
			_ = file.Close()
			return func() {}
		}
		time.Sleep(proxySettingsLockRetry)
	}
}
