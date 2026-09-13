//go:build windows

package services

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// lockProbeFromSecondHandle attempts the same byte-range lock through a separate
// file handle, which is what a concurrent --recover-network process would do.
func lockProbeFromSecondHandle(t *testing.T) error {
	t.Helper()
	file, err := os.OpenFile(proxySettingsLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open proxy settings lock: %v", err)
	}
	defer file.Close()
	return windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped),
	)
}

func TestProxySettingsLockExcludesSecondHolder(t *testing.T) {
	t.Setenv("HYPOMUX_DATA_DIR", t.TempDir())

	release := acquireProxySettingsLock()
	if err := lockProbeFromSecondHandle(t); !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		release()
		t.Fatalf("second holder acquired the held lock: %v", err)
	}
	release()

	if err := lockProbeFromSecondHandle(t); err != nil {
		t.Fatalf("lock was still held after release: %v", err)
	}
}

func TestProxySettingsLockFailsOpenWhenContended(t *testing.T) {
	t.Setenv("HYPOMUX_DATA_DIR", t.TempDir())

	release := acquireProxySettingsLock()
	defer release()

	// Recovery must never be blocked indefinitely by a contended or abandoned
	// lock, so acquisition gives up after the bounded timeout and proceeds.
	started := time.Now()
	contended := acquireProxySettingsLock()
	elapsed := time.Since(started)
	contended()

	if elapsed < proxySettingsLockTimeout {
		t.Fatalf("contended acquisition returned after %v, expected to wait out %v", elapsed, proxySettingsLockTimeout)
	}
	if elapsed > proxySettingsLockTimeout+2*time.Second {
		t.Fatalf("contended acquisition blocked for %v, want just over %v", elapsed, proxySettingsLockTimeout)
	}
}
