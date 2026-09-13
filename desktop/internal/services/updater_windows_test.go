//go:build windows

package services

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateDownloadedInstallerPathRequiresOwnedTempDirectory(t *testing.T) {
	owned, err := os.MkdirTemp("", "HypoMuxUpdate-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(owned)
	installer := filepath.Join(owned, "HypoMux_Setup_2.3.1.exe")
	if err := os.WriteFile(installer, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateDownloadedInstallerPath(installer); err != nil {
		t.Fatalf("owned installer rejected: %v", err)
	}

	foreign, err := os.MkdirTemp("", "ForeignUpdate-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(foreign)
	foreignInstaller := filepath.Join(foreign, "HypoMux_Setup_2.3.1.exe")
	if err := os.WriteFile(foreignInstaller, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateDownloadedInstallerPath(foreignInstaller); err == nil {
		t.Fatal("foreign temporary installer was accepted")
	}
}

func TestValidateDownloadedInstallerPathRejectsUnexpectedName(t *testing.T) {
	owned, err := os.MkdirTemp("", "HypoMuxUpdate-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(owned)
	installer := filepath.Join(owned, "payload.exe")
	if err := os.WriteFile(installer, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateDownloadedInstallerPath(installer); err == nil {
		t.Fatal("unexpected installer name was accepted")
	}
}

func TestVerifyDownloadedInstallerAuthenticityRejectsUnsignedFile(t *testing.T) {
	installer := filepath.Join(t.TempDir(), "HypoMux_Setup_2.5.8.exe")
	if err := os.WriteFile(installer, []byte("not a signed executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDownloadedInstallerAuthenticity(installer); err == nil {
		t.Fatal("unsigned installer was accepted")
	}
}

func TestVerifyDownloadedInstallerAuthenticityAcceptsOfficialSignedInstaller(t *testing.T) {
	installer := os.Getenv("HYPOMUX_SIGNED_INSTALLER_TEST")
	if installer == "" {
		t.Skip("set HYPOMUX_SIGNED_INSTALLER_TEST to an official signed installer")
	}
	if err := verifyDownloadedInstallerAuthenticity(installer); err != nil {
		t.Fatalf("official signed installer rejected: %v", err)
	}
}

func TestIsRevokedCertificateErrorOnlyAcceptsDefinitiveRevocation(t *testing.T) {
	revoked := []error{
		syscall.Errno(trustERevoked),
		syscall.Errno(windows.CRYPT_E_REVOKED),
		fmt.Errorf("wrapped: %w", syscall.Errno(trustERevoked)),
	}
	for _, err := range revoked {
		if !isRevokedCertificateError(err) {
			t.Errorf("revocation result %v was not recognised", err)
		}
	}
	// Inconclusive results must not count: treating an unreachable CRL server as
	// revocation would block updates for every offline or firewalled machine.
	inconclusive := []error{
		syscall.Errno(windows.CRYPT_E_REVOCATION_OFFLINE),
		syscall.Errno(windows.CRYPT_E_NO_REVOCATION_CHECK),
		syscall.Errno(windows.CRYPT_E_NO_REVOCATION_DLL),
		syscall.Errno(windows.TRUST_E_NOSIGNATURE),
		errors.New("plain failure"),
	}
	for _, err := range inconclusive {
		if isRevokedCertificateError(err) {
			t.Errorf("inconclusive result %v was treated as revocation", err)
		}
	}
}

func TestCheckInstallerRevocationFailsOpenWithoutRevocationEvidence(t *testing.T) {
	installer := filepath.Join(t.TempDir(), "HypoMux_Setup_2.5.8.exe")
	if err := os.WriteFile(installer, []byte("not a signed executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkInstallerRevocation(installer); err != nil {
		t.Fatalf("revocation pass blocked an installer without revocation evidence: %v", err)
	}
}

func TestLaunchInstallerRejectsUnsignedFileBeforeCreatingHelper(t *testing.T) {
	directory, err := os.MkdirTemp("", "HypoMuxUpdate-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	installer := filepath.Join(directory, "HypoMux_Setup_2.5.8.exe")
	if err := os.WriteFile(installer, []byte("not a signed executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := launchInstallerAfterExit(installer, os.Getpid()); err == nil {
		t.Fatal("unsigned installer reached the launcher")
	}
	if _, err := os.Stat(filepath.Join(directory, "run-update.cmd")); !os.IsNotExist(err) {
		t.Fatal("launcher helper was created before Authenticode validation")
	}
}
