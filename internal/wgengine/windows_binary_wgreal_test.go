//go:build wgreal

package wgengine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsPowerShellPathIsAbsoluteAndSystemOwned(t *testing.T) {
	const want = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	if windowsPowerShellPath != want {
		t.Fatalf("PowerShell path = %q, want %q", windowsPowerShellPath, want)
	}
}

func TestFindWindowsWireGuardBinaryPrefersCanonicalInstall(t *testing.T) {
	programFiles := t.TempDir()
	canonicalDir := filepath.Join(programFiles, "WireGuard")
	if err := os.Mkdir(canonicalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(canonicalDir, "wireguard.exe")
	if err := os.WriteFile(canonical, []byte("canonical"), 0o600); err != nil {
		t.Fatal(err)
	}

	pathDir := t.TempDir()
	pathBinary := filepath.Join(pathDir, "wireguard.exe")
	if err := os.WriteFile(pathBinary, []byte("path"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ProgramFiles", programFiles)
	t.Setenv("PATH", pathDir)

	got, err := findWindowsWireGuardBinary("wireguard")
	if err != nil {
		t.Fatal(err)
	}
	if got != canonical {
		t.Fatalf("binary = %q, want canonical install %q", got, canonical)
	}
}
