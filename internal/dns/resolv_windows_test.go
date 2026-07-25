package dns

import (
	"testing"
)

func TestWindowsPowerShellPathIsAbsoluteAndSystemOwned(t *testing.T) {
	const want = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	if windowsPowerShellPath != want {
		t.Fatalf("PowerShell path = %q, want %q", windowsPowerShellPath, want)
	}
}
