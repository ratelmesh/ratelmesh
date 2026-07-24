package exitstack

import (
	"strings"
	"testing"
)

func TestWindowsNATEnableScriptIsScopedAndFailSafe(t *testing.T) {
	script := windowsNATEnableScript("100.64.0.0/10", "ratelmesh0")
	for _, want := range []string{
		"Get-NetAdapter -Name 'ratelmesh0'",
		"-Forwarding Enabled",
		"Get-NetNat -Name 'RatelMesh'",
		"New-NetNat -Name 'RatelMesh' -InternalIPInterfaceAddressPrefix '100.64.0.0/10'",
		"-Forwarding Disabled",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("Windows NAT script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "Get-NetNat |") {
		t.Fatalf("Windows NAT script removes unrelated NAT instances:\n%s", script)
	}
}

func TestPowerShellSingleQuoteEscaping(t *testing.T) {
	if got := psSingleQuote("bad'name"); got != "bad''name" {
		t.Fatalf("escaped value = %q", got)
	}
}
