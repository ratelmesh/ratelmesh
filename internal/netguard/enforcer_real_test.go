package netguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinEnforcerDetectsRulesFromCrashedProcess(t *testing.T) {
	oldPath := darwinKillSwitchPath
	oldLegacyPath := legacyDarwinKillSwitchPath
	darwinKillSwitchPath = filepath.Join(t.TempDir(), "ratelmesh-killswitch.pf.conf")
	legacyDarwinKillSwitchPath = filepath.Join(t.TempDir(), "legacy-killswitch.pf.conf")
	t.Cleanup(func() {
		darwinKillSwitchPath = oldPath
		legacyDarwinKillSwitchPath = oldLegacyPath
	})

	e := &DarwinEnforcer{}
	if e.needsRestoreLocked() {
		t.Fatal("fresh enforcer unexpectedly needs restore")
	}
	if err := os.WriteFile(darwinKillSwitchPath, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !e.needsRestoreLocked() {
		t.Fatal("new process did not detect predecessor's managed pf rules")
	}
}

func TestDarwinEnforcerDetectsLegacyCrashMarker(t *testing.T) {
	oldPath := darwinKillSwitchPath
	oldLegacyPath := legacyDarwinKillSwitchPath
	darwinKillSwitchPath = filepath.Join(t.TempDir(), "ratelmesh-killswitch.pf.conf")
	legacyDarwinKillSwitchPath = filepath.Join(t.TempDir(), "legacy-killswitch.pf.conf")
	t.Cleanup(func() {
		darwinKillSwitchPath = oldPath
		legacyDarwinKillSwitchPath = oldLegacyPath
	})
	if err := os.WriteFile(legacyDarwinKillSwitchPath, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &DarwinEnforcer{}
	if !e.needsRestoreLocked() {
		t.Fatal("legacy crash marker was ignored")
	}
	e.restoreLocked()
	if _, err := os.Stat(legacyDarwinKillSwitchPath); !os.IsNotExist(err) {
		t.Fatalf("legacy marker remained after restore: %v", err)
	}
}

// TestDarwinEnforcerClearsPfEnabledMarkerFromCrashedProcess covers the case a
// purely in-memory weEnabledPf cannot: the process that ran `pfctl -E` was
// SIGKILLed, so its successor starts with weEnabledPf=false and would otherwise
// leave pf enabled forever on a machine where the user had it disabled.
func TestDarwinEnforcerClearsPfEnabledMarkerFromCrashedProcess(t *testing.T) {
	oldMarker := darwinPfEnabledMarkerPath
	darwinPfEnabledMarkerPath = filepath.Join(t.TempDir(), "ratelmesh-pf-enabled")
	t.Cleanup(func() { darwinPfEnabledMarkerPath = oldMarker })

	if pfEnabledByUsPreviously() {
		t.Fatal("no marker written, but pf reported as previously enabled by us")
	}
	if err := os.WriteFile(darwinPfEnabledMarkerPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// A successor process: fresh struct, so weEnabledPf is false.
	e := &DarwinEnforcer{}
	if !pfEnabledByUsPreviously() {
		t.Fatal("successor did not detect the predecessor's pf-enabled marker")
	}
	e.restoreLocked()
	if _, err := os.Stat(darwinPfEnabledMarkerPath); !os.IsNotExist(err) {
		t.Fatalf("pf-enabled marker remained after restore: %v", err)
	}
}
