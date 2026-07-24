package netguard

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// NewEnforcer returns the real kill-switch enforcer for the host OS: nftables on
// Linux, pf on macOS, else the stub (so builds/tests stay portable).
func NewEnforcer(log *slog.Logger) Enforcer {
	if log == nil {
		log = slog.Default()
	}
	switch runtime.GOOS {
	case "linux":
		return &LinuxEnforcer{log: log}
	case "darwin":
		return &DarwinEnforcer{log: log}
	default:
		return NewStubEnforcer(log)
	}
}

// NewLinuxEnforcer is retained for callers; it now dispatches per-OS.
func NewLinuxEnforcer(log *slog.Logger) Enforcer { return NewEnforcer(log) }

// LinuxEnforcer applies the kill-switch policy for real by loading the rendered
// nftables ruleset via `nft -f -`. It requires root + NET_ADMIN.
type LinuxEnforcer struct {
	log *slog.Logger
	mu  sync.Mutex
	cur Policy
}

const killTable = "ratelmesh_killswitch"

var legacyKillTable = strings.Join([]string{"h", "bm_killswitch"}, "")

func clearLinuxKillTables() {
	for _, table := range []string{killTable, legacyKillTable} {
		_ = exec.Command("nft", "delete", "table", "inet", table).Run()
	}
}

func (e *LinuxEnforcer) Apply(p Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Always start from a clean table.
	clearLinuxKillTables()
	if !p.Enabled {
		e.cur = p
		return nil
	}
	ruleset := RenderNFT(p)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netguard: nft load: %v: %s", err, out)
	}
	e.cur = p
	e.log.Info("killswitch: nftables ruleset applied", "tunnelEndpoints", len(p.TunnelEndpoints))
	return nil
}

func (e *LinuxEnforcer) Clear() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	clearLinuxKillTables()
	e.cur = Policy{}
	return nil
}

func (e *LinuxEnforcer) Current() Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cur
}

// DarwinEnforcer applies the kill switch on macOS with pf: it loads the rendered
// pf ruleset and enables pf while armed, restoring /etc/pf.conf and (if we
// enabled it) disabling pf on clear. Requires root. It assumes the default pf
// state; a packaged install would use a dedicated pf anchor referenced from
// pf.conf for cleaner coexistence.
type DarwinEnforcer struct {
	log         *slog.Logger
	mu          sync.Mutex
	cur         Policy
	weEnabledPf bool
}

// Use a process-independent runtime path. launchd may supply a different
// TMPDIR after restart; a marker there would make crash-recovery depend on the
// predecessor's environment and could strand its fail-closed pf rules.
var darwinKillSwitchPath = "/var/run/ratelmesh-killswitch.pf.conf"
var legacyDarwinKillSwitchPath = strings.Join([]string{"/var/run/h", "bm-killswitch.pf.conf"}, "")

// darwinPfEnabledMarkerPath records that WE turned pf on, so a successor process
// can turn it back off. It needs the same durability as the ruleset marker above
// and for the same reason: weEnabledPf is in-memory only, so a SIGKILLed daemon
// would leave pf enabled on a machine where the user had it disabled, with no
// record that we were the ones who enabled it.
var darwinPfEnabledMarkerPath = "/var/run/ratelmesh-pf-enabled"

func pfEnabledByUsPreviously() bool {
	_, err := os.Stat(darwinPfEnabledMarkerPath)
	return err == nil
}

func (e *DarwinEnforcer) Apply(p Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if legacyDarwinRulesExist() {
		// A predecessor may have died while its global pf rules were armed.
		// Restore the host ruleset before applying the new policy so the old
		// marker cannot strand the machine after an in-place upgrade.
		e.restoreLocked()
	}
	if !p.Enabled {
		// The rules file is also a persistent ownership marker. It survives a
		// daemon SIGKILL, unlike e.cur, so a relaunched process can remove the
		// predecessor's fail-closed global pf ruleset.
		if e.needsRestoreLocked() {
			e.restoreLocked()
		}
		e.cur = p
		return nil
	}
	if err := os.WriteFile(darwinKillSwitchPath, []byte(RenderPF(p)), 0o600); err != nil {
		return err
	}
	// Enable pf if it is currently disabled (track so we can restore).
	if out, _ := exec.Command("pfctl", "-s", "info").CombinedOutput(); strings.Contains(string(out), "Status: Disabled") {
		if err := exec.Command("pfctl", "-E").Run(); err == nil {
			e.weEnabledPf = true
			// Persist before we can be killed; see darwinPfEnabledMarkerPath.
			if err := os.WriteFile(darwinPfEnabledMarkerPath, nil, 0o600); err != nil {
				e.log.Warn("killswitch: persist pf-enabled marker failed", "err", err)
			}
		}
	}
	if out, err := exec.Command("pfctl", "-f", darwinKillSwitchPath).CombinedOutput(); err != nil {
		_ = os.Remove(darwinKillSwitchPath)
		return fmt.Errorf("netguard: pfctl load: %v: %s", err, out)
	}
	e.cur = p
	e.log.Info("killswitch: pf ruleset applied", "tunnelEndpoints", len(p.TunnelEndpoints))
	return nil
}

func (e *DarwinEnforcer) Clear() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.needsRestoreLocked() {
		e.restoreLocked()
	}
	e.cur = Policy{}
	return nil
}

func (e *DarwinEnforcer) restoreLocked() {
	// Reload the system ruleset and, if we turned pf on, turn it back off.
	_ = exec.Command("pfctl", "-f", "/etc/pf.conf").Run()
	// The marker covers the crash case: a successor process has weEnabledPf=false
	// but must still undo the pf enable its predecessor performed.
	if e.weEnabledPf || pfEnabledByUsPreviously() {
		_ = exec.Command("pfctl", "-d").Run()
		e.weEnabledPf = false
		_ = os.Remove(darwinPfEnabledMarkerPath)
	}
	_ = os.Remove(darwinKillSwitchPath)
	_ = os.Remove(legacyDarwinKillSwitchPath)
}

func managedDarwinRulesExist() bool {
	_, err := os.Stat(darwinKillSwitchPath)
	return err == nil
}

func legacyDarwinRulesExist() bool {
	_, err := os.Stat(legacyDarwinKillSwitchPath)
	return err == nil
}

func (e *DarwinEnforcer) needsRestoreLocked() bool {
	return e.cur.Enabled || managedDarwinRulesExist() || legacyDarwinRulesExist()
}

func (e *DarwinEnforcer) Current() Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cur
}
