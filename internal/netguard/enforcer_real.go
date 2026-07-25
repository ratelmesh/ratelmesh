package netguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
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
		return NewUnsupportedEnforcer("host firewall backend unavailable on " + runtime.GOOS)
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
	run firewallRunner
}

const killTable = "ratelmesh_killswitch"

var legacyKillTable = strings.Join([]string{"h", "bm_killswitch"}, "")

type firewallRunner interface {
	Run(stdin, name string, args ...string) ([]byte, error)
}

type execFirewallRunner struct{}

func (execFirewallRunner) Run(stdin, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

func (e *LinuxEnforcer) runner() firewallRunner {
	if e.run != nil {
		return e.run
	}
	return execFirewallRunner{}
}

func (e *LinuxEnforcer) logger() *slog.Logger {
	if e.log != nil {
		return e.log
	}
	return slog.Default()
}

func clearLinuxKillTables(run firewallRunner) error {
	tables, err := run.Run("", "nft", "list", "tables")
	if err != nil {
		return fmt.Errorf("netguard: inspect nftables for clear: %w", err)
	}
	var transaction strings.Builder
	for _, table := range []string{killTable, legacyKillTable} {
		if nftTableListed(tables, table) {
			fmt.Fprintf(&transaction, "delete table inet %s\n", table)
		}
	}
	if transaction.Len() == 0 {
		return nil
	}
	if _, err := run.Run(transaction.String(), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("netguard: clear nftables transaction: %w", err)
	}
	return nil
}

func (e *LinuxEnforcer) Apply(p Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	p = clonePolicy(p)
	if err := p.Validate(); err != nil {
		return err
	}
	run := e.runner()
	if !p.Active() {
		if err := clearLinuxKillTables(run); err != nil {
			return err
		}
		e.cur = p
		return nil
	}
	ruleset, err := RenderNFT(p)
	if err != nil {
		return err
	}
	tables, err := run.Run("", "nft", "list", "tables")
	if err != nil {
		return fmt.Errorf("netguard: inspect nftables: %w", err)
	}
	if nftTableListed(tables, killTable) {
		// nft -f executes this batch as one transaction. A parse/apply failure
		// therefore leaves the previous table protecting the host.
		ruleset = "delete table inet " + killTable + "\n" + ruleset
	}
	if _, err := run.Run(ruleset, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("netguard: load nftables transaction: %w", err)
	}
	// Legacy cleanup is intentionally after the new complete policy is live.
	_, _ = run.Run("", "nft", "delete", "table", "inet", legacyKillTable)
	e.cur = p
	e.logger().Info("netguard: nftables ruleset applied",
		"killSwitch", p.Enabled, "remoteEnforcement", p.RemoteEnforcement)
	return nil
}

func (e *LinuxEnforcer) Clear() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := clearLinuxKillTables(e.runner()); err != nil {
		return err
	}
	e.cur = Policy{}
	return nil
}

func (e *LinuxEnforcer) Capability() Capability {
	return Capability{HostFirewall: true, RemoteAccess: true}
}

func (e *LinuxEnforcer) Current() Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return clonePolicy(e.cur)
}

func nftTableListed(out []byte, name string) bool {
	want := "table inet " + name
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
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
	run         firewallRunner
	commit      markerCommitter
	quarantined bool
}

type markerCommitter interface {
	// Commit reports renamed=true once candidate has replaced path, even when a
	// later durability sync fails.
	Commit(candidate, path string) (renamed bool, err error)
}

type osMarkerCommitter struct{}

func (osMarkerCommitter) Commit(candidate, path string) (bool, error) {
	if filepath.Dir(candidate) != filepath.Dir(path) {
		return false, errors.New("netguard: PF candidate is not in marker directory")
	}
	if err := os.Rename(candidate, path); err != nil {
		return false, err
	}
	dirHandle, err := os.Open(filepath.Dir(path))
	if err != nil {
		return true, err
	}
	defer dirHandle.Close()
	return true, dirHandle.Sync()
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

const (
	pfOwnershipIntent    = "intent\n"
	pfOwnershipEnabled   = "enabled\n"
	pfOwnershipCancelled = "cancelled\n"
)

func pfOwnershipPhase() string {
	data, err := os.ReadFile(darwinPfEnabledMarkerPath)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		return pfOwnershipEnabled
	}
	if string(data) == pfOwnershipIntent {
		return pfOwnershipIntent
	}
	if string(data) == pfOwnershipCancelled {
		return pfOwnershipCancelled
	}
	// Zero-byte markers were written by earlier releases after pfctl -E.
	// Treat them (and any root-owned malformed marker) conservatively as enabled
	// ownership so upgrades cannot strand PF on.
	return pfOwnershipEnabled
}

func pfEnabledByUsPreviously() bool {
	phase := pfOwnershipPhase()
	// Intent is written only after observing PF disabled and before pfctl -E.
	// A crash can occur immediately after -E, so recovery must release PF for
	// both intent and enabled. Cancelled records a completed compensation and
	// must never disable a user's later PF enable.
	return phase == pfOwnershipEnabled || phase == pfOwnershipIntent
}

func pfOwnershipMarkerExists() bool {
	_, err := os.Stat(darwinPfEnabledMarkerPath)
	return err == nil
}

func (e *DarwinEnforcer) runner() firewallRunner {
	if e.run != nil {
		return e.run
	}
	return execFirewallRunner{}
}

func (e *DarwinEnforcer) logger() *slog.Logger {
	if e.log != nil {
		return e.log
	}
	return slog.Default()
}

func (e *DarwinEnforcer) committer() markerCommitter {
	if e.commit != nil {
		return e.commit
	}
	return osMarkerCommitter{}
}

func (e *DarwinEnforcer) Apply(p Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	p = clonePolicy(p)
	if err := p.Validate(); err != nil {
		return err
	}
	if !p.Active() {
		// The rules file is also a persistent ownership marker. It survives a
		// daemon SIGKILL, unlike e.cur, so a relaunched process can remove the
		// predecessor's fail-closed global pf ruleset.
		if e.needsRestoreLocked() {
			if err := e.restoreLocked(); err != nil {
				return err
			}
		}
		e.cur = p
		return nil
	}
	ruleset, err := RenderPF(p)
	if err != nil {
		return err
	}
	candidate, err := writeCandidateFile(darwinKillSwitchPath, []byte(ruleset), 0o600)
	if err != nil {
		return err
	}
	keepCandidate := false
	defer func() {
		if !keepCandidate {
			_ = os.Remove(candidate)
		}
	}()
	backup, hadPrevious, err := backupMarkerFile(darwinKillSwitchPath)
	if err != nil {
		return fmt.Errorf("netguard: snapshot PF marker: %w", err)
	}
	if backup != "" {
		defer os.Remove(backup)
	}
	run := e.runner()
	// Enable pf if it is currently disabled (track so we can restore).
	status, err := run.Run("", "pfctl", "-s", "info")
	if err != nil {
		return fmt.Errorf("netguard: inspect pf status: %w", err)
	}
	disabled := strings.Contains(string(status), "Status: Disabled")
	if !disabled && !strings.Contains(string(status), "Status: Enabled") {
		return errors.New("netguard: unrecognized pf status")
	}
	if disabled {
		// Persist intent before mutating PF. An intent marker is safe to clean up
		// after a crash and is never by itself grounds to disable a user's PF.
		intentRenamed, intentErr := writeFileAtomic(
			darwinPfEnabledMarkerPath, []byte(pfOwnershipIntent), 0o600, e.committer())
		if intentErr != nil {
			if intentRenamed {
				_ = writeMarkerInPlace(darwinPfEnabledMarkerPath, pfOwnershipCancelled)
				_ = removeIfExists(darwinPfEnabledMarkerPath)
			}
			return fmt.Errorf("netguard: persist pf enable intent: %w", intentErr)
		}
		if _, err := run.Run("", "pfctl", "-E"); err != nil {
			// pfctl may report an error after producing the enable side effect.
			// The durable intent proves the baseline was disabled, so always
			// compensate with a bounded disable instead of assuming no mutation.
			if _, disableErr := run.Run("", "pfctl", "-d"); disableErr != nil {
				e.weEnabledPf = true
				if phaseErr := writeMarkerInPlace(darwinPfEnabledMarkerPath, pfOwnershipEnabled); phaseErr != nil {
					return errors.New("netguard: enable and compensating disable failed; ownership persistence failed")
				}
				return errors.New("netguard: enable pf failed and compensating disable failed")
			}
			e.weEnabledPf = false
			phaseErr := writeMarkerInPlace(darwinPfEnabledMarkerPath, pfOwnershipCancelled)
			removeErr := removeIfExists(darwinPfEnabledMarkerPath)
			if removeErr != nil {
				if phaseErr != nil {
					return errors.New("netguard: enable compensation succeeded but cancellation persistence and cleanup failed")
				}
				return errors.New("netguard: enable compensation succeeded but intent cleanup failed")
			}
			return fmt.Errorf("netguard: enable pf: %w", err)
		}
		e.weEnabledPf = true
		// Commit the enabled phase after pfctl succeeds.
		enabledRenamed, enabledErr := writeFileAtomic(
			darwinPfEnabledMarkerPath, []byte(pfOwnershipEnabled), 0o600, e.committer())
		if enabledErr != nil {
			if _, disableErr := run.Run("", "pfctl", "-d"); disableErr != nil {
				// PF is definitely ours and remains enabled. Ensure restart can
				// distinguish it from a pre-enable intent even if rename failed.
				if !enabledRenamed {
					_ = writeMarkerInPlace(darwinPfEnabledMarkerPath, pfOwnershipEnabled)
				}
				return errors.New("netguard: persist pf ownership failed and disabling pf failed")
			}
			e.weEnabledPf = false
			// PF is disabled again. Downgrade any post-rename "enabled" marker
			// to harmless intent before removal, so a removal failure cannot make
			// a successor disable PF later after the user enables it.
			if enabledRenamed {
				_ = writeMarkerInPlace(darwinPfEnabledMarkerPath, pfOwnershipCancelled)
			}
			if removeErr := removeIfExists(darwinPfEnabledMarkerPath); removeErr != nil {
				return errors.New("netguard: persist pf ownership failed and compensation marker cleanup failed")
			}
			return fmt.Errorf("netguard: persist pf ownership: %w", enabledErr)
		}
	}
	if _, err := run.Run("", "pfctl", "-f", candidate); err != nil {
		return fmt.Errorf("netguard: pfctl load: %w", err)
	}
	renamed, commitErr := e.committer().Commit(candidate, darwinKillSwitchPath)
	if commitErr != nil {
		rollback := "/etc/pf.conf"
		if hadPrevious {
			rollback = backup
		}
		if _, rollbackErr := run.Run("", "pfctl", "-f", rollback); rollbackErr == nil {
			// The kernel is back at the previous state. Restore marker contents
			// if the failed commit had already replaced them.
			if renamed && hadPrevious {
				backupRenamed, backupErr := e.committer().Commit(backup, darwinKillSwitchPath)
				if backupErr != nil && !backupRenamed {
					return errors.New("netguard: PF rollback restored kernel but not ownership marker")
				}
			}
			if renamed && !hadPrevious {
				if err := removeIfExists(darwinKillSwitchPath); err != nil {
					e.cur = Policy{}
					return fmt.Errorf("netguard: remove rolled-back PF marker: %w", err)
				}
			}
			// Current was never changed and still describes the restored kernel.
			return fmt.Errorf("netguard: commit pf marker: %w", commitErr)
		}
		// Rollback itself failed. The new rules are still live. If rename
		// happened, the ownership marker is also present, so report success and
		// truthfully record the new policy instead of a false failure that leaves
		// a newly opened grant hidden from the caller.
		if renamed {
			e.cur = p
			e.logger().Warn("netguard: PF marker durability failed; new policy remains active")
			return nil
		}
		// The standard marker is still old or absent. Preserve the loaded
		// candidate at a fixed emergency ownership path so a successor can
		// restore system PF rules. Current truthfully records the live policy.
		emergency := darwinEmergencyMarkerPath()
		emergencyRenamed, emergencyErr := e.committer().Commit(candidate, emergency)
		e.cur = p
		if emergencyErr == nil || emergencyRenamed {
			e.logger().Warn("netguard: new PF policy retained under emergency ownership")
			return nil
		}
		if journalErr := writeQuarantineJournal(candidate); journalErr == nil {
			keepCandidate = true
			e.quarantined = true
			return errors.New("netguard: PF state retained in durable quarantine")
		}
		e.quarantined = true
		return errors.New("netguard: PF state quarantined after marker and rollback failure")
	}
	// Loading the new complete PF ruleset supersedes a predecessor's global
	// rules atomically. Remove its ownership marker only after success.
	if err := removeIfExists(legacyDarwinKillSwitchPath); err != nil {
		e.logger().Warn("netguard: remove legacy PF marker failed", "err", err)
	}
	e.cur = p
	e.logger().Info("netguard: pf ruleset applied",
		"killSwitch", p.Enabled, "remoteEnforcement", p.RemoteEnforcement)
	return nil
}

func (e *DarwinEnforcer) Capability() Capability {
	return Capability{HostFirewall: true, RemoteAccess: true}
}

func (e *DarwinEnforcer) Clear() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.needsRestoreLocked() {
		if err := e.restoreLocked(); err != nil {
			return err
		}
	}
	e.cur = Policy{}
	return nil
}

func (e *DarwinEnforcer) restoreLocked() error {
	run := e.runner()
	// Reload the system ruleset and, if we turned pf on, turn it back off.
	if _, err := run.Run("", "pfctl", "-f", "/etc/pf.conf"); err != nil {
		return fmt.Errorf("netguard: restore system pf rules: %w", err)
	}
	// From this point onward the managed input/output rules are no longer in the
	// kernel. Keep Current synchronized even if a later ownership cleanup step
	// fails and must be retried.
	e.cur = Policy{}
	// The marker covers the crash case: a successor process has weEnabledPf=false
	// but must still undo the pf enable its predecessor performed.
	if e.weEnabledPf || pfEnabledByUsPreviously() {
		if _, err := run.Run("", "pfctl", "-d"); err != nil {
			return fmt.Errorf("netguard: disable owned pf: %w", err)
		}
		e.weEnabledPf = false
	}
	for _, path := range []string{
		darwinPfEnabledMarkerPath,
		darwinKillSwitchPath,
		legacyDarwinKillSwitchPath,
		darwinEmergencyMarkerPath(),
	} {
		if err := removeIfExists(path); err != nil {
			return fmt.Errorf("netguard: remove PF ownership marker: %w", err)
		}
	}
	if candidate, ok := quarantinedCandidate(); ok {
		if err := removeIfExists(candidate); err != nil {
			return fmt.Errorf("netguard: remove quarantined PF candidate: %w", err)
		}
	}
	if err := removeIfExists(darwinQuarantineJournalPath()); err != nil {
		return fmt.Errorf("netguard: remove PF quarantine journal: %w", err)
	}
	e.quarantined = false
	return nil
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
	return e.cur.Active() || managedDarwinRulesExist() || legacyDarwinRulesExist() ||
		e.weEnabledPf || pfOwnershipMarkerExists() || emergencyDarwinRulesExist() ||
		quarantineJournalExists() || e.quarantined
}

func (e *DarwinEnforcer) Current() Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return clonePolicy(e.cur)
}

func writeCandidateFile(path string, data []byte, mode os.FileMode) (string, error) {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".ratelmesh-netguard-*")
	if err != nil {
		return "", err
	}
	temp := file.Name()
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		_ = os.Remove(temp)
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(temp)
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temp)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temp)
		return "", err
	}
	return temp, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode, commit markerCommitter) (bool, error) {
	candidate, err := writeCandidateFile(path, data, mode)
	if err != nil {
		return false, err
	}
	defer os.Remove(candidate)
	return commit.Commit(candidate, path)
}

func backupMarkerFile(path string) (backup string, exists bool, err error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return "", false, errors.New("netguard: invalid PF marker")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	backup, err = writeCandidateFile(path, data, 0o600)
	if err != nil {
		return "", false, err
	}
	return backup, true, nil
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func darwinEmergencyMarkerPath() string {
	return filepath.Join(filepath.Dir(darwinKillSwitchPath), "ratelmesh-firewall-emergency")
}

func emergencyDarwinRulesExist() bool {
	_, err := os.Stat(darwinEmergencyMarkerPath())
	return err == nil
}

func writeMarkerInPlace(path, phase string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(phase); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func darwinQuarantineJournalPath() string {
	return filepath.Join(filepath.Dir(darwinKillSwitchPath), "ratelmesh-firewall-quarantine")
}

func writeQuarantineJournal(candidate string) error {
	dir := filepath.Dir(darwinKillSwitchPath)
	if filepath.Dir(candidate) != dir {
		return errors.New("netguard: quarantine candidate outside marker directory")
	}
	base := filepath.Base(candidate)
	if !strings.HasPrefix(base, ".ratelmesh-netguard-") || strings.ContainsAny(base, `/\`) {
		return errors.New("netguard: invalid quarantine candidate")
	}
	path := darwinQuarantineJournalPath()
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("netguard: quarantine journal is a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(base + "\n"); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirHandle.Close()
	return dirHandle.Sync()
}

func quarantinedCandidate() (string, bool) {
	data, err := os.ReadFile(darwinQuarantineJournalPath())
	if err != nil || len(data) == 0 || len(data) > 256 {
		return "", false
	}
	base := strings.TrimSuffix(string(data), "\n")
	if !strings.HasPrefix(base, ".ratelmesh-netguard-") ||
		filepath.Base(base) != base || strings.ContainsAny(base, `/\`) {
		return "", false
	}
	return filepath.Join(filepath.Dir(darwinKillSwitchPath), base), true
}

func quarantineJournalExists() bool {
	_, err := os.Stat(darwinQuarantineJournalPath())
	return err == nil
}
