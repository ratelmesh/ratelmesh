package netguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type runnerCall struct {
	stdin string
	name  string
	args  []string
}

type scriptedRunner struct {
	calls     []runnerCall
	tables    []byte
	applyErr  error
	applyOut  []byte
	legacyErr error
}

type successRunner struct{}

func (successRunner) Run(string, string, ...string) ([]byte, error) {
	return []byte("Status: Enabled"), nil
}

type pfTestRunner struct {
	calls        []runnerCall
	restoreErr   error
	loadErr      error
	failLoadAt   int
	loadCount    int
	disableErr   error
	status       string
	beforeEnable func()
}

type postRenameFailCommitter struct {
	failPath string
	calls    []string
}

func (c *postRenameFailCommitter) Commit(candidate, path string) (bool, error) {
	c.calls = append(c.calls, path)
	if err := os.Rename(candidate, path); err != nil {
		return false, err
	}
	if path == c.failPath {
		return true, errors.New("injected directory fsync failure")
	}
	return true, nil
}

func (r *pfTestRunner) Run(stdin, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, runnerCall{stdin: stdin, name: name, args: append([]string(nil), args...)})
	if name != "pfctl" {
		return nil, errors.New("unexpected command")
	}
	if len(args) == 2 && args[0] == "-s" && args[1] == "info" {
		status := r.status
		if status == "" {
			status = "Status: Enabled"
		}
		return []byte(status), nil
	}
	if len(args) == 2 && args[0] == "-f" {
		if args[1] == "/etc/pf.conf" {
			return nil, r.restoreErr
		}
		r.loadCount++
		if r.loadErr != nil && (r.failLoadAt == 0 || r.loadCount == r.failLoadAt) {
			return nil, r.loadErr
		}
		return nil, nil
	}
	if len(args) == 1 && args[0] == "-E" && r.beforeEnable != nil {
		r.beforeEnable()
	}
	if len(args) == 1 && args[0] == "-d" {
		return nil, r.disableErr
	}
	return nil, nil
}

type nthPostRenameFailCommitter struct {
	path  string
	at    int
	count int
}

func (c *nthPostRenameFailCommitter) Commit(candidate, path string) (bool, error) {
	if err := os.Rename(candidate, path); err != nil {
		return false, err
	}
	if path == c.path {
		c.count++
		if c.count == c.at {
			return true, errors.New("injected post-rename sync failure")
		}
	}
	return true, nil
}

type preRenameFailCommitter struct {
	path string
}

func (c preRenameFailCommitter) Commit(candidate, path string) (bool, error) {
	if path == c.path {
		return false, errors.New("injected rename failure")
	}
	if err := os.Rename(candidate, path); err != nil {
		return false, err
	}
	return true, nil
}

type twoTargetFailCommitter struct {
	first  string
	second string
}

func (c twoTargetFailCommitter) Commit(candidate, path string) (bool, error) {
	if path == c.first || path == c.second {
		return false, errors.New("injected shared rename failure")
	}
	if err := os.Rename(candidate, path); err != nil {
		return false, err
	}
	return true, nil
}

func setDarwinTestPaths(t *testing.T) {
	t.Helper()
	oldRules := darwinKillSwitchPath
	oldLegacy := legacyDarwinKillSwitchPath
	oldEnabled := darwinPfEnabledMarkerPath
	root := t.TempDir()
	darwinKillSwitchPath = filepath.Join(root, "ratelmesh.pf")
	legacyDarwinKillSwitchPath = filepath.Join(root, "legacy.pf")
	darwinPfEnabledMarkerPath = filepath.Join(root, "enabled")
	t.Cleanup(func() {
		darwinKillSwitchPath = oldRules
		legacyDarwinKillSwitchPath = oldLegacy
		darwinPfEnabledMarkerPath = oldEnabled
	})
}

func (r *scriptedRunner) Run(stdin, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, runnerCall{stdin: stdin, name: name, args: append([]string(nil), args...)})
	if name != "nft" {
		return nil, errors.New("unexpected command")
	}
	joined := strings.Join(args, " ")
	switch joined {
	case "list tables":
		return r.tables, nil
	case "-f -":
		return r.applyOut, r.applyErr
	case "delete table inet " + legacyKillTable:
		return nil, r.legacyErr
	default:
		return nil, nil
	}
}

func TestLinuxApplyReplacesExistingTableInOneTransaction(t *testing.T) {
	run := &scriptedRunner{tables: []byte("table inet " + killTable + "\n")}
	e := &LinuxEnforcer{run: run}
	p := remotePolicy()
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	if len(run.calls) != 3 {
		t.Fatalf("commands = %d, want inspect, atomic apply, legacy cleanup: %#v", len(run.calls), run.calls)
	}
	if got := strings.Join(run.calls[0].args, " "); got != "list tables" {
		t.Fatalf("first command = %q, want fixed table inspection", got)
	}
	apply := run.calls[1]
	if apply.name != "nft" || strings.Join(apply.args, " ") != "-f -" {
		t.Fatalf("apply command is not fixed nft transaction: %#v", apply)
	}
	if !strings.HasPrefix(apply.stdin, "delete table inet "+killTable+"\n") ||
		!strings.Contains(apply.stdin, "table inet "+killTable+" {") {
		t.Fatalf("replacement was not one delete+add transaction:\n%s", apply.stdin)
	}
	if got := strings.Join(run.calls[2].args, " "); got != "delete table inet "+legacyKillTable {
		t.Fatalf("legacy cleanup did not happen last: %q", got)
	}
}

func TestLinuxFailedTransactionPreservesOldPolicyAndDoesNotCleanLegacy(t *testing.T) {
	secret := []byte("sensitive nft diagnostic")
	run := &scriptedRunner{
		tables:   []byte("table inet " + killTable + "\n"),
		applyErr: errors.New("exit status 1"),
		applyOut: secret,
	}
	old := samplePolicy()
	e := &LinuxEnforcer{run: run, cur: old}
	err := e.Apply(remotePolicy())
	if err == nil {
		t.Fatal("failed nft transaction reported success")
	}
	if strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("nft output leaked through error: %v", err)
	}
	if !e.Current().Enabled {
		t.Fatal("failed transaction replaced recorded old policy")
	}
	if len(run.calls) != 2 {
		t.Fatalf("failure ran commands after transaction: %#v", run.calls)
	}
}

func TestLinuxRemoteOnlyPolicyIsApplied(t *testing.T) {
	run := &scriptedRunner{}
	e := &LinuxEnforcer{run: run}
	p := remotePolicy()
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	if len(run.calls) < 2 || !strings.Contains(run.calls[1].stdin, "chain input") {
		t.Fatalf("remote-only policy was cleared instead of loaded: %#v", run.calls)
	}
}

func TestLinuxInactiveCleanupFailureIsPropagated(t *testing.T) {
	run := &scriptedRunner{
		tables:   []byte("table inet " + killTable + "\n"),
		applyErr: errors.New("exit status 1"),
	}
	old := remotePolicy()
	e := &LinuxEnforcer{run: run, cur: old}
	if err := e.Apply(Policy{}); err == nil {
		t.Fatal("inactive apply hid nft cleanup failure")
	}
	if !e.Current().RemoteEnforcement {
		t.Fatal("cleanup failure changed Current")
	}
	if err := e.Clear(); err == nil {
		t.Fatal("Clear hid nft cleanup failure")
	}
	if !e.Current().RemoteEnforcement {
		t.Fatal("failed Clear changed Current")
	}
}

func TestLinuxPolicyStateHasNoSliceAliases(t *testing.T) {
	run := &scriptedRunner{}
	e := &LinuxEnforcer{run: run}
	p := remotePolicy()
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	p.ManagedServices[0].TCPPort = 1
	got := e.Current()
	if got.ManagedServices[0].TCPPort == 1 {
		t.Fatal("Apply retained caller slice alias")
	}
	got.ManagedServices[0].TCPPort = 2
	if e.Current().ManagedServices[0].TCPPort == 2 {
		t.Fatal("Current exposed internal slice alias")
	}
}

func TestUnsupportedEnforcerFailsClosed(t *testing.T) {
	e := NewUnsupportedEnforcer("test platform")
	if err := e.Apply(remotePolicy()); err == nil {
		t.Fatal("unsupported platform reported active remote enforcement")
	}
	if capability := e.Capability(); capability.HostFirewall || capability.RemoteAccess {
		t.Fatalf("unsupported capability falsely advertises enforcement: %#v", capability)
	}
}

func TestDarwinFailedCandidateLoadPreservesPreviousMarkerAndCurrent(t *testing.T) {
	setDarwinTestPaths(t)
	if err := os.WriteFile(darwinKillSwitchPath, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &pfTestRunner{loadErr: errors.New("load failed")}
	old := samplePolicy()
	e := &DarwinEnforcer{run: run, cur: old}
	if err := e.Apply(remotePolicy()); err == nil {
		t.Fatal("candidate load failure reported success")
	}
	content, err := os.ReadFile(darwinKillSwitchPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "previous" {
		t.Fatalf("candidate failure replaced prior marker: %q", content)
	}
	if !e.Current().Enabled {
		t.Fatal("candidate failure changed Current")
	}
}

func TestDarwinLoadsCandidateBeforeCommittingMarker(t *testing.T) {
	setDarwinTestPaths(t)
	if err := os.WriteFile(darwinKillSwitchPath, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &pfTestRunner{}
	e := &DarwinEnforcer{run: run, cur: samplePolicy()}
	p := remotePolicy()
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	var loadedPath string
	for _, call := range run.calls {
		if len(call.args) == 2 && call.args[0] == "-f" {
			loadedPath = call.args[1]
		}
	}
	if loadedPath == "" || loadedPath == darwinKillSwitchPath ||
		filepath.Dir(loadedPath) != filepath.Dir(darwinKillSwitchPath) {
		t.Fatalf("PF was not loaded from a same-directory candidate: %q", loadedPath)
	}
	content, err := os.ReadFile(darwinKillSwitchPath)
	if err != nil {
		t.Fatal(err)
	}
	want := mustPF(t, p)
	if string(content) != want {
		t.Fatalf("successful PF load did not commit candidate marker:\n%s", content)
	}
}

func TestDarwinPostRenameSyncFailureRollsBackKernelMarkerAndCurrent(t *testing.T) {
	setDarwinTestPaths(t)
	old := remotePolicy()
	old.RemoteAccessRules = nil
	oldRules := mustPF(t, old)
	if err := os.WriteFile(darwinKillSwitchPath, []byte(oldRules), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &pfTestRunner{}
	commit := &postRenameFailCommitter{failPath: darwinKillSwitchPath}
	e := &DarwinEnforcer{run: run, commit: commit, cur: old}
	next := remotePolicy() // adds one exact grant
	if err := e.Apply(next); err == nil {
		t.Fatal("post-rename durability failure reported success despite successful rollback")
	}
	content, err := os.ReadFile(darwinKillSwitchPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != oldRules {
		t.Fatalf("rollback did not restore old marker:\n%s", content)
	}
	if len(e.Current().RemoteAccessRules) != 0 {
		t.Fatal("failed Apply exposed new grant through Current")
	}
	var loads []string
	for _, call := range run.calls {
		if len(call.args) == 2 && call.args[0] == "-f" {
			loads = append(loads, call.args[1])
		}
	}
	if len(loads) != 2 || loads[0] == loads[1] ||
		filepath.Base(loads[1]) == filepath.Base(darwinKillSwitchPath) {
		t.Fatalf("kernel was not rolled back from independent backup: %v", loads)
	}
}

func TestDarwinInactiveRestoreFailurePreservesOwnershipAndCurrent(t *testing.T) {
	setDarwinTestPaths(t)
	if err := os.WriteFile(darwinKillSwitchPath, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &pfTestRunner{restoreErr: errors.New("restore failed")}
	old := remotePolicy()
	e := &DarwinEnforcer{run: run, cur: old}
	if err := e.Apply(Policy{}); err == nil {
		t.Fatal("inactive apply hid PF restore failure")
	}
	if _, err := os.Stat(darwinKillSwitchPath); err != nil {
		t.Fatalf("restore failure removed ownership marker: %v", err)
	}
	if !e.Current().RemoteEnforcement {
		t.Fatal("restore failure changed Current")
	}
	if err := e.Clear(); err == nil {
		t.Fatal("Clear hid PF restore failure")
	}
}

func TestDarwinDisableFailureRecordsKernelInactiveAndRetainsOwnership(t *testing.T) {
	setDarwinTestPaths(t)
	if err := os.WriteFile(darwinKillSwitchPath, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(darwinPfEnabledMarkerPath, []byte(pfOwnershipEnabled), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &pfTestRunner{disableErr: errors.New("disable failed")}
	e := &DarwinEnforcer{run: run, cur: remotePolicy(), weEnabledPf: true}
	if err := e.Clear(); err == nil {
		t.Fatal("disable failure was hidden")
	}
	if e.Current().Active() {
		t.Fatal("Current still claims managed rules after system PF rules were loaded")
	}
	if !e.weEnabledPf {
		t.Fatal("failed disable discarded retry ownership")
	}
	if _, err := os.Stat(darwinPfEnabledMarkerPath); err != nil {
		t.Fatalf("failed disable removed persistent ownership: %v", err)
	}
	run.disableErr = nil
	if err := e.Clear(); err != nil {
		t.Fatalf("retry did not finish cleanup: %v", err)
	}
}

func TestDarwinMarkerRemovalFailureRecordsKernelInactive(t *testing.T) {
	setDarwinTestPaths(t)
	if err := os.Mkdir(darwinKillSwitchPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(darwinKillSwitchPath, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e := &DarwinEnforcer{run: &pfTestRunner{}, cur: remotePolicy()}
	if err := e.Clear(); err == nil {
		t.Fatal("marker removal failure was hidden")
	}
	if e.Current().Active() {
		t.Fatal("Current still claims managed rules after restore")
	}
	if _, err := os.Stat(darwinKillSwitchPath); err != nil {
		t.Fatalf("failed removal lost retry marker: %v", err)
	}
}

func TestDarwinOwnershipPersistAndDisableFailureRemainRetryable(t *testing.T) {
	setDarwinTestPaths(t)
	validEnabledPath := darwinPfEnabledMarkerPath
	darwinPfEnabledMarkerPath = filepath.Join(filepath.Dir(validEnabledPath), "missing", "enabled")
	run := &pfTestRunner{
		status: "Status: Disabled",
	}
	e := &DarwinEnforcer{run: run}
	if err := e.Apply(remotePolicy()); err == nil {
		t.Fatal("intent persistence failure was hidden")
	}
	if e.weEnabledPf {
		t.Fatal("PF was enabled before durable intent")
	}
	if e.Current().Active() {
		t.Fatal("failed pre-load Apply changed Current")
	}
	for _, call := range run.calls {
		if len(call.args) == 1 && call.args[0] == "-E" {
			t.Fatal("pfctl -E ran without durable intent")
		}
	}
}

func TestDarwinOwnershipIntentPrecedesEnableAndEnableFailureCleansIt(t *testing.T) {
	setDarwinTestPaths(t)
	intentObserved := false
	run := &pfTestRunner{
		status: "Status: Disabled",
		beforeEnable: func() {
			intentObserved = pfOwnershipPhase() == pfOwnershipIntent
		},
	}
	run.loadErr = nil
	// Reuse disableErr as no-op; inject -E failure with a small dedicated runner.
	wrapped := &enableFailRunner{pfTestRunner: run}
	e := &DarwinEnforcer{run: wrapped}
	if err := e.Apply(remotePolicy()); err == nil {
		t.Fatal("enable failure was hidden")
	}
	if !intentObserved {
		t.Fatal("pfctl -E ran before durable intent")
	}
	if pfOwnershipMarkerExists() {
		t.Fatal("enable failure left stale ownership intent")
	}
	foundDisable := false
	for _, call := range run.calls {
		if len(call.args) == 1 && call.args[0] == "-d" {
			foundDisable = true
		}
	}
	if !foundDisable {
		t.Fatal("pfctl -E error was not conservatively compensated")
	}
}

type enableFailRunner struct {
	pfTestRunner *pfTestRunner
}

func (r *enableFailRunner) Run(stdin, name string, args ...string) ([]byte, error) {
	if len(args) == 1 && args[0] == "-E" {
		r.pfTestRunner.calls = append(r.pfTestRunner.calls, runnerCall{
			stdin: stdin, name: name, args: append([]string(nil), args...),
		})
		if r.pfTestRunner.beforeEnable != nil {
			r.pfTestRunner.beforeEnable()
		}
		return nil, errors.New("enable failed")
	}
	return r.pfTestRunner.Run(stdin, name, args...)
}

func TestDarwinEnableErrorAndDisableErrorRemainRecoverableAfterRestart(t *testing.T) {
	setDarwinTestPaths(t)
	run := &pfTestRunner{
		status:     "Status: Disabled",
		disableErr: errors.New("disable side effect unknown"),
	}
	e := &DarwinEnforcer{run: &enableFailRunner{pfTestRunner: run}}
	if err := e.Apply(remotePolicy()); err == nil {
		t.Fatal("double failure reported success")
	}
	if !e.weEnabledPf {
		t.Fatal("double failure discarded in-memory ownership")
	}
	if phase := pfOwnershipPhase(); phase != pfOwnershipEnabled {
		t.Fatalf("double failure did not persist enabled ownership: %q", phase)
	}
	if e.Current().Active() {
		t.Fatal("failure before ruleset load changed Current")
	}

	// Simulate a daemon crash. Only the durable marker remains; a fresh process
	// must issue -d and clear ownership.
	freshRun := &pfTestRunner{}
	fresh := &DarwinEnforcer{run: freshRun}
	if err := fresh.Clear(); err != nil {
		t.Fatalf("fresh recovery failed: %v", err)
	}
	foundDisable := false
	for _, call := range freshRun.calls {
		if len(call.args) == 1 && call.args[0] == "-d" {
			foundDisable = true
		}
	}
	if !foundDisable {
		t.Fatal("fresh recovery did not compensate uncertain enable side effect")
	}
	if pfOwnershipMarkerExists() {
		t.Fatal("fresh recovery left enabled ownership marker")
	}
}

func TestDarwinEnabledMarkerPostRenameFailureCompensatesExactly(t *testing.T) {
	for _, disableFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("disable-fails-%v", disableFails), func(t *testing.T) {
			setDarwinTestPaths(t)
			run := &pfTestRunner{status: "Status: Disabled"}
			if disableFails {
				run.disableErr = errors.New("disable failed")
			}
			commit := &nthPostRenameFailCommitter{path: darwinPfEnabledMarkerPath, at: 2}
			e := &DarwinEnforcer{run: run, commit: commit}
			if err := e.Apply(remotePolicy()); err == nil {
				t.Fatal("enabled marker durability failure was hidden")
			}
			if disableFails {
				if !e.weEnabledPf || pfOwnershipPhase() != pfOwnershipEnabled {
					t.Fatalf("failed disable lost retryable enabled ownership: memory=%v phase=%q",
						e.weEnabledPf, pfOwnershipPhase())
				}
				run.disableErr = nil
				if err := e.Clear(); err != nil {
					t.Fatalf("retry cleanup failed: %v", err)
				}
			} else {
				if e.weEnabledPf || pfOwnershipMarkerExists() {
					t.Fatalf("successful compensation left stale ownership: memory=%v phase=%q",
						e.weEnabledPf, pfOwnershipPhase())
				}
			}
		})
	}
}

func TestDarwinCommitAndRollbackFailureRetainsTruthfulEmergencyOwnership(t *testing.T) {
	for _, hadPrevious := range []bool{false, true} {
		t.Run(fmt.Sprintf("previous-%v", hadPrevious), func(t *testing.T) {
			setDarwinTestPaths(t)
			old := remotePolicy()
			old.RemoteAccessRules = nil
			if hadPrevious {
				if err := os.WriteFile(darwinKillSwitchPath, []byte(mustPF(t, old)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			run := &pfTestRunner{
				loadErr:    errors.New("rollback load failed"),
				failLoadAt: 2,
			}
			if !hadPrevious {
				run.restoreErr = errors.New("system rollback failed")
			}
			next := remotePolicy()
			e := &DarwinEnforcer{
				run:    run,
				commit: preRenameFailCommitter{path: darwinKillSwitchPath},
				cur:    old,
			}
			if err := e.Apply(next); err != nil {
				t.Fatalf("live new policy was falsely reported as failed: %v", err)
			}
			if len(e.Current().RemoteAccessRules) != 1 {
				t.Fatal("Current did not record the actually loaded new grant")
			}
			if _, err := os.Stat(darwinEmergencyMarkerPath()); err != nil {
				t.Fatalf("new live policy lacks durable emergency ownership: %v", err)
			}
		})
	}
}

func TestDarwinSharedRenameAndRollbackFailureSurvivesRestartViaJournal(t *testing.T) {
	for _, hadPrevious := range []bool{false, true} {
		t.Run(fmt.Sprintf("previous-%v", hadPrevious), func(t *testing.T) {
			setDarwinTestPaths(t)
			old := remotePolicy()
			old.RemoteAccessRules = nil
			if hadPrevious {
				if err := os.WriteFile(darwinKillSwitchPath, []byte(mustPF(t, old)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			run := &pfTestRunner{}
			if hadPrevious {
				run.loadErr = errors.New("backup rollback failed")
				run.failLoadAt = 2
			} else {
				run.restoreErr = errors.New("system rollback failed")
			}
			next := remotePolicy()
			e := &DarwinEnforcer{
				run: run,
				commit: twoTargetFailCommitter{
					first:  darwinKillSwitchPath,
					second: darwinEmergencyMarkerPath(),
				},
				cur: old,
			}
			if err := e.Apply(next); err == nil {
				t.Fatal("durable quarantine was not reported")
			}
			if len(e.Current().RemoteAccessRules) != 1 {
				t.Fatal("quarantine Current does not describe live kernel policy")
			}
			candidate, ok := quarantinedCandidate()
			if !ok {
				t.Fatal("fixed quarantine journal is missing or invalid")
			}
			if _, err := os.Stat(candidate); err != nil {
				t.Fatalf("only fsynced candidate was deleted: %v", err)
			}

			// A fresh process has no in-memory flags but must discover and clean
			// the journal and candidate after restoring system PF rules.
			fresh := &DarwinEnforcer{run: &pfTestRunner{}}
			if !fresh.needsRestoreLocked() {
				t.Fatal("fresh enforcer did not discover quarantine journal")
			}
			if err := fresh.Clear(); err != nil {
				t.Fatalf("fresh recovery failed: %v", err)
			}
			if quarantineJournalExists() {
				t.Fatal("fresh recovery left quarantine journal")
			}
			if _, err := os.Stat(candidate); !os.IsNotExist(err) {
				t.Fatalf("fresh recovery left quarantined candidate: %v", err)
			}
		})
	}
}

func TestDarwinFreshRecoveryDisablesPFForEnableIntent(t *testing.T) {
	setDarwinTestPaths(t)
	if err := os.WriteFile(darwinPfEnabledMarkerPath, []byte(pfOwnershipIntent), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &pfTestRunner{}
	fresh := &DarwinEnforcer{run: run}
	if err := fresh.Clear(); err != nil {
		t.Fatal(err)
	}
	foundDisable := false
	for _, call := range run.calls {
		if len(call.args) == 1 && call.args[0] == "-d" {
			foundDisable = true
		}
	}
	if !foundDisable {
		t.Fatal("fresh recovery did not release PF after crash-window intent")
	}
	if pfOwnershipMarkerExists() {
		t.Fatal("fresh recovery left intent marker")
	}
}

func TestDarwinFreshRecoveryDoesNotDisablePFForCancelledIntent(t *testing.T) {
	setDarwinTestPaths(t)
	if err := os.WriteFile(darwinPfEnabledMarkerPath, []byte(pfOwnershipCancelled), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &pfTestRunner{}
	fresh := &DarwinEnforcer{run: run}
	if err := fresh.Clear(); err != nil {
		t.Fatal(err)
	}
	for _, call := range run.calls {
		if len(call.args) == 1 && call.args[0] == "-d" {
			t.Fatal("cancelled ownership caused user PF disable")
		}
	}
}

func TestDarwinEnforcerDetectsRulesFromCrashedProcess(t *testing.T) {
	oldPath := darwinKillSwitchPath
	oldLegacyPath := legacyDarwinKillSwitchPath
	darwinKillSwitchPath = filepath.Join(t.TempDir(), "ratelmesh-killswitch.pf.conf")
	legacyDarwinKillSwitchPath = filepath.Join(t.TempDir(), "legacy-killswitch.pf.conf")
	t.Cleanup(func() {
		darwinKillSwitchPath = oldPath
		legacyDarwinKillSwitchPath = oldLegacyPath
	})

	e := &DarwinEnforcer{run: successRunner{}}
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
	e := &DarwinEnforcer{run: successRunner{}}
	if !e.needsRestoreLocked() {
		t.Fatal("legacy crash marker was ignored")
	}
	if err := e.restoreLocked(); err != nil {
		t.Fatal(err)
	}
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
	if err := os.WriteFile(darwinPfEnabledMarkerPath, []byte(pfOwnershipEnabled), 0o600); err != nil {
		t.Fatal(err)
	}

	// A successor process: fresh struct, so weEnabledPf is false.
	e := &DarwinEnforcer{run: successRunner{}}
	if !pfEnabledByUsPreviously() {
		t.Fatal("successor did not detect the predecessor's pf-enabled marker")
	}
	if err := e.restoreLocked(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(darwinPfEnabledMarkerPath); !os.IsNotExist(err) {
		t.Fatalf("pf-enabled marker remained after restore: %v", err)
	}
}
