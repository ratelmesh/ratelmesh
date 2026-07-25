package remoteservice

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	systemCommandTimeout = 10 * time.Second
	systemOutputLimit    = 32 << 10
)

var (
	errBackendUnsupported = errors.New("remote service system backend unsupported")
	errBackendState       = errors.New("remote service system backend state invalid")
)

type commandExecutionError struct {
	cause error
}

func (e *commandExecutionError) Error() string {
	return "fixed service command failed"
}

func (e *commandExecutionError) Unwrap() error {
	return e.cause
}

type fixedService uint8

const (
	fixedServiceUnknown fixedService = iota
	fixedLinuxSSH
	fixedLinuxSSHD
	fixedMacSSH
	fixedWindowsSSH
	fixedWindowsRDP
)

type commandSpec struct {
	executable string
	arguments  []string
}

type commandResult struct {
	stdout    string
	stderr    string
	truncated bool
}

type commandRunner interface {
	Run(context.Context, commandSpec, int) (commandResult, error)
}

// atomicServiceTransitioner is implemented only by a native platform adapter
// that can atomically prove start ownership and conditionally roll back the
// same generation. A command exit status and before/after polling are
// insufficient.
type atomicServiceTransitioner interface {
	StartAtomic(context.Context, Target, fixedService, ServiceState) (atomicStartResult, error)
	RollbackAtomic(context.Context, Target, fixedService, ServiceState, ServiceRevision, [32]byte) error
}

// atomicStartResult makes the mutation boundary explicit. Zero/incomplete
// observations are never evidence that a failed or timed-out native operation
// left the service unchanged.
type atomicStartResult struct {
	after                 observedService
	ownership             [32]byte
	mutationAttempted     bool
	definitivelyUnchanged bool
}

type observedService struct {
	state          ServiceState
	pid            uint64
	generation     uint64
	configuration  uint64
	nativeSnapshot [32]byte
	mutationSafe   bool
	listening      bool
	identity       bool
	unit           fixedService
}

// SystemBackend implements the fixed native-service allowlist for the local
// desktop operating system. It has no API for configuring executable paths,
// service names, command arguments, ports, users, or credentials.
type SystemBackend struct {
	platform Platform
	runner   commandRunner
	atomic   atomicServiceTransitioner
	// productionDetectOnly is set only by NewSystemBackend. Tests may exercise
	// the otherwise unreachable transaction machinery with deterministic native
	// adapters, but the exported production constructor never permits CLI
	// mutation without atomic ownership.
	productionDetectOnly bool
}

// NewSystemBackend creates the production backend for the current OS.
func NewSystemBackend() (*SystemBackend, error) {
	platform, err := runtimePlatform(runtime.GOOS)
	if err != nil {
		return nil, err
	}
	backend := newSystemBackend(platform, execCommandRunner{})
	backend.productionDetectOnly = true
	return backend, nil
}

func newSystemBackend(platform Platform, runner commandRunner) *SystemBackend {
	backend := &SystemBackend{platform: platform, runner: runner}
	if atomic, ok := runner.(atomicServiceTransitioner); ok {
		backend.atomic = atomic
	}
	return backend
}

func runtimePlatform(goos string) (Platform, error) {
	switch goos {
	case "linux":
		return PlatformLinux, nil
	case "darwin":
		return PlatformMacOS, nil
	case "windows":
		return PlatformWindows, nil
	default:
		return PlatformUnknown, &Error{Code: CodeUnsupportedTarget, Cause: errBackendUnsupported}
	}
}

func (b *SystemBackend) Capture(ctx context.Context, target Target) (ServiceState, error) {
	if err := b.validate(target); err != nil {
		return ServiceState{}, err
	}
	observed, err := b.inspect(ctx, target)
	if err != nil {
		return ServiceState{}, err
	}
	return observed.state, nil
}

func (b *SystemBackend) Detect(ctx context.Context, target Target) (Health, error) {
	if err := b.validate(target); err != nil {
		return Health{}, err
	}
	observed, err := b.inspect(ctx, target)
	if err != nil {
		return Health{}, err
	}
	return Health{
		Running:          observed.state.Running,
		Listening:        observed.listening,
		Healthy:          observed.state.Running && observed.state.Enabled && observed.listening && observed.identity,
		IdentityVerified: observed.identity,
	}, nil
}

func (b *SystemBackend) Start(ctx context.Context, target Target, permit StartPermit) (ChangeReceipt, error) {
	if err := b.validate(target); err != nil {
		return ChangeReceipt{}, err
	}
	service, err := fixedServiceFor(target)
	if err != nil {
		return ChangeReceipt{}, err
	}
	// SSH is detect-only: proving that sshd listens only on the Mesh requires
	// platform firewall and bind-address ownership that this backend does not
	// have. RDP may start only through a native adapter that atomically owns the
	// exact policy/firewall/service snapshot and can conditionally restore it.
	// The production execCommandRunner intentionally implements no such claim.
	if b.productionDetectOnly && (service != fixedWindowsRDP || b.atomic == nil) {
		return ChangeReceipt{}, &Error{Code: CodeUnsupportedTarget, Cause: errBackendUnsupported}
	}
	if permit.target != target || permit.nonce == ([32]byte{}) || permit.before.Running {
		return ChangeReceipt{}, ErrRollbackConflict
	}
	before, err := b.inspect(ctx, target)
	if err != nil {
		return ChangeReceipt{}, err
	}
	if before.state != permit.before || before.state.Running {
		return ChangeReceipt{}, ErrRollbackConflict
	}
	// This path exists for deterministic package tests and future embedders that
	// explicitly construct an internal backend. NewSystemBackend rejects it.
	if b.atomic == nil {
		return b.startCLI(ctx, target, permit, before)
	}
	transitionCtx, cancel := context.WithTimeout(ctx, systemCommandTimeout)
	atomicResult, startErr := b.atomic.StartAtomic(
		transitionCtx, target, before.unit, before.state,
	)
	contextErr := transitionCtx.Err()
	cancel()
	if contextErr != nil {
		startErr = contextErr
	}
	after := atomicResult.after
	ownership := atomicResult.ownership
	if atomicResult.definitivelyUnchanged {
		consistentAfter := after == (observedService{}) || after == before
		if atomicResult.mutationAttempted || ownership != ([32]byte{}) || !consistentAfter {
			return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, startErr, ErrOwnershipUnproven)
		}
		if startErr != nil {
			return ChangeReceipt{}, startErr
		}
		return ChangeReceipt{}, ErrOwnershipUnproven
	}
	if after == (observedService{}) || after.unit != before.unit {
		if !atomicResult.mutationAttempted && startErr == nil {
			return ChangeReceipt{}, ErrOwnershipUnproven
		}
		return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, startErr, ErrOwnershipUnproven)
	}
	if after.state.Running && (after.pid == 0 || after.generation == 0) {
		return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, startErr, errBackendState)
	}
	changed := after.state != before.state ||
		after.pid != before.pid ||
		after.generation != before.generation ||
		after.configuration != before.configuration ||
		after.nativeSnapshot != before.nativeSnapshot
	if ownership == ([32]byte{}) {
		if changed {
			receipt := permit.CommitObserved(revisionFor(target, after))
			return receipt, errors.Join(ErrManualCleanupRequired, startErr)
		}
		if atomicResult.mutationAttempted {
			return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, startErr, ErrOwnershipUnproven)
		}
		if startErr != nil {
			return ChangeReceipt{}, startErr
		}
		return ChangeReceipt{}, ErrOwnershipUnproven
	}
	if !atomicResult.mutationAttempted {
		return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, startErr, ErrOwnershipUnproven)
	}
	if after.state == before.state {
		return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, startErr, ErrOwnershipUnproven)
	}
	receipt := permit.CommitOwned(revisionFor(target, after), ownership)
	if !receipt.Changed() {
		return ChangeReceipt{}, ErrOwnershipUnproven
	}
	if startErr != nil {
		return receipt, startErr
	}
	if !after.state.Running || after.pid == 0 || after.generation == 0 {
		return receipt, errBackendState
	}
	return receipt, nil
}

func (b *SystemBackend) startCLI(
	ctx context.Context,
	target Target,
	permit StartPermit,
	before observedService,
) (ChangeReceipt, error) {
	// A second read immediately before the first mutation narrows the race
	// window. CLI mode never receives stop authority even when this check and
	// every command succeeds.
	guard, err := b.inspect(ctx, target)
	if err != nil {
		return ChangeReceipt{}, err
	}
	if guard.state != before.state || guard.unit != before.unit || guard.state.Running {
		return ChangeReceipt{}, ErrRollbackConflict
	}
	if guard.unit == fixedWindowsRDP {
		if !guard.mutationSafe {
			return ChangeReceipt{}, errBackendState
		}
		if guard.nativeSnapshot != before.nativeSnapshot {
			return ChangeReceipt{}, ErrRollbackConflict
		}
		preflight, preflightErr := b.inspectWindowsRDP(ctx)
		if preflightErr != nil {
			return ChangeReceipt{}, preflightErr
		}
		if !preflight.mutationSafe || preflight.nativeSnapshot != guard.nativeSnapshot {
			return ChangeReceipt{}, ErrRollbackConflict
		}
		guard = preflight
	}

	if !guard.state.Enabled {
		enableErr := b.enableFixed(ctx, guard.unit)
		if enableErr != nil && guard.unit == fixedWindowsRDP {
			return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, enableErr)
		}
		afterEnable, inspectErr := b.inspectAfterAttempt(ctx, target)
		if inspectErr != nil {
			return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, enableErr, inspectErr)
		}
		if enableErr != nil {
			return classifyCLIChange(permit, target, before, afterEnable, enableErr)
		}
		if afterEnable.state.Running {
			if (guard.unit == fixedMacSSH || guard.unit == fixedWindowsRDP) &&
				afterEnable.unit == before.unit {
				receipt := permit.CommitObserved(revisionFor(target, afterEnable))
				if receipt.Changed() {
					return receipt, nil
				}
			}
			return classifyCLIChange(
				permit, target, before, afterEnable, ErrManualCleanupRequired,
			)
		}
		if guard.unit == fixedWindowsRDP &&
			(!afterEnable.state.Enabled || afterEnable.unit != before.unit) {
			return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, errBackendState)
		}
		if !afterEnable.state.Enabled || afterEnable.unit != before.unit {
			return classifyCLIChange(permit, target, before, afterEnable, errBackendState)
		}
		guard = afterEnable
	} else {
		// Enabled services get another last-moment state read directly before
		// start to avoid a needless duplicate start when practical.
		guard, err = b.inspect(ctx, target)
		if err != nil {
			return ChangeReceipt{}, err
		}
		if guard.state != before.state || guard.unit != before.unit || guard.state.Running {
			return ChangeReceipt{}, ErrRollbackConflict
		}
	}

	startErr := b.startFixed(ctx, guard.unit)
	after, inspectErr := b.inspectAfterAttempt(ctx, target)
	if inspectErr != nil {
		return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, startErr, inspectErr)
	}
	if startErr != nil {
		if guard.unit == fixedWindowsRDP {
			return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, startErr)
		}
		return classifyCLIChange(permit, target, before, after, startErr)
	}
	if !after.state.Running || after.pid == 0 || after.generation == 0 {
		if guard.unit == fixedWindowsRDP {
			return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, errBackendState)
		}
		return classifyCLIChange(permit, target, before, after, errBackendState)
	}
	receipt := permit.CommitObserved(revisionFor(target, after))
	if !receipt.Changed() {
		return ChangeReceipt{}, errBackendState
	}
	return receipt, nil
}

func (b *SystemBackend) inspectAfterAttempt(ctx context.Context, target Target) (observedService, error) {
	inspectCtx := ctx
	var cancel context.CancelFunc
	if ctx.Err() != nil {
		inspectCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), systemCommandTimeout)
		defer cancel()
	}
	return b.inspect(inspectCtx, target)
}

func classifyCLIChange(
	permit StartPermit,
	target Target,
	before observedService,
	after observedService,
	cause error,
) (ChangeReceipt, error) {
	if after == (observedService{}) || after.unit != before.unit {
		return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, cause)
	}
	if after.state == before.state &&
		after.pid == before.pid &&
		after.generation == before.generation &&
		after.configuration == before.configuration &&
		after.nativeSnapshot == before.nativeSnapshot {
		return ChangeReceipt{}, cause
	}
	receipt := permit.CommitObserved(revisionFor(target, after))
	if !receipt.Changed() {
		return permit.CommitUncertain(), errors.Join(ErrManualCleanupRequired, cause)
	}
	return receipt, errors.Join(ErrManualCleanupRequired, cause)
}

func (b *SystemBackend) Rollback(
	ctx context.Context,
	target Target,
	before ServiceState,
	receipt ChangeReceipt,
) error {
	if err := b.validate(target); err != nil {
		return err
	}
	if before.Running {
		return ErrRollbackConflict
	}
	current, err := b.inspect(ctx, target)
	if err != nil {
		return err
	}
	if !receipt.AuthorizesRollback(target, before, revisionFor(target, current)) {
		return ErrRollbackConflict
	}
	if b.atomic == nil {
		return ErrOwnershipUnproven
	}
	rollbackCtx, cancel := context.WithTimeout(ctx, systemCommandTimeout)
	err = b.atomic.RollbackAtomic(
		rollbackCtx,
		target,
		current.unit,
		before,
		receipt.PostRevision(),
		receipt.ownershipToken(),
	)
	contextErr := rollbackCtx.Err()
	cancel()
	if contextErr != nil {
		return contextErr
	}
	if err != nil {
		return err
	}
	restored, err := b.inspect(ctx, target)
	if err != nil {
		return err
	}
	if restored.state != before {
		return errBackendState
	}
	return nil
}

func (b *SystemBackend) validate(target Target) error {
	if b == nil || b.runner == nil {
		return &Error{Code: CodeInvalidRequest}
	}
	if target.Device == (DeviceID{}) {
		return &Error{Code: CodeInvalidRequest}
	}
	if target.Platform != b.platform {
		return &Error{Code: CodeUnsupportedTarget, Cause: errBackendUnsupported}
	}
	if _, err := fixedServiceFor(target); err != nil {
		return err
	}
	return nil
}

func fixedServiceFor(target Target) (fixedService, error) {
	switch {
	case target.Platform == PlatformLinux && target.Service == ServiceSSH:
		return fixedLinuxSSH, nil
	case target.Platform == PlatformMacOS && target.Service == ServiceSSH:
		return fixedMacSSH, nil
	case target.Platform == PlatformWindows && target.Service == ServiceSSH:
		return fixedWindowsSSH, nil
	case target.Platform == PlatformWindows && target.Service == ServiceRDP:
		return fixedWindowsRDP, nil
	default:
		return fixedServiceUnknown, &Error{Code: CodeUnsupportedTarget, Cause: errBackendUnsupported}
	}
}

func (b *SystemBackend) inspect(ctx context.Context, target Target) (observedService, error) {
	service, err := fixedServiceFor(target)
	if err != nil {
		return observedService{}, err
	}
	switch service {
	case fixedLinuxSSH:
		return b.inspectLinuxSSH(ctx)
	case fixedMacSSH:
		return b.inspectMacSSH(ctx)
	case fixedWindowsSSH:
		return b.inspectWindowsSSH(ctx)
	case fixedWindowsRDP:
		return b.inspectWindowsRDP(ctx)
	default:
		return observedService{}, &Error{Code: CodeUnsupportedTarget}
	}
}

func (b *SystemBackend) inspectLinuxSSH(ctx context.Context) (observedService, error) {
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		result, err := b.run(ctx, commandSpec{
			executable: "/usr/bin/systemctl",
			arguments: []string{
				"show", unit, "--no-pager",
				"--property=LoadState",
				"--property=ActiveState",
				"--property=UnitFileState",
				"--property=MainPID",
				"--property=ActiveEnterTimestampMonotonic",
			},
		})
		if err != nil {
			return observedService{}, err
		}
		values := parseKeyValues(result.stdout)
		if values["LoadState"] != "loaded" {
			continue
		}
		pid, pidErr := parseUint(values["MainPID"])
		generation, generationErr := parseUint(values["ActiveEnterTimestampMonotonic"])
		if pidErr != nil || generationErr != nil {
			return observedService{}, errBackendState
		}
		enabled := linuxUnitEnabled(values["UnitFileState"])
		running := values["ActiveState"] == "active"
		if running && (pid == 0 || generation == 0) {
			return observedService{}, errBackendState
		}
		listening := false
		if running && pid != 0 {
			listening, err = b.linuxListening(ctx, pid, 22)
			if err != nil {
				return observedService{}, err
			}
		}
		nativeUnit := fixedLinuxSSH
		if unit == "sshd.service" {
			nativeUnit = fixedLinuxSSHD
		}
		return observedService{
			state:      ServiceState{Running: running, Enabled: enabled},
			pid:        pid,
			generation: generation,
			listening:  listening,
			identity:   true,
			unit:       nativeUnit,
		}, nil
	}
	return observedService{}, &Error{Code: CodeUnsupportedTarget, Cause: errBackendUnsupported}
}

func (b *SystemBackend) inspectMacSSH(ctx context.Context) (observedService, error) {
	result, err := b.run(ctx, commandSpec{
		executable: "/usr/sbin/systemsetup",
		arguments:  []string{"-getremotelogin"},
	})
	if err != nil {
		return observedService{}, err
	}
	enabled, ok := parseRemoteLogin(result.stdout)
	if !ok {
		return observedService{}, errBackendState
	}
	listening, pid := false, uint64(0)
	if enabled {
		listening, pid, err = b.macTrustedSSHListener(ctx)
		if err != nil {
			return observedService{}, err
		}
	}
	return observedService{
		state:      ServiceState{Running: enabled && listening, Enabled: enabled},
		pid:        pid,
		generation: boolGeneration(enabled),
		listening:  listening,
		identity:   true,
		unit:       fixedMacSSH,
	}, nil
}

func (b *SystemBackend) inspectWindowsRDP(ctx context.Context) (observedService, error) {
	result, err := b.run(ctx, powershellSpec(windowsRDPInspectScript))
	if err != nil {
		var executionErr *commandExecutionError
		if errors.As(err, &executionErr) {
			return observedService{}, &Error{Code: CodeUnsupportedTarget, Cause: errBackendUnsupported}
		}
		return observedService{}, err
	}
	values := parseStrictKeyValues(result.stdout, []string{
		"PolicyEnabled", "FirewallRulesUnique", "FirewallEnabled", "FirewallSnapshot", "ServiceEnabled",
		"Running", "PID", "Generation", "Listening",
	})
	if values == nil {
		return observedService{}, errBackendState
	}
	policy, err := parseBinary(values["PolicyEnabled"])
	if err != nil {
		return observedService{}, errBackendState
	}
	firewall, err := parseBinary(values["FirewallEnabled"])
	if err != nil {
		return observedService{}, errBackendState
	}
	rulesUnique, err := parseBinary(values["FirewallRulesUnique"])
	if err != nil {
		return observedService{}, errBackendState
	}
	nativeSnapshot, err := parseSnapshot(values["FirewallSnapshot"])
	if err != nil {
		return observedService{}, errBackendState
	}
	serviceEnabled, err := parseBinary(values["ServiceEnabled"])
	if err != nil {
		return observedService{}, errBackendState
	}
	running, err := parseBinary(values["Running"])
	if err != nil {
		return observedService{}, errBackendState
	}
	listening, err := parseBinary(values["Listening"])
	if err != nil {
		return observedService{}, errBackendState
	}
	pid, pidErr := parseUint(values["PID"])
	generation, generationErr := parseUint(values["Generation"])
	if pidErr != nil || generationErr != nil ||
		(running && (pid == 0 || generation == 0)) ||
		(!running && (pid != 0 || generation != 0 || listening)) {
		return observedService{}, errBackendState
	}
	enabled := policy && firewall && serviceEnabled
	return observedService{
		state: ServiceState{
			Running: running && enabled && listening,
			Enabled: enabled,
		},
		pid:            pid,
		generation:     generation,
		configuration:  rdpConfiguration(policy, firewall, serviceEnabled),
		nativeSnapshot: nativeSnapshot,
		mutationSafe:   rulesUnique,
		listening:      listening,
		identity:       true,
		unit:           fixedWindowsRDP,
	}, nil
}

func (b *SystemBackend) inspectStructuredWindowsService(
	ctx context.Context,
	service fixedService,
	script string,
) (observedService, error) {
	result, err := b.run(ctx, powershellSpec(script))
	if err != nil {
		var executionErr *commandExecutionError
		if errors.As(err, &executionErr) {
			return observedService{}, &Error{Code: CodeUnsupportedTarget, Cause: errBackendUnsupported}
		}
		return observedService{}, err
	}
	values := parseStrictKeyValues(result.stdout, []string{
		"ServiceEnabled", "Running", "PID", "Generation", "Listening",
	})
	if values == nil {
		return observedService{}, errBackendState
	}
	enabled, err := parseBinary(values["ServiceEnabled"])
	if err != nil {
		return observedService{}, errBackendState
	}
	running, err := parseBinary(values["Running"])
	if err != nil {
		return observedService{}, errBackendState
	}
	listening, err := parseBinary(values["Listening"])
	if err != nil {
		return observedService{}, errBackendState
	}
	pid, pidErr := parseUint(values["PID"])
	generation, generationErr := parseUint(values["Generation"])
	if pidErr != nil || generationErr != nil ||
		(running && (pid == 0 || generation == 0)) ||
		(!running && (pid != 0 || generation != 0 || listening)) ||
		(listening && !running) {
		return observedService{}, errBackendState
	}
	usable := running && enabled && listening
	return observedService{
		state:      ServiceState{Running: usable, Enabled: enabled},
		pid:        pid,
		generation: generation,
		listening:  listening,
		identity:   true,
		unit:       service,
	}, nil
}

func (b *SystemBackend) inspectWindowsSSH(ctx context.Context) (observedService, error) {
	return b.inspectStructuredWindowsService(ctx, fixedWindowsSSH, windowsSSHInspectScript)
}

func revisionFor(target Target, observed observedService) ServiceRevision {
	var revision ServiceRevision
	binary.BigEndian.PutUint64(revision[0:8], observed.pid)
	binary.BigEndian.PutUint64(revision[8:16], observed.generation)
	revision[16] = byte(target.Platform)
	revision[17] = byte(target.Service)
	revision[18] = byte(observed.unit)
	if observed.state.Running {
		revision[19] |= 1
	}
	if observed.state.Enabled {
		revision[19] |= 2
	}
	var digestInput [60]byte
	copy(digestInput[:20], revision[:20])
	binary.BigEndian.PutUint64(digestInput[20:28], observed.configuration)
	copy(digestInput[28:], observed.nativeSnapshot[:])
	digest := sha256.Sum256(digestInput[:])
	copy(revision[20:], digest[:12])
	return revision
}

func rdpConfiguration(policy, firewall, serviceEnabled bool) uint64 {
	var configuration uint64
	if policy {
		configuration |= 1
	}
	if firewall {
		configuration |= 2
	}
	if serviceEnabled {
		configuration |= 4
	}
	return configuration
}

func parseKeyValues(output string) map[string]string {
	values := make(map[string]string, 5)
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "LoadState", "ActiveState", "UnitFileState", "MainPID", "ActiveEnterTimestampMonotonic":
			values[key] = strings.TrimSpace(value)
		}
	}
	return values
}

func parseUint(value string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(value), 10, 64)
}

func parseRemoteLogin(output string) (bool, bool) {
	switch strings.TrimSpace(output) {
	case "Remote Login: On":
		return true, true
	case "Remote Login: Off":
		return false, true
	default:
		return false, false
	}
}

func boolGeneration(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func parseStrictKeyValues(output string, keys []string) map[string]string {
	allowed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		allowed[key] = struct{}{}
	}
	values := make(map[string]string, len(keys))
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			return nil
		}
		if _, ok := allowed[key]; !ok {
			return nil
		}
		if _, duplicate := values[key]; duplicate {
			return nil
		}
		values[key] = strings.TrimSpace(value)
	}
	if len(values) != len(keys) {
		return nil
	}
	return values
}

func parseBinary(value string) (bool, error) {
	switch value {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, errBackendState
	}
}

func parseSnapshot(value string) ([32]byte, error) {
	var snapshot [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(snapshot) {
		return snapshot, errBackendState
	}
	copy(snapshot[:], decoded)
	if snapshot == ([32]byte{}) {
		return snapshot, errBackendState
	}
	return snapshot, nil
}

func linuxUnitEnabled(value string) bool {
	switch value {
	case "enabled", "enabled-runtime", "static", "indirect", "generated":
		return true
	default:
		return false
	}
}
