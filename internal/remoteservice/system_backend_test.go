package remoteservice

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingRunner struct {
	mu    sync.Mutex
	calls []commandSpec
	run   func(context.Context, commandSpec, int) (commandResult, error)
}

type detectorOnlyRunner struct {
	commandRunner
}

type scriptedAtomicRunner struct {
	commandRunner
	result atomicStartResult
	err    error
	wait   bool
}

func (r *scriptedAtomicRunner) StartAtomic(ctx context.Context, _ Target, _ fixedService, _ ServiceState) (atomicStartResult, error) {
	if r.wait {
		<-ctx.Done()
		return r.result, ctx.Err()
	}
	return r.result, r.err
}

func (*scriptedAtomicRunner) RollbackAtomic(context.Context, Target, fixedService, ServiceState, ServiceRevision, [32]byte) error {
	return errors.New("unexpected rollback")
}

type failingRunner struct {
	commandRunner
	script string
}

type failNthScriptRunner struct {
	commandRunner
	script string
	nth    int
	seen   int
}

type waitingScriptRunner struct {
	commandRunner
	script string
}

func (r waitingScriptRunner) Run(ctx context.Context, spec commandSpec, limit int) (commandResult, error) {
	if len(spec.arguments) == 5 && spec.arguments[4] == r.script {
		<-ctx.Done()
		return commandResult{}, ctx.Err()
	}
	return r.commandRunner.Run(ctx, spec, limit)
}

func (r *failNthScriptRunner) Run(ctx context.Context, spec commandSpec, limit int) (commandResult, error) {
	if len(spec.arguments) == 5 && spec.arguments[4] == r.script {
		r.seen++
		if r.seen == r.nth {
			return commandResult{}, errors.New("injected fixed-stage observation failure")
		}
	}
	return r.commandRunner.Run(ctx, spec, limit)
}

func (r failingRunner) Run(ctx context.Context, spec commandSpec, limit int) (commandResult, error) {
	if len(spec.arguments) == 5 && spec.arguments[4] == r.script {
		return commandResult{}, errors.New("injected fixed-stage failure")
	}
	return r.commandRunner.Run(ctx, spec, limit)
}

func (r *recordingRunner) Run(ctx context.Context, spec commandSpec, limit int) (commandResult, error) {
	r.mu.Lock()
	r.calls = append(r.calls, cloneCommand(spec))
	run := r.run
	r.mu.Unlock()
	if run == nil {
		return commandResult{}, nil
	}
	return run(ctx, spec, limit)
}

func (r *recordingRunner) snapshot() []commandSpec {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]commandSpec, len(r.calls))
	for index, call := range r.calls {
		result[index] = cloneCommand(call)
	}
	return result
}

type linuxServiceRunner struct {
	recordingRunner
	unit            string
	running         bool
	enabled         bool
	pid             uint64
	generation      uint64
	startErr        error
	startWait       bool
	noListener      bool
	ownership       [32]byte
	atomicStarts    int
	atomicRollbacks int
	startEntered    chan struct{}
	startGate       <-chan struct{}
	rollbackEntered chan struct{}
	rollbackGate    <-chan struct{}
}

func (r *linuxServiceRunner) StartAtomic(
	_ context.Context,
	target Target,
	unit fixedService,
	before ServiceState,
) (atomicStartResult, error) {
	if r.startEntered != nil {
		r.startEntered <- struct{}{}
	}
	if r.startGate != nil {
		<-r.startGate
	}
	r.recordingRunner.mu.Lock()
	defer r.recordingRunner.mu.Unlock()
	r.atomicStarts++
	current := ServiceState{Running: r.running, Enabled: r.enabled}
	if current != before || r.running {
		return atomicStartResult{definitivelyUnchanged: true}, ErrRollbackConflict
	}
	r.enabled = true
	r.running = true
	r.pid = 101
	r.generation++
	if r.generation == 0 {
		r.generation = 1
	}
	r.ownership = ownershipFor(target, r.pid, r.generation)
	after := observedService{
		state:      ServiceState{Running: true, Enabled: true},
		pid:        r.pid,
		generation: r.generation,
		identity:   true,
		unit:       unit,
	}
	return atomicStartResult{
		after:             after,
		ownership:         r.ownership,
		mutationAttempted: true,
	}, r.startErr
}

func (r *linuxServiceRunner) RollbackAtomic(
	_ context.Context,
	target Target,
	unit fixedService,
	before ServiceState,
	expected ServiceRevision,
	ownership [32]byte,
) error {
	if r.rollbackEntered != nil {
		r.rollbackEntered <- struct{}{}
	}
	if r.rollbackGate != nil {
		<-r.rollbackGate
	}
	r.recordingRunner.mu.Lock()
	defer r.recordingRunner.mu.Unlock()
	r.atomicRollbacks++
	current := observedService{
		state:      ServiceState{Running: r.running, Enabled: r.enabled},
		pid:        r.pid,
		generation: r.generation,
		unit:       unit,
	}
	if revisionFor(target, current) != expected ||
		ownership == ([32]byte{}) ||
		ownership != r.ownership {
		return ErrRollbackConflict
	}
	r.running = before.Running
	r.enabled = before.Enabled
	r.pid = 0
	r.generation = 0
	r.ownership = [32]byte{}
	return nil
}

func newLinuxServiceRunner(unit string) *linuxServiceRunner {
	runner := &linuxServiceRunner{unit: unit}
	runner.recordingRunner.run = runner.execute
	return runner
}

func (r *linuxServiceRunner) execute(ctx context.Context, spec commandSpec, _ int) (commandResult, error) {
	r.recordingRunner.mu.Lock()
	defer r.recordingRunner.mu.Unlock()
	if spec.executable == "/usr/bin/systemctl" && spec.arguments[0] == "show" {
		if spec.arguments[1] != r.unit {
			return commandResult{stdout: "LoadState=not-found\n"}, nil
		}
		active := "inactive"
		if r.running {
			active = "active"
		}
		unitState := "disabled"
		if r.enabled {
			unitState = "enabled"
		}
		return commandResult{stdout: fmt.Sprintf(
			"LoadState=loaded\nActiveState=%s\nUnitFileState=%s\nMainPID=%d\nActiveEnterTimestampMonotonic=%d\n",
			active, unitState, r.pid, r.generation,
		)}, nil
	}
	if spec.executable == "/usr/bin/systemctl" {
		switch spec.arguments[0] {
		case "enable":
			r.enabled = true
		case "disable":
			r.enabled = false
		case "start":
			if r.startWait {
				<-ctx.Done()
				return commandResult{}, nil
			}
			if r.startErr != nil {
				return commandResult{}, r.startErr
			}
			r.running = true
			r.pid = 101
			r.generation = 9001
		case "stop":
			r.running = false
			r.pid = 0
			r.generation = 0
		}
		return commandResult{}, nil
	}
	if spec.executable == "/usr/bin/ss" {
		if r.running && !r.noListener {
			return commandResult{stdout: fmt.Sprintf(
				"LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=%d,fd=3))\n",
				r.pid,
			)}, nil
		}
		return commandResult{}, nil
	}
	return commandResult{}, errors.New("unexpected command")
}

type macServiceRunner struct {
	recordingRunner
	label      string
	running    bool
	enabled    bool
	pid        uint64
	generation uint64
	ownership  [32]byte
}

func (r *macServiceRunner) StartAtomic(
	_ context.Context,
	target Target,
	unit fixedService,
	before ServiceState,
) (atomicStartResult, error) {
	r.recordingRunner.mu.Lock()
	defer r.recordingRunner.mu.Unlock()
	if (ServiceState{Running: r.running, Enabled: r.enabled}) != before || r.running {
		return atomicStartResult{definitivelyUnchanged: true}, ErrRollbackConflict
	}
	r.running = true
	r.enabled = true
	r.pid = 1
	r.generation = 1
	r.ownership = ownershipFor(target, r.pid, r.generation)
	return atomicStartResult{
		after: observedService{
			state:      ServiceState{Running: true, Enabled: true},
			pid:        r.pid,
			generation: r.generation,
			listening:  true,
			identity:   true,
			unit:       unit,
		},
		ownership:         r.ownership,
		mutationAttempted: true,
	}, nil
}

func (r *macServiceRunner) RollbackAtomic(
	_ context.Context,
	target Target,
	unit fixedService,
	before ServiceState,
	expected ServiceRevision,
	ownership [32]byte,
) error {
	r.recordingRunner.mu.Lock()
	defer r.recordingRunner.mu.Unlock()
	current := observedService{
		state:      ServiceState{Running: r.running, Enabled: r.enabled},
		pid:        r.pid,
		generation: r.generation,
		unit:       unit,
	}
	if revisionFor(target, current) != expected || ownership != r.ownership {
		return ErrRollbackConflict
	}
	r.running = before.Running
	r.enabled = before.Enabled
	r.pid = 0
	r.generation = 0
	r.ownership = [32]byte{}
	return nil
}

func newMacServiceRunner(label string) *macServiceRunner {
	runner := &macServiceRunner{label: label}
	runner.recordingRunner.run = runner.execute
	return runner
}

func (r *macServiceRunner) execute(_ context.Context, spec commandSpec, _ int) (commandResult, error) {
	r.recordingRunner.mu.Lock()
	defer r.recordingRunner.mu.Unlock()
	if spec.executable == "/usr/sbin/systemsetup" {
		switch spec.arguments[0] {
		case "-getremotelogin":
			if r.enabled {
				return commandResult{stdout: "Remote Login: On\n"}, nil
			}
			return commandResult{stdout: "Remote Login: Off\n"}, nil
		case "-setremotelogin":
			r.enabled = true
			r.running = true
			r.pid = 1
			r.generation++
			return commandResult{}, nil
		}
	}
	if spec.executable == "/bin/launchctl" {
		switch spec.arguments[0] {
		case "print":
			if !r.enabled && !r.running {
				return commandResult{}, errors.New("not loaded")
			}
			state := "waiting"
			if r.running {
				state = "running"
			}
			return commandResult{stdout: fmt.Sprintf(
				"state = %s\npid = %d\nruns = %d\n", state, r.pid, r.generation,
			)}, nil
		case "print-disabled":
			if !r.enabled {
				return commandResult{stdout: fmt.Sprintf(`"%s" => true`, r.label)}, nil
			}
			return commandResult{stdout: "{}"}, nil
		case "enable":
			r.enabled = true
		case "disable":
			r.enabled = false
		case "kickstart":
			r.running = true
			r.pid = 202
			r.generation++
		case "kill":
			r.running = false
			r.pid = 0
		}
		return commandResult{}, nil
	}
	if spec.executable == "/usr/sbin/lsof" {
		if r.running {
			port := "5900"
			for _, argument := range spec.arguments {
				if argument == "-iTCP:22" {
					port = "22"
				}
			}
			name := "service"
			pid := r.pid
			if port == "22" {
				name = "launchd"
				pid = 1
			}
			return commandResult{stdout: fmt.Sprintf("%s %d root TCP *:%s (LISTEN)\n", name, pid, port)}, nil
		}
		return commandResult{}, nil
	}
	return commandResult{}, errors.New("unexpected command")
}

type windowsServiceRunner struct {
	recordingRunner
	name              string
	running           bool
	enabled           bool
	pid               uint64
	generation        uint64
	ownership         [32]byte
	rdpPolicy         bool
	rdpFirewall       bool
	rulesUnique       bool
	firewallAction    string
	firewallDirection string
	firewallProfile   string
	tcpProtocol       string
	udpProtocol       string
	tcpPort           string
	udpPort           string
	localAddress      string
	remoteAddress     string
	application       string
	serviceFilter     string
	interfaceType     string
	interfaceAlias    string
}

func newWindowsServiceRunner(name string) *windowsServiceRunner {
	runner := &windowsServiceRunner{name: name, rulesUnique: true}
	runner.recordingRunner.run = runner.execute
	return runner
}

func (r *windowsServiceRunner) execute(_ context.Context, spec commandSpec, _ int) (commandResult, error) {
	r.recordingRunner.mu.Lock()
	defer r.recordingRunner.mu.Unlock()
	if spec.executable == `C:\Windows\System32\sc.exe` {
		switch spec.arguments[0] {
		case "queryex":
			state := "1 STOPPED"
			if r.running {
				state = "4 RUNNING"
			}
			return commandResult{stdout: fmt.Sprintf("STATE : %s\nPID : %d\n", state, r.pid)}, nil
		case "qc":
			startType := "4 DISABLED"
			if r.enabled {
				startType = "3 DEMAND_START"
			}
			return commandResult{stdout: "START_TYPE : " + startType + "\n"}, nil
		case "config":
			r.enabled = spec.arguments[3] != "disabled"
		case "start":
			r.running = true
			r.pid = 303
			r.generation++
		case "stop":
			r.running = false
			r.pid = 0
		}
		return commandResult{}, nil
	}
	if spec.executable == `C:\Windows\System32\netstat.exe` {
		if r.running {
			port := "22"
			if r.name == "TermService" {
				port = "3389"
			}
			return commandResult{stdout: fmt.Sprintf("TCP 0.0.0.0:%s 0.0.0.0:0 LISTENING %d\n", port, r.pid)}, nil
		}
		return commandResult{}, nil
	}
	if spec.executable == `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` {
		if spec.arguments[4] == windowsSSHInspectScript {
			return commandResult{stdout: fmt.Sprintf(
				"ServiceEnabled=%d\nRunning=%d\nPID=%d\nGeneration=%d\nListening=%d\n",
				boolInt(r.enabled), boolInt(r.running), r.pid, r.generation, boolInt(r.running),
			)}, nil
		}
		if spec.arguments[4] == windowsRDPInspectScript {
			return commandResult{stdout: fmt.Sprintf(
				"PolicyEnabled=%d\nFirewallRulesUnique=%d\nFirewallEnabled=%d\nFirewallSnapshot=%x\nServiceEnabled=%d\nRunning=%d\nPID=%d\nGeneration=%d\nListening=%d\n",
				boolInt(r.rdpPolicy), boolInt(r.rulesUnique), boolInt(r.firewallCompliant()), r.firewallSnapshot(), boolInt(r.enabled),
				boolInt(r.running), r.pid, r.generation, boolInt(r.running),
			)}, nil
		}
		if spec.arguments[4] == windowsRDPEnablePolicyScript {
			r.rdpPolicy = true
			return commandResult{}, nil
		}
		if spec.arguments[4] == windowsRDPDisableFirewallScript {
			r.rdpFirewall = false
			return commandResult{}, nil
		}
		if spec.arguments[4] == windowsRDPEnableFirewallScript {
			r.rdpFirewall = false
			r.firewallAction = "Allow"
			r.firewallDirection = "Inbound"
			r.firewallProfile = "Any"
			return commandResult{}, nil
		}
		if spec.arguments[4] == windowsRDPEnablePortScript {
			r.tcpProtocol = "TCP"
			r.udpProtocol = "UDP"
			r.tcpPort = "3389"
			r.udpPort = "3389"
			return commandResult{}, nil
		}
		if spec.arguments[4] == windowsRDPEnableAddressScript {
			r.localAddress = "Any"
			r.remoteAddress = "100.64.0.0/10"
			return commandResult{}, nil
		}
		if spec.arguments[4] == windowsRDPEnableBindingScript {
			r.application = `%SystemRoot%\System32\svchost.exe`
			r.serviceFilter = "TermService"
			r.interfaceType = "Any"
			r.interfaceAlias = "ratelmesh0"
			return commandResult{}, nil
		}
		if spec.arguments[4] == windowsRDPVerifyDisabledScript {
			if !r.firewallShapeCompliant(false) {
				return commandResult{}, errors.New("disabled firewall verification failed")
			}
			return commandResult{}, nil
		}
		if spec.arguments[4] == windowsRDPFinalEnableScript {
			if !r.firewallShapeCompliant(false) {
				return commandResult{}, errors.New("pre-enable firewall verification failed")
			}
			r.rdpFirewall = true
			return commandResult{}, nil
		}
		if spec.arguments[4] == windowsRDPVerifyEnabledScript {
			if !r.firewallShapeCompliant(true) {
				return commandResult{}, errors.New("enabled firewall verification failed")
			}
			return commandResult{}, nil
		}
		return commandResult{stdout: fmt.Sprintf("%d\n", r.generation)}, nil
	}
	return commandResult{}, errors.New("unexpected command")
}

func (r *windowsServiceRunner) StartAtomic(
	_ context.Context,
	target Target,
	unit fixedService,
	before ServiceState,
) (atomicStartResult, error) {
	r.recordingRunner.mu.Lock()
	defer r.recordingRunner.mu.Unlock()
	if (ServiceState{Running: r.running, Enabled: r.enabled}) != before || r.running {
		return atomicStartResult{definitivelyUnchanged: true}, ErrRollbackConflict
	}
	r.running = true
	r.enabled = true
	if unit == fixedWindowsRDP {
		r.rdpPolicy = true
		r.setCompliantFirewall()
	}
	r.pid = 303
	r.generation++
	if r.generation == 0 {
		r.generation = 1
	}
	r.ownership = ownershipFor(target, r.pid, r.generation)
	return atomicStartResult{
		after: observedService{
			state:          ServiceState{Running: true, Enabled: true},
			pid:            r.pid,
			generation:     r.generation,
			configuration:  windowsTestConfiguration(unit, r),
			nativeSnapshot: windowsTestSnapshot(unit, r),
			mutationSafe:   unit != fixedWindowsRDP || r.rulesUnique,
			listening:      true,
			identity:       true,
			unit:           unit,
		},
		ownership:         r.ownership,
		mutationAttempted: true,
	}, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (r *windowsServiceRunner) setCompliantFirewall() {
	r.rdpFirewall = true
	r.firewallAction = "Allow"
	r.firewallDirection = "Inbound"
	r.firewallProfile = "Any"
	r.tcpProtocol = "TCP"
	r.udpProtocol = "UDP"
	r.tcpPort = "3389"
	r.udpPort = "3389"
	r.localAddress = "Any"
	r.remoteAddress = "100.64.0.0/10"
	r.application = `%SystemRoot%\System32\svchost.exe`
	r.serviceFilter = "TermService"
	r.interfaceType = "Any"
	r.interfaceAlias = "ratelmesh0"
}

func (r *windowsServiceRunner) firewallCompliant() bool {
	return r.firewallShapeCompliant(true)
}

func (r *windowsServiceRunner) firewallShapeCompliant(enabled bool) bool {
	return r.rdpFirewall == enabled &&
		r.rulesUnique &&
		r.firewallAction == "Allow" &&
		r.firewallDirection == "Inbound" &&
		r.firewallProfile == "Any" &&
		r.tcpProtocol == "TCP" &&
		r.udpProtocol == "UDP" &&
		r.tcpPort == "3389" &&
		r.udpPort == "3389" &&
		r.localAddress == "Any" &&
		r.remoteAddress == "100.64.0.0/10" &&
		r.application == `%SystemRoot%\System32\svchost.exe` &&
		r.serviceFilter == "TermService" &&
		r.interfaceType == "Any" &&
		r.interfaceAlias == "ratelmesh0"
}

func (r *windowsServiceRunner) firewallSnapshot() [32]byte {
	return sha256.Sum256([]byte(strings.Join([]string{
		fmt.Sprint(r.rulesUnique), fmt.Sprint(r.rdpFirewall),
		r.firewallAction, r.firewallDirection, r.firewallProfile,
		r.tcpProtocol, r.udpProtocol, r.tcpPort, r.udpPort,
		r.localAddress, r.remoteAddress, r.application, r.serviceFilter,
		r.interfaceType, r.interfaceAlias,
	}, "|")))
}

func (r *windowsServiceRunner) RollbackAtomic(
	_ context.Context,
	target Target,
	unit fixedService,
	before ServiceState,
	expected ServiceRevision,
	ownership [32]byte,
) error {
	r.recordingRunner.mu.Lock()
	defer r.recordingRunner.mu.Unlock()
	current := observedService{
		state:          ServiceState{Running: r.running, Enabled: r.enabled},
		pid:            r.pid,
		generation:     r.generation,
		configuration:  windowsTestConfiguration(unit, r),
		nativeSnapshot: windowsTestSnapshot(unit, r),
		unit:           unit,
	}
	if revisionFor(target, current) != expected || ownership != r.ownership {
		return ErrRollbackConflict
	}
	r.running = before.Running
	r.enabled = before.Enabled
	if unit == fixedWindowsRDP {
		r.rdpPolicy = before.Enabled
		r.rdpFirewall = before.Enabled
		if before.Enabled {
			r.setCompliantFirewall()
		}
	}
	r.pid = 0
	r.generation = 0
	r.ownership = [32]byte{}
	return nil
}

func windowsTestConfiguration(unit fixedService, runner *windowsServiceRunner) uint64 {
	if unit != fixedWindowsRDP {
		return 0
	}
	return rdpConfiguration(runner.rdpPolicy, runner.firewallCompliant(), runner.enabled)
}

func windowsTestSnapshot(unit fixedService, runner *windowsServiceRunner) [32]byte {
	if unit != fixedWindowsRDP {
		return [32]byte{}
	}
	return runner.firewallSnapshot()
}

func ownershipFor(target Target, pid, generation uint64) [32]byte {
	var input [50]byte
	copy(input[:32], target.Device[:])
	input[32] = byte(target.Platform)
	input[33] = byte(target.Service)
	binary.BigEndian.PutUint64(input[34:42], pid)
	binary.BigEndian.PutUint64(input[42:50], generation)
	return sha256.Sum256(input[:])
}

func backendPermit(target Target, before ServiceState) StartPermit {
	var nonce [32]byte
	nonce[0] = 1
	return StartPermit{nonce: nonce, target: target, before: before}
}

func TestSystemBackendPlatformMatrix(t *testing.T) {
	supported := []Target{
		targetFor(PlatformLinux, ServiceSSH),
		targetFor(PlatformMacOS, ServiceSSH),
		targetFor(PlatformWindows, ServiceSSH),
		targetFor(PlatformWindows, ServiceRDP),
	}
	for _, target := range supported {
		if _, err := fixedServiceFor(target); err != nil {
			t.Fatalf("supported target %+v: %v", target, err)
		}
	}
	unsupported := []Target{
		targetFor(PlatformLinux, ServiceRDP),
		targetFor(PlatformLinux, ServiceVNC),
		targetFor(PlatformWindows, ServiceVNC),
		targetFor(PlatformMacOS, ServiceVNC),
		targetFor(PlatformMacOS, ServiceRDP),
		targetFor(PlatformAndroid, ServiceSSH),
		targetFor(PlatformIOS, ServiceVNC),
	}
	for _, target := range unsupported {
		if _, err := fixedServiceFor(target); !IsCode(err, CodeUnsupportedTarget) {
			t.Fatalf("unsupported target %+v: %v", target, err)
		}
	}
}

func TestProductionBackendsAreDetectOnlyWithoutNativeAtomicOwnership(t *testing.T) {
	tests := []struct {
		name     string
		platform Platform
		service  ServiceKind
		runner   func() (commandRunner, func() []commandSpec)
	}{
		{"linux SSH", PlatformLinux, ServiceSSH, func() (commandRunner, func() []commandSpec) {
			runner := newLinuxServiceRunner("ssh.service")
			return detectorOnlyRunner{commandRunner: &runner.recordingRunner}, runner.snapshot
		}},
		{"macOS SSH", PlatformMacOS, ServiceSSH, func() (commandRunner, func() []commandSpec) {
			runner := newMacServiceRunner("com.openssh.sshd")
			return detectorOnlyRunner{commandRunner: &runner.recordingRunner}, runner.snapshot
		}},
		{"Windows SSH", PlatformWindows, ServiceSSH, func() (commandRunner, func() []commandSpec) {
			runner := newWindowsServiceRunner("sshd")
			return detectorOnlyRunner{commandRunner: &runner.recordingRunner}, runner.snapshot
		}},
		{"Windows RDP", PlatformWindows, ServiceRDP, func() (commandRunner, func() []commandSpec) {
			runner := newWindowsServiceRunner("TermService")
			return detectorOnlyRunner{commandRunner: &runner.recordingRunner}, runner.snapshot
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner, snapshot := test.runner()
			backend := newSystemBackend(test.platform, runner)
			backend.productionDetectOnly = true
			target := targetFor(test.platform, test.service)
			before, err := backend.Capture(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := backend.Start(
				context.Background(),
				target,
				backendPermit(target, before),
			)
			if !IsCode(err, CodeUnsupportedTarget) || receipt.Changed() {
				t.Fatalf("receipt=%+v error=%v", receipt, err)
			}
			for _, call := range snapshot() {
				if productionCommandMutates(call) {
					t.Fatalf("production detect-only backend ran mutation: %+v", call)
				}
			}
		})
	}
}

func productionCommandMutates(spec commandSpec) bool {
	if spec.executable == "/usr/bin/systemctl" {
		return len(spec.arguments) > 0 && spec.arguments[0] != "show"
	}
	if spec.executable == "/usr/sbin/systemsetup" {
		return len(spec.arguments) > 0 && spec.arguments[0] != "-getremotelogin"
	}
	if spec.executable == `C:\Windows\System32\sc.exe` {
		return len(spec.arguments) > 0 && spec.arguments[0] != "queryex" && spec.arguments[0] != "qc"
	}
	if spec.executable == `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` {
		return len(spec.arguments) != 5 ||
			(spec.arguments[4] != windowsSSHInspectScript && spec.arguments[4] != windowsRDPInspectScript)
	}
	return false
}

func TestAtomicFailedStartRequiresExplicitUnchangedProof(t *testing.T) {
	base := newLinuxServiceRunner("ssh.service")
	target := targetFor(PlatformLinux, ServiceSSH)
	before := ServiceState{}
	for _, test := range []struct {
		name   string
		result atomicStartResult
		wait   bool
	}{
		{
			name:   "zero after mutation",
			result: atomicStartResult{mutationAttempted: true},
		},
		{
			name: "unit mismatch with ownership",
			result: atomicStartResult{
				after: observedService{
					state: ServiceState{Running: true, Enabled: true},
					pid:   99, generation: 1, unit: fixedWindowsSSH,
				},
				ownership:         [32]byte{1},
				mutationAttempted: true,
			},
		},
		{
			name: "incomplete running observation",
			result: atomicStartResult{
				after: observedService{
					state: ServiceState{Running: true, Enabled: true},
					unit:  fixedLinuxSSH,
				},
				ownership:         [32]byte{1},
				mutationAttempted: true,
			},
		},
		{
			name: "running observation missing PID",
			result: atomicStartResult{
				after: observedService{
					state:      ServiceState{Running: true, Enabled: true},
					generation: 1, unit: fixedLinuxSSH,
				},
				ownership:         [32]byte{1},
				mutationAttempted: true,
			},
		},
		{
			name: "running observation missing generation",
			result: atomicStartResult{
				after: observedService{
					state: ServiceState{Running: true, Enabled: true},
					pid:   1, unit: fixedLinuxSSH,
				},
				ownership:         [32]byte{1},
				mutationAttempted: true,
			},
		},
		{
			name: "contradictory definitive unchanged mutation",
			result: atomicStartResult{
				definitivelyUnchanged: true,
				mutationAttempted:     true,
			},
		},
		{
			name: "contradictory definitive unchanged ownership",
			result: atomicStartResult{
				definitivelyUnchanged: true,
				ownership:             [32]byte{1},
			},
		},
		{
			name: "contradictory definitive unchanged after",
			result: atomicStartResult{
				definitivelyUnchanged: true,
				after:                 observedService{unit: fixedWindowsSSH},
			},
		},
		{
			name: "mutation attempted without ownership and unchanged observation",
			result: atomicStartResult{
				after:             observedService{unit: fixedLinuxSSH},
				mutationAttempted: true,
			},
		},
		{
			name:   "timeout with incomplete result",
			result: atomicStartResult{mutationAttempted: true},
			wait:   true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &scriptedAtomicRunner{
				commandRunner: &base.recordingRunner,
				result:        test.result,
				err:           errors.New("native start failed"),
				wait:          test.wait,
			}
			backend := newSystemBackend(PlatformLinux, runner)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			receipt, err := backend.Start(ctx, target, backendPermit(target, before))
			if err == nil || !errors.Is(err, ErrManualCleanupRequired) ||
				!receipt.Changed() || receipt.RollbackAuthorized() {
				t.Fatalf("receipt=%+v error=%v", receipt, err)
			}
		})
	}

	runner := &scriptedAtomicRunner{
		commandRunner: &base.recordingRunner,
		result:        atomicStartResult{definitivelyUnchanged: true},
		err:           errors.New("native rejected before mutation"),
	}
	backend := newSystemBackend(PlatformLinux, runner)
	receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
	if err == nil || receipt.Changed() {
		t.Fatalf("definitively unchanged receipt=%+v error=%v", receipt, err)
	}
}

func TestLinuxBackendStartsAndConditionallyRollsBackFixedSSH(t *testing.T) {
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		t.Run(unit, func(t *testing.T) {
			runner := newLinuxServiceRunner(unit)
			backend := newSystemBackend(PlatformLinux, runner)
			target := targetFor(PlatformLinux, ServiceSSH)
			before, err := backend.Capture(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
			if err != nil {
				t.Fatal(err)
			}
			health, err := backend.Detect(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			if !validHealth(health) || !receipt.Changed() {
				t.Fatalf("health=%+v receipt=%+v", health, receipt)
			}
			if err := backend.Rollback(context.Background(), target, before, receipt); err != nil {
				t.Fatal(err)
			}
			if runner.running || runner.enabled {
				t.Fatalf("rollback left running=%t enabled=%t", runner.running, runner.enabled)
			}
			for _, call := range runner.snapshot() {
				if !allowedCommand(call) {
					t.Fatalf("non-allowlisted command: %+v", call)
				}
				for _, argument := range call.arguments {
					if strings.Contains(argument, "password") || strings.Contains(argument, "username") {
						t.Fatalf("credential-like argument: %q", argument)
					}
				}
			}
			if runner.atomicStarts != 1 || runner.atomicRollbacks != 1 {
				t.Fatalf("atomic starts=%d rollbacks=%d", runner.atomicStarts, runner.atomicRollbacks)
			}
		})
	}
}

func TestLinuxRunningIdentityRequiresPIDAndGeneration(t *testing.T) {
	for _, test := range []struct {
		name       string
		pid        uint64
		generation uint64
	}{
		{"missing PID", 0, 1},
		{"missing generation", 101, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := newLinuxServiceRunner("ssh.service")
			runner.running = true
			runner.enabled = true
			runner.pid = test.pid
			runner.generation = test.generation
			backend := newSystemBackend(PlatformLinux, runner)
			if _, err := backend.Capture(
				context.Background(),
				targetFor(PlatformLinux, ServiceSSH),
			); err == nil {
				t.Fatal("incomplete running identity was accepted")
			}
		})
	}
}

func TestMacBackendsUseOnlyNativeFixedServices(t *testing.T) {
	runner := newMacServiceRunner("com.openssh.sshd")
	backend := newSystemBackend(PlatformMacOS, runner)
	target := targetFor(PlatformMacOS, ServiceSSH)
	before, err := backend.Capture(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
	if err != nil {
		t.Fatal(err)
	}
	health, err := backend.Detect(context.Background(), target)
	if err != nil || !validHealth(health) {
		t.Fatalf("health=%+v err=%v", health, err)
	}
	if err := backend.Rollback(context.Background(), target, before, receipt); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.snapshot() {
		if !allowedCommand(call) {
			t.Fatalf("non-allowlisted command: %+v", call)
		}
	}
}

func TestMacRemoteLoginSocketActivationDoesNotRequireMatchingJobPID(t *testing.T) {
	runner := newMacServiceRunner("com.openssh.sshd")
	runner.enabled = true
	runner.running = true
	runner.pid = 202 // lsof deliberately reports trusted launchd PID 1.
	backend := newSystemBackend(
		PlatformMacOS,
		detectorOnlyRunner{commandRunner: &runner.recordingRunner},
	)
	health, err := backend.Detect(
		context.Background(),
		targetFor(PlatformMacOS, ServiceSSH),
	)
	if err != nil || !validHealth(health) {
		t.Fatalf("socket-activated health=%+v error=%v", health, err)
	}
}

func TestWindowsBackendsUseFixedServices(t *testing.T) {
	for _, test := range []struct {
		service ServiceKind
		name    string
	}{
		{service: ServiceSSH, name: "sshd"},
		{service: ServiceRDP, name: "TermService"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := newWindowsServiceRunner(test.name)
			backend := newSystemBackend(PlatformWindows, runner)
			target := targetFor(PlatformWindows, test.service)
			before, err := backend.Capture(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
			if err != nil {
				t.Fatal(err)
			}
			health, err := backend.Detect(context.Background(), target)
			if err != nil || !validHealth(health) {
				t.Fatalf("health=%+v err=%v", health, err)
			}
			if err := backend.Rollback(context.Background(), target, before, receipt); err != nil {
				t.Fatal(err)
			}
			for _, call := range runner.snapshot() {
				if !allowedCommand(call) {
					t.Fatalf("non-allowlisted command: %+v", call)
				}
			}
		})
	}
}

func TestSystemBackendRejectsArbitraryCommandsBeforeRunner(t *testing.T) {
	runner := &recordingRunner{}
	backend := newSystemBackend(PlatformLinux, runner)
	malicious := []commandSpec{
		{executable: "/bin/sh", arguments: []string{"-c", "id"}},
		{executable: "/usr/bin/systemctl", arguments: []string{"start", "../../evil"}},
		{executable: "/usr/bin/systemctl", arguments: []string{"status", "ssh.service"}},
		{executable: `C:\Windows\System32\sc.exe`, arguments: []string{"start", "attacker"}},
		{
			executable: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			arguments:  []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "Get-Process; whoami"},
		},
	}
	for _, spec := range malicious {
		if _, err := backend.run(context.Background(), spec); err == nil {
			t.Fatalf("accepted command %+v", spec)
		}
	}
	if len(runner.snapshot()) != 0 {
		t.Fatalf("runner received rejected commands: %+v", runner.snapshot())
	}
}

func TestSystemBackendCommandEnvironmentIsFixed(t *testing.T) {
	if got := fixedCommandEnvironment("linux"); !equalArguments(got,
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C") {
		t.Fatalf("unix environment = %#v", got)
	}
	if got := fixedCommandEnvironment("windows"); !equalArguments(got,
		`PATH=C:\Windows\System32`, `SystemRoot=C:\Windows`, `WINDIR=C:\Windows`) {
		t.Fatalf("windows environment = %#v", got)
	}
	if fixedCommandDirectory("linux") != "/" ||
		fixedCommandDirectory("windows") != `C:\Windows\System32` {
		t.Fatal("command working directories are not fixed")
	}
}

func TestSystemBackendRejectsWrongPlatformAndUntrustedVNC(t *testing.T) {
	runner := &recordingRunner{}
	backend := newSystemBackend(PlatformLinux, runner)
	for _, target := range []Target{
		targetFor(PlatformWindows, ServiceSSH),
		targetFor(PlatformLinux, ServiceVNC),
		targetFor(PlatformLinux, ServiceRDP),
	} {
		if _, err := backend.Capture(context.Background(), target); !IsCode(err, CodeUnsupportedTarget) {
			t.Fatalf("target=%+v error=%v", target, err)
		}
	}
	if len(runner.snapshot()) != 0 {
		t.Fatalf("rejected targets reached runner: %+v", runner.snapshot())
	}
}

func TestSystemBackendBoundsContextAndOutput(t *testing.T) {
	t.Run("context", func(t *testing.T) {
		runner := &recordingRunner{}
		runner.run = func(ctx context.Context, _ commandSpec, _ int) (commandResult, error) {
			<-ctx.Done()
			return commandResult{}, nil
		}
		backend := newSystemBackend(PlatformLinux, runner)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := backend.Capture(ctx, targetFor(PlatformLinux, ServiceSSH))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout error = %v", err)
		}
	})
	t.Run("hostile output", func(t *testing.T) {
		runner := &recordingRunner{
			run: func(_ context.Context, _ commandSpec, limit int) (commandResult, error) {
				return commandResult{stdout: strings.Repeat("x", limit+1)}, nil
			},
		}
		backend := newSystemBackend(PlatformLinux, runner)
		if _, err := backend.Capture(context.Background(), targetFor(PlatformLinux, ServiceSSH)); err == nil {
			t.Fatal("oversized output was accepted")
		}
	})
}

func TestListenerParsingUsesExactPortAndPIDTokens(t *testing.T) {
	linuxFalse := `LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:(("sshd",pid=123,fd=3))`
	if linuxOutputHasPortPID(linuxFalse, 22, 12) ||
		linuxOutputHasPortPID(linuxFalse, 22, 123) ||
		linuxOutputHasPortPID(linuxFalse, 2200, 12) {
		t.Fatal("Linux listener accepted a port/PID substring")
	}
	if linuxOutputHasPortPID(
		`LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=oops,fd=3))`,
		22,
		12,
	) {
		t.Fatal("Linux listener accepted malformed PID")
	}
	linuxTrue := `LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=12,fd=3))`
	if !linuxOutputHasPortPID(linuxTrue, 22, 12) {
		t.Fatal("Linux listener rejected exact tokens")
	}

	macFalse := "sshd 123 root 3u IPv6 TCP *:2222 (LISTEN)"
	if macOutputHasPortPID(macFalse, 22, 12) ||
		macOutputHasPortPID(macFalse, 22, 123) ||
		macOutputHasPortPID(macFalse, 2222, 12) {
		t.Fatal("macOS listener accepted a port/PID substring")
	}
	macTrue := "sshd 12 root 3u IPv6 TCP *:22 (LISTEN)"
	if !macOutputHasPortPID(macTrue, 22, 12) {
		t.Fatal("macOS listener rejected exact tokens")
	}
}

func TestCLIBackendStartsWithoutRollbackAuthority(t *testing.T) {
	stateRunner := newLinuxServiceRunner("ssh.service")
	backend := newSystemBackend(
		PlatformLinux,
		detectorOnlyRunner{commandRunner: &stateRunner.recordingRunner},
	)
	target := targetFor(PlatformLinux, ServiceSSH)
	before, err := backend.Capture(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
	if err != nil || !receipt.Changed() || receipt.RollbackAuthorized() {
		t.Fatalf("receipt=%+v error=%v", receipt, err)
	}
	health, err := backend.Detect(context.Background(), target)
	if err != nil || !validHealth(health) {
		t.Fatalf("health=%+v error=%v", health, err)
	}
	foundEnable, foundStart := false, false
	for _, call := range stateRunner.snapshot() {
		if len(call.arguments) > 0 {
			switch call.arguments[0] {
			case "enable":
				foundEnable = true
			case "start":
				foundStart = true
			case "stop", "disable", "kill":
				t.Fatalf("CLI backend obtained stop authority: %+v", call)
			}
		}
	}
	if !foundEnable || !foundStart {
		t.Fatalf("fixed CLI start path incomplete: %+v", stateRunner.snapshot())
	}
}

func TestManagerReportsSuccessfulCLIStartWithoutRollbackAuthority(t *testing.T) {
	stateRunner := newLinuxServiceRunner("ssh.service")
	backend := newSystemBackend(
		PlatformLinux,
		detectorOnlyRunner{commandRunner: &stateRunner.recordingRunner},
	)
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	manager, err := NewManager(backend, confirmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	target := targetFor(PlatformLinux, ServiceSSH)
	result, err := manager.EnsureRunning(
		context.Background(),
		confirmedRequest(t, confirmer, target),
	)
	if err != nil ||
		result.Code != OutcomeStarted ||
		result.RollbackAuthority ||
		result.MayRemainRunning {
		t.Fatalf("result=%+v error=%#v", result, err)
	}
	if !stateRunner.running || !stateRunner.enabled {
		t.Fatal("successful CLI start did not run service")
	}
}

func TestMacAndWindowsCLIStartPathsAreFixedAndUsable(t *testing.T) {
	t.Run("mac remote login", func(t *testing.T) {
		stateRunner := newMacServiceRunner("com.openssh.sshd")
		backend := newSystemBackend(
			PlatformMacOS,
			detectorOnlyRunner{commandRunner: &stateRunner.recordingRunner},
		)
		target := targetFor(PlatformMacOS, ServiceSSH)
		before, err := backend.Capture(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
		if err != nil || !receipt.Changed() || receipt.RollbackAuthorized() {
			t.Fatalf("receipt=%+v error=%v", receipt, err)
		}
		foundEnable, foundStart := false, false
		for _, call := range stateRunner.snapshot() {
			if equalArguments(call.arguments, "-setremotelogin", "on") {
				foundEnable = true
			}
			if equalArguments(call.arguments, "-getremotelogin") {
				foundStart = true
			}
		}
		if !foundEnable || !foundStart {
			t.Fatalf("mac fixed actions missing: %+v", stateRunner.snapshot())
		}
	})

	t.Run("windows rdp", func(t *testing.T) {
		stateRunner := newWindowsServiceRunner("TermService")
		backend := newSystemBackend(
			PlatformWindows,
			detectorOnlyRunner{commandRunner: &stateRunner.recordingRunner},
		)
		target := targetFor(PlatformWindows, ServiceRDP)
		before, err := backend.Capture(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
		if err != nil || !receipt.Changed() || receipt.RollbackAuthorized() {
			t.Fatalf("receipt=%+v error=%v", receipt, err)
		}
		foundPolicy, foundFirewall, foundEnable, foundStart := false, false, false, false
		var firewallStages []string
		for _, call := range stateRunner.snapshot() {
			if len(call.arguments) == 5 && call.arguments[4] == windowsRDPEnablePolicyScript {
				foundPolicy = true
			}
			if len(call.arguments) == 5 && call.arguments[4] == windowsRDPEnableFirewallScript {
				foundFirewall = true
			}
			if len(call.arguments) == 5 {
				for _, stage := range []string{
					windowsRDPDisableFirewallScript,
					windowsRDPEnableFirewallScript,
					windowsRDPEnablePortScript,
					windowsRDPEnableAddressScript,
					windowsRDPEnableBindingScript,
					windowsRDPVerifyDisabledScript,
					windowsRDPFinalEnableScript,
					windowsRDPVerifyEnabledScript,
					windowsRDPEnablePolicyScript,
				} {
					if call.arguments[4] == stage {
						firewallStages = append(firewallStages, stage)
					}
				}
			}
			if equalArguments(call.arguments, "config", "TermService", "start=", "demand") {
				foundEnable = true
			}
			if equalArguments(call.arguments, "start", "TermService") {
				foundStart = true
			}
		}
		if !foundPolicy || !foundFirewall || !foundEnable || !foundStart {
			t.Fatalf("Windows fixed actions missing: %+v", stateRunner.snapshot())
		}
		expectedStages := []string{
			windowsRDPDisableFirewallScript,
			windowsRDPEnableFirewallScript,
			windowsRDPEnablePortScript,
			windowsRDPEnableAddressScript,
			windowsRDPEnableBindingScript,
			windowsRDPVerifyDisabledScript,
			windowsRDPFinalEnableScript,
			windowsRDPVerifyEnabledScript,
			windowsRDPEnablePolicyScript,
		}
		if !slices.Equal(firewallStages, expectedStages) {
			t.Fatalf("unsafe RDP stage order: got=%v want=%v", firewallStages, expectedStages)
		}
	})
}

func TestWindowsRDPPartialStagesRequireManualCleanupAndNeverStop(t *testing.T) {
	t.Run("configuration failure keeps policy closed and firewall disabled", func(t *testing.T) {
		state := newWindowsServiceRunner("TermService")
		runner := failingRunner{
			commandRunner: &state.recordingRunner,
			script:        windowsRDPEnableFirewallScript,
		}
		backend := newSystemBackend(PlatformWindows, runner)
		target := targetFor(PlatformWindows, ServiceRDP)
		before, err := backend.Capture(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
		if err == nil || !errors.Is(err, ErrManualCleanupRequired) ||
			!receipt.Changed() || receipt.RollbackAuthorized() {
			t.Fatalf("receipt=%+v error=%v", receipt, err)
		}
		if state.rdpPolicy || state.rdpFirewall || state.running {
			t.Fatalf("partial RDP state=%+v", state)
		}
		assertNoStopCommand(t, state.snapshot())
	})

	t.Run("post-mutation inspection failure is uncertain", func(t *testing.T) {
		state := newWindowsServiceRunner("TermService")
		runner := &failNthScriptRunner{
			commandRunner: &state.recordingRunner,
			script:        windowsRDPInspectScript,
			nth:           5, // Capture, Start read, CLI guard, preflight, then post-mutation inspect.
		}
		backend := newSystemBackend(PlatformWindows, runner)
		target := targetFor(PlatformWindows, ServiceRDP)
		before, err := backend.Capture(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
		if err == nil || !errors.Is(err, ErrManualCleanupRequired) ||
			!receipt.Changed() || receipt.RollbackAuthorized() {
			t.Fatalf("receipt=%+v error=%v", receipt, err)
		}
		assertNoStopCommand(t, state.snapshot())
	})
}

func TestWindowsRDPEachMutationStageFailureIsUncertain(t *testing.T) {
	stages := []string{
		windowsRDPDisableFirewallScript,
		windowsRDPEnableFirewallScript,
		windowsRDPEnablePortScript,
		windowsRDPEnableAddressScript,
		windowsRDPEnableBindingScript,
		windowsRDPVerifyDisabledScript,
		windowsRDPFinalEnableScript,
		windowsRDPVerifyEnabledScript,
		windowsRDPEnablePolicyScript,
	}
	for index, stage := range stages {
		t.Run(fmt.Sprintf("stage-%d", index), func(t *testing.T) {
			state := newWindowsServiceRunner("TermService")
			backend := newSystemBackend(PlatformWindows, failingRunner{
				commandRunner: &state.recordingRunner,
				script:        stage,
			})
			target := targetFor(PlatformWindows, ServiceRDP)
			before, err := backend.Capture(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
			if err == nil || !errors.Is(err, ErrManualCleanupRequired) ||
				!receipt.Changed() || receipt.RollbackAuthorized() {
				t.Fatalf("receipt=%+v error=%v", receipt, err)
			}
			assertNoStopCommand(t, state.snapshot())
		})
	}

	t.Run("timeout", func(t *testing.T) {
		state := newWindowsServiceRunner("TermService")
		backend := newSystemBackend(PlatformWindows, waitingScriptRunner{
			commandRunner: &state.recordingRunner,
			script:        windowsRDPEnablePortScript,
		})
		target := targetFor(PlatformWindows, ServiceRDP)
		before, err := backend.Capture(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		receipt, err := backend.Start(ctx, target, backendPermit(target, before))
		if err == nil || !errors.Is(err, ErrManualCleanupRequired) ||
			!receipt.Changed() || receipt.RollbackAuthorized() {
			t.Fatalf("receipt=%+v error=%v", receipt, err)
		}
		assertNoStopCommand(t, state.snapshot())
	})
}

func TestRunningTermServiceWithClosedPolicyIsConfirmedAndRepaired(t *testing.T) {
	state := newWindowsServiceRunner("TermService")
	state.running = true
	state.enabled = true
	state.pid = 303
	state.generation = 9
	backend := newSystemBackend(
		PlatformWindows,
		detectorOnlyRunner{commandRunner: &state.recordingRunner},
	)
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	manager, _ := NewManager(backend, confirmer, testConfig())
	target := targetFor(PlatformWindows, ServiceRDP)
	result, err := manager.EnsureRunning(
		context.Background(),
		confirmedRequest(t, confirmer, target),
	)
	if err != nil || result.Code != OutcomeStarted || !validHealth(result.Health) {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if !state.rdpPolicy || !state.firewallCompliant() || !state.running {
		t.Fatalf("RDP was not fully repaired: %+v", state)
	}
	for _, call := range state.snapshot() {
		if call.executable == `C:\Windows\System32\netstat.exe` ||
			(len(call.arguments) > 0 &&
				(call.arguments[0] == "queryex" || call.arguments[0] == "qc")) {
			t.Fatalf("localized text parser command used: %+v", call)
		}
	}
}

func TestWindowsRDPFirewallShapeMustBeExact(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*windowsServiceRunner)
	}{
		{"block action", func(r *windowsServiceRunner) { r.firewallAction = "Block" }},
		{"outbound direction", func(r *windowsServiceRunner) { r.firewallDirection = "Outbound" }},
		{"wrong TCP port", func(r *windowsServiceRunner) { r.tcpPort = "3390" }},
		{"wrong UDP protocol", func(r *windowsServiceRunner) { r.udpProtocol = "TCP" }},
		{"insufficient profile", func(r *windowsServiceRunner) { r.firewallProfile = "Private" }},
		{"not mesh scoped", func(r *windowsServiceRunner) { r.remoteAddress = "192.168.0.0/16" }},
		{"overbroad remote scope", func(r *windowsServiceRunner) { r.remoteAddress = "Any" }},
		{"wrong application", func(r *windowsServiceRunner) { r.application = `C:\evil.exe` }},
		{"overbroad application", func(r *windowsServiceRunner) { r.application = "Any" }},
		{"overbroad service", func(r *windowsServiceRunner) { r.serviceFilter = "Any" }},
		{"interface type constrained", func(r *windowsServiceRunner) { r.interfaceType = "Wireless" }},
		{"interface alias constrained", func(r *windowsServiceRunner) { r.interfaceAlias = "Ethernet" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := newWindowsServiceRunner("TermService")
			state.running = true
			state.enabled = true
			state.pid = 303
			state.generation = 8
			state.rdpPolicy = true
			state.setCompliantFirewall()
			test.mutate(state)
			backend := newSystemBackend(
				PlatformWindows,
				detectorOnlyRunner{commandRunner: &state.recordingRunner},
			)
			health, err := backend.Detect(
				context.Background(),
				targetFor(PlatformWindows, ServiceRDP),
			)
			if err != nil {
				t.Fatal(err)
			}
			if validHealth(health) || health.Healthy {
				t.Fatalf("non-compliant firewall reported healthy: %+v", health)
			}
		})
	}
}

func TestWindowsRDPDuplicateRulesFailBeforeMutation(t *testing.T) {
	state := newWindowsServiceRunner("TermService")
	state.rulesUnique = false
	backend := newSystemBackend(
		PlatformWindows,
		detectorOnlyRunner{commandRunner: &state.recordingRunner},
	)
	target := targetFor(PlatformWindows, ServiceRDP)
	before, err := backend.Capture(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
	if err == nil || receipt.Changed() {
		t.Fatalf("duplicate-rule receipt=%+v error=%v", receipt, err)
	}
	if state.rdpPolicy || state.rdpFirewall || state.enabled || state.running {
		t.Fatalf("duplicate-rule preflight mutated state: %+v", state)
	}
	for _, call := range state.snapshot() {
		if len(call.arguments) == 5 &&
			(call.arguments[4] == windowsRDPEnablePolicyScript ||
				call.arguments[4] == windowsRDPDisableFirewallScript ||
				call.arguments[4] == windowsRDPEnableFirewallScript ||
				call.arguments[4] == windowsRDPEnablePortScript ||
				call.arguments[4] == windowsRDPEnableAddressScript ||
				call.arguments[4] == windowsRDPEnableBindingScript ||
				call.arguments[4] == windowsRDPVerifyDisabledScript ||
				call.arguments[4] == windowsRDPFinalEnableScript ||
				call.arguments[4] == windowsRDPVerifyEnabledScript) {
			t.Fatalf("mutation ran after duplicate-rule preflight: %+v", call)
		}
	}
}

func TestWindowsStructuredServiceOutputFailsClosed(t *testing.T) {
	runner := &recordingRunner{run: func(_ context.Context, spec commandSpec, _ int) (commandResult, error) {
		if len(spec.arguments) == 5 && spec.arguments[4] == windowsSSHInspectScript {
			return commandResult{stdout: "ServiceEnabled=1\nRunning=1\nPID=12\nListening=1\n"}, nil
		}
		return commandResult{}, errors.New("unexpected command")
	}}
	backend := newSystemBackend(PlatformWindows, runner)
	if _, err := backend.Detect(context.Background(), targetFor(PlatformWindows, ServiceSSH)); err == nil {
		t.Fatal("missing structured field was accepted")
	}
}

func TestWindowsSSHUsesOnlyLocaleIndependentStructuredInspection(t *testing.T) {
	state := newWindowsServiceRunner("sshd")
	backend := newSystemBackend(
		PlatformWindows,
		detectorOnlyRunner{commandRunner: &state.recordingRunner},
	)
	target := targetFor(PlatformWindows, ServiceSSH)
	before, err := backend.Capture(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
	if err != nil || !receipt.Changed() || receipt.RollbackAuthorized() {
		t.Fatalf("receipt=%+v error=%v", receipt, err)
	}
	health, err := backend.Detect(context.Background(), target)
	if err != nil || !validHealth(health) {
		t.Fatalf("health=%+v error=%v", health, err)
	}
	for _, call := range state.snapshot() {
		if call.executable == `C:\Windows\System32\netstat.exe` ||
			(len(call.arguments) > 0 &&
				(call.arguments[0] == "queryex" || call.arguments[0] == "qc")) {
			t.Fatalf("localized command output was used: %+v", call)
		}
	}
}

func assertNoStopCommand(t *testing.T, calls []commandSpec) {
	t.Helper()
	for _, call := range calls {
		if len(call.arguments) > 0 &&
			(call.arguments[0] == "stop" || call.arguments[0] == "disable" ||
				call.arguments[0] == "kill") {
			t.Fatalf("unsafe rollback command: %+v", call)
		}
	}
}

func TestCLIStartFailureWithEnableChangeRequiresManualCleanup(t *testing.T) {
	stateRunner := newLinuxServiceRunner("ssh.service")
	stateRunner.startErr = errors.New("start failed")
	backend := newSystemBackend(
		PlatformLinux,
		detectorOnlyRunner{commandRunner: &stateRunner.recordingRunner},
	)
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	manager, _ := NewManager(backend, confirmer, testConfig())
	target := targetFor(PlatformLinux, ServiceSSH)
	result, err := manager.EnsureRunning(
		context.Background(),
		confirmedRequest(t, confirmer, target),
	)
	var serviceErr *Error
	if !errors.As(err, &serviceErr) ||
		serviceErr.RollbackCode != CodeManualCleanupRequired ||
		result.Code != OutcomeManualCleanup ||
		!result.MayRemainRunning ||
		result.RollbackAuthority {
		t.Fatalf("result=%+v error=%#v", result, err)
	}
	if stateRunner.running || !stateRunner.enabled {
		t.Fatalf("partial state running=%t enabled=%t", stateRunner.running, stateRunner.enabled)
	}
	for _, call := range stateRunner.snapshot() {
		if len(call.arguments) > 0 &&
			(call.arguments[0] == "stop" || call.arguments[0] == "disable") {
			t.Fatalf("CLI failure performed unsafe rollback: %+v", call)
		}
	}
}

func TestCLIStartTimeoutWithEnableChangeRequiresManualCleanup(t *testing.T) {
	stateRunner := newLinuxServiceRunner("ssh.service")
	stateRunner.startWait = true
	backend := newSystemBackend(
		PlatformLinux,
		detectorOnlyRunner{commandRunner: &stateRunner.recordingRunner},
	)
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	config := testConfig()
	config.StartTimeout = 20 * time.Millisecond
	manager, _ := NewManager(backend, confirmer, config)
	target := targetFor(PlatformLinux, ServiceSSH)
	result, err := manager.EnsureRunning(
		context.Background(),
		confirmedRequest(t, confirmer, target),
	)
	var serviceErr *Error
	if !errors.As(err, &serviceErr) ||
		serviceErr.Code != CodeTimeout ||
		serviceErr.RollbackCode != CodeManualCleanupRequired ||
		result.Code != OutcomeManualCleanup ||
		!result.MayRemainRunning {
		t.Fatalf("result=%+v error=%#v", result, err)
	}
	if stateRunner.running || !stateRunner.enabled {
		t.Fatalf("timeout state running=%t enabled=%t", stateRunner.running, stateRunner.enabled)
	}
}

func TestCLIStartFailureWithProvenNoChangeIsOrdinaryFailure(t *testing.T) {
	stateRunner := newLinuxServiceRunner("ssh.service")
	stateRunner.enabled = true
	stateRunner.startErr = errors.New("start failed")
	backend := newSystemBackend(
		PlatformLinux,
		detectorOnlyRunner{commandRunner: &stateRunner.recordingRunner},
	)
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	manager, _ := NewManager(backend, confirmer, testConfig())
	target := targetFor(PlatformLinux, ServiceSSH)
	result, err := manager.EnsureRunning(
		context.Background(),
		confirmedRequest(t, confirmer, target),
	)
	var serviceErr *Error
	if !errors.As(err, &serviceErr) ||
		serviceErr.Code != CodeStartFailed ||
		serviceErr.RollbackCode != "" ||
		result.Code != "" ||
		result.MayRemainRunning {
		t.Fatalf("result=%+v error=%#v", result, err)
	}
	if stateRunner.running || !stateRunner.enabled {
		t.Fatalf("unchanged state running=%t enabled=%t", stateRunner.running, stateRunner.enabled)
	}
}

func TestCLIVerifyFailureRequiresManualCleanupWithoutStop(t *testing.T) {
	stateRunner := newLinuxServiceRunner("ssh.service")
	stateRunner.noListener = true
	backend := newSystemBackend(
		PlatformLinux,
		detectorOnlyRunner{commandRunner: &stateRunner.recordingRunner},
	)
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	manager, _ := NewManager(backend, confirmer, testConfig())
	target := targetFor(PlatformLinux, ServiceSSH)
	result, err := manager.EnsureRunning(
		context.Background(),
		confirmedRequest(t, confirmer, target),
	)
	var serviceErr *Error
	if !errors.As(err, &serviceErr) ||
		serviceErr.Code != CodeVerifyFailed ||
		serviceErr.RollbackCode != CodeManualCleanupRequired ||
		result.Code != OutcomeManualCleanup ||
		!result.MayRemainRunning {
		t.Fatalf("result=%+v error=%#v", result, err)
	}
	if !stateRunner.running {
		t.Fatal("unowned CLI instance was stopped")
	}
	for _, call := range stateRunner.snapshot() {
		if len(call.arguments) > 0 && call.arguments[0] == "stop" {
			t.Fatalf("verify failure issued unsafe stop: %+v", call)
		}
	}
}

func TestSystemBackendExternalRestartConflicts(t *testing.T) {
	runner := newLinuxServiceRunner("ssh.service")
	backend := newSystemBackend(PlatformLinux, runner)
	target := targetFor(PlatformLinux, ServiceSSH)
	before, err := backend.Capture(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
	if err != nil {
		t.Fatal(err)
	}
	runner.recordingRunner.mu.Lock()
	runner.pid++
	runner.generation++
	runner.recordingRunner.mu.Unlock()
	if err := backend.Rollback(context.Background(), target, before, receipt); !errors.Is(err, ErrRollbackConflict) {
		t.Fatalf("external restart error = %v", err)
	}
	if !runner.running {
		t.Fatal("conflicting external service was stopped")
	}
	for _, call := range runner.snapshot() {
		if equalArguments(call.arguments, "stop", "ssh.service") {
			t.Fatal("rollback issued stop after revision conflict")
		}
	}
}

func TestWindowsPIDReuseWithNewCreationTimeConflicts(t *testing.T) {
	runner := newWindowsServiceRunner("sshd")
	backend := newSystemBackend(PlatformWindows, runner)
	target := targetFor(PlatformWindows, ServiceSSH)
	before, err := backend.Capture(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
	if err != nil {
		t.Fatal(err)
	}
	runner.recordingRunner.mu.Lock()
	originalPID := runner.pid
	runner.generation++
	runner.recordingRunner.mu.Unlock()
	if err := backend.Rollback(context.Background(), target, before, receipt); !errors.Is(err, ErrRollbackConflict) {
		t.Fatalf("PID reuse rollback error = %v", err)
	}
	if !runner.running || runner.pid != originalPID {
		t.Fatal("PID-reused external process was stopped")
	}
}

func TestAtomicStartDoesNotClaimConcurrentExternalInstance(t *testing.T) {
	runner := newLinuxServiceRunner("ssh.service")
	startEntered := make(chan struct{})
	startGate := make(chan struct{})
	runner.startEntered = startEntered
	runner.startGate = startGate
	backend := newSystemBackend(PlatformLinux, runner)
	target := targetFor(PlatformLinux, ServiceSSH)
	before, err := backend.Capture(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	type startResult struct {
		receipt ChangeReceipt
		err     error
	}
	done := make(chan startResult, 1)
	go func() {
		receipt, startErr := backend.Start(
			context.Background(),
			target,
			backendPermit(target, before),
		)
		done <- startResult{receipt: receipt, err: startErr}
	}()
	<-startEntered
	runner.recordingRunner.mu.Lock()
	runner.running = true
	runner.enabled = true
	runner.pid = 999
	runner.generation = 42
	runner.recordingRunner.mu.Unlock()
	close(startGate)
	result := <-done
	if !errors.Is(result.err, ErrRollbackConflict) || result.receipt.Changed() {
		t.Fatalf("receipt=%+v error=%v", result.receipt, result.err)
	}
	if !runner.running || runner.pid != 999 {
		t.Fatal("external instance was changed")
	}
}

func TestConditionalRollbackRechecksInsideAtomicOperation(t *testing.T) {
	runner := newLinuxServiceRunner("ssh.service")
	backend := newSystemBackend(PlatformLinux, runner)
	target := targetFor(PlatformLinux, ServiceSSH)
	before, err := backend.Capture(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	gate := make(chan struct{})
	runner.rollbackEntered = entered
	runner.rollbackGate = gate
	done := make(chan error, 1)
	go func() {
		done <- backend.Rollback(context.Background(), target, before, receipt)
	}()
	<-entered
	runner.recordingRunner.mu.Lock()
	runner.pid = 777
	runner.generation++
	runner.recordingRunner.mu.Unlock()
	close(gate)
	if err := <-done; !errors.Is(err, ErrRollbackConflict) {
		t.Fatalf("rollback race error = %v", err)
	}
	if !runner.running || runner.pid != 777 {
		t.Fatal("atomic rollback stopped external generation")
	}
}

func TestSystemBackendRollbackPreservesOriginalEnablement(t *testing.T) {
	runner := newLinuxServiceRunner("ssh.service")
	runner.enabled = true
	backend := newSystemBackend(PlatformLinux, runner)
	target := targetFor(PlatformLinux, ServiceSSH)
	before, err := backend.Capture(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Rollback(context.Background(), target, before, receipt); err != nil {
		t.Fatal(err)
	}
	if runner.running || !runner.enabled {
		t.Fatalf("rollback running=%t enabled=%t", runner.running, runner.enabled)
	}
	for _, call := range runner.snapshot() {
		if len(call.arguments) > 0 &&
			(call.arguments[0] == "enable" || call.arguments[0] == "disable") {
			t.Fatalf("rollback changed original enablement: %+v", call)
		}
	}
}

func TestSystemBackendEnableOnlyFailureReturnsRollbackReceipt(t *testing.T) {
	runner := newLinuxServiceRunner("ssh.service")
	runner.startErr = errors.New("start rejected")
	backend := newSystemBackend(PlatformLinux, runner)
	target := targetFor(PlatformLinux, ServiceSSH)
	before, err := backend.Capture(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backend.Start(context.Background(), target, backendPermit(target, before))
	if err == nil || !receipt.Changed() {
		t.Fatalf("receipt=%+v error=%v", receipt, err)
	}
	if err := backend.Rollback(context.Background(), target, before, receipt); err != nil {
		t.Fatal(err)
	}
	if runner.running || runner.enabled {
		t.Fatalf("partial enable was not restored: running=%t enabled=%t", runner.running, runner.enabled)
	}
}

func TestAtomicStartErrorAfterRunningIsRolledBack(t *testing.T) {
	runner := newLinuxServiceRunner("ssh.service")
	runner.startErr = errors.New("native start completion error")
	backend := newSystemBackend(PlatformLinux, runner)
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	manager, err := NewManager(backend, confirmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	target := targetFor(PlatformLinux, ServiceSSH)
	result, err := manager.EnsureRunning(
		context.Background(),
		confirmedRequest(t, confirmer, target),
	)
	if !IsCode(err, CodeStartFailed) ||
		result.Code != OutcomeRolledBack ||
		!result.Rollback {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if runner.running || runner.enabled {
		t.Fatal("owned failed start was left running")
	}
}

func TestSystemBackendNeverStopsOriginallyRunningService(t *testing.T) {
	runner := newLinuxServiceRunner("ssh.service")
	runner.running = true
	runner.enabled = true
	runner.pid = 404
	runner.generation = 12
	backend := newSystemBackend(PlatformLinux, runner)
	target := targetFor(PlatformLinux, ServiceSSH)
	clk := &fakeClock{now: time.Unix(100, 0)}
	confirmer := testConfirmer(t, &fakePresence{}, clk)
	manager, err := NewManager(backend, confirmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.EnsureRunning(context.Background(), confirmedRequest(t, confirmer, target))
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != OutcomeAlreadyRunning || !runner.running {
		t.Fatalf("result=%+v running=%t", result, runner.running)
	}
	for _, call := range runner.snapshot() {
		if len(call.arguments) > 0 &&
			(call.arguments[0] == "stop" || call.arguments[0] == "disable") {
			t.Fatalf("original service was mutated: %+v", call)
		}
	}
}
