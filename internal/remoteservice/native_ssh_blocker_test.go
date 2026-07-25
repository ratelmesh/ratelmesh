package remoteservice

import (
	"context"
	"runtime"
	"testing"
)

// Even a runner which can manufacture an atomic service-transition receipt
// cannot make the global SSH listener Mesh-only. Production SSH remains
// detect-only until firewall-generation attestation and an exact Mesh-bound
// native service are part of the same transaction.
func TestProductionSSHRejectsAtomicGlobalServiceRunner(t *testing.T) {
	tests := []struct {
		name     string
		platform Platform
		runner   func() (commandRunner, func() ServiceState)
	}{
		{
			name:     "linux",
			platform: PlatformLinux,
			runner: func() (commandRunner, func() ServiceState) {
				state := newLinuxServiceRunner("ssh.service")
				return state, func() ServiceState {
					state.recordingRunner.mu.Lock()
					defer state.recordingRunner.mu.Unlock()
					return ServiceState{Running: state.running, Enabled: state.enabled}
				}
			},
		},
		{
			name:     "macos",
			platform: PlatformMacOS,
			runner: func() (commandRunner, func() ServiceState) {
				state := newMacServiceRunner("com.openssh.sshd")
				return state, func() ServiceState {
					state.recordingRunner.mu.Lock()
					defer state.recordingRunner.mu.Unlock()
					return ServiceState{Running: state.running, Enabled: state.enabled}
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner, current := test.runner()
			backend := newSystemBackend(test.platform, runner)
			if backend.atomic == nil {
				t.Fatal("hostile fixture must exercise an atomic-capable runner")
			}
			backend.productionDetectOnly = true
			target := targetFor(test.platform, ServiceSSH)
			before := current()
			receipt, err := backend.Start(
				context.Background(),
				target,
				backendPermit(target, before),
			)
			if !IsCode(err, CodeUnsupportedTarget) {
				t.Fatalf("global SSH mutation was not rejected: %v", err)
			}
			if receipt.Changed() {
				t.Fatalf("rejected mutation returned a change receipt: %+v", receipt)
			}
			if after := current(); after != before {
				t.Fatalf("rejected mutation changed service: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestProductionConstructorNeverInstallsSyntheticAtomicOwnership(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
	default:
		t.Skip("unsupported production platform")
	}
	backend, err := NewSystemBackend()
	if err != nil {
		t.Fatal(err)
	}
	if !backend.productionDetectOnly {
		t.Fatal("production backend unexpectedly permits unreviewed mutation")
	}
	if backend.atomic != nil {
		t.Fatal("command runner was treated as native atomic ownership")
	}
}
