package filetransfer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func makeResidualDir(t *testing.T, state, name string, entries map[string]string, modified time.Time) {
	t.Helper()
	path := filepath.Join(state, name)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	for entry, content := range entries {
		if err := os.WriteFile(filepath.Join(path, entry), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
}

func TestGarbageCollectRecoversExactCrashResiduals(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	old := now.Add(-DefaultStateRetention - time.Hour)
	id := "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name    string
		entries map[string]string
	}{
		{
			name: ".transfer-0123456789abcdef01234567.new",
			entries: map[string]string{
				"expires.at":        "12345678",
				"reservation.state": "metadata",
				"transfer.lock":     "",
			},
		},
		{
			name: ".gc-" + id + "-0123456789abcdef",
			entries: map[string]string{
				"transfer.lock": "",
				"content.part":  "power-loss-restored-content",
				"resume.state":  "power-loss-restored-resume",
			},
		},
		{
			name: ".cancel-" + id + "-fedcba9876543210",
			entries: map[string]string{
				"transfer.lock":     "",
				"reservation.state": "power-loss-restored-reservation",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := t.TempDir()
			makeResidualDir(t, state, test.name, test.entries, old)
			count, err := GarbageCollectExpired(state, now)
			if err != nil || count != 1 {
				t.Fatalf("recover residual: count=%d err=%v", count, err)
			}
			if _, err := os.Lstat(filepath.Join(state, test.name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("residual survived recovery: %v", err)
			}
		})
	}
}

func TestGarbageCollectPreservesFreshOrLeasedStaging(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	name := ".transfer-0123456789abcdef01234567.new"
	t.Run("fresh", func(t *testing.T) {
		state := t.TempDir()
		makeResidualDir(t, state, name, map[string]string{"expires.at": "12345678"}, now)
		count, err := GarbageCollectExpired(state, now)
		if err != nil || count != 0 {
			t.Fatalf("fresh staging classified as garbage: count=%d err=%v", count, err)
		}
		if _, err := os.Stat(filepath.Join(state, name)); err != nil {
			t.Fatalf("fresh staging removed: %v", err)
		}
	})
	t.Run("leased", func(t *testing.T) {
		state := t.TempDir()
		old := now.Add(-DefaultStateRetention - time.Hour)
		makeResidualDir(t, state, name, map[string]string{"expires.at": "12345678"}, old)
		root, err := os.OpenRoot(filepath.Join(state, name))
		if err != nil {
			t.Fatal(err)
		}
		lease, err := acquireTransferLease(root)
		if err != nil {
			t.Fatal(err)
		}
		count, err := GarbageCollectExpired(state, now)
		if err != nil || count != 0 {
			t.Fatalf("leased staging classified as garbage: count=%d err=%v", count, err)
		}
		if err := lease.close(); err != nil {
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		count, err = GarbageCollectExpired(state, now)
		if err != nil || count != 1 {
			t.Fatalf("released orphan was not recovered: count=%d err=%v", count, err)
		}
	})
}

func TestGarbageCollectResidualsFailClosed(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	old := now.Add(-DefaultStateRetention - time.Hour)
	name := ".transfer-0123456789abcdef01234567.new"
	t.Run("unknown content preserves known state", func(t *testing.T) {
		state := t.TempDir()
		makeResidualDir(t, state, name, map[string]string{
			"reservation.state": "must-survive",
			"hostile":           "unknown",
		}, old)
		count, err := GarbageCollectExpired(state, now)
		if count != 0 || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("unknown residual content accepted: count=%d err=%v", count, err)
		}
		got, err := os.ReadFile(filepath.Join(state, name, "reservation.state"))
		if err != nil || string(got) != "must-survive" {
			t.Fatalf("validation partially destroyed state: %q %v", got, err)
		}
	})
	t.Run("unknown quarantine content preserves known state", func(t *testing.T) {
		state := t.TempDir()
		quarantine := ".gc-" +
			"0123456789abcdef0123456789abcdef" +
			"-0123456789abcdef"
		makeResidualDir(t, state, quarantine, map[string]string{
			"content.part": "must-survive-validation",
			"hostile":      "unknown",
		}, old)
		count, err := GarbageCollectExpired(state, now)
		if count != 0 || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("unknown quarantine content accepted: count=%d err=%v", count, err)
		}
		got, err := os.ReadFile(filepath.Join(state, quarantine, "content.part"))
		if err != nil || string(got) != "must-survive-validation" {
			t.Fatalf("quarantine validation partially destroyed state: %q %v", got, err)
		}
	})
	t.Run("symlink directory never follows target", func(t *testing.T) {
		state := t.TempDir()
		target := t.TempDir()
		marker := filepath.Join(target, "marker")
		if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(state, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		count, err := GarbageCollectExpired(state, now)
		if count != 0 || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("residual symlink accepted: count=%d err=%v", count, err)
		}
		if got, err := os.ReadFile(marker); err != nil || string(got) != "keep" {
			t.Fatalf("symlink target touched: %q %v", got, err)
		}
	})
	t.Run("symlink content never follows target", func(t *testing.T) {
		state := t.TempDir()
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(state, name)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(path, "expires.at")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		count, err := GarbageCollectExpired(state, now)
		if count != 0 || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("residual content symlink accepted: count=%d err=%v", count, err)
		}
		if got, err := os.ReadFile(target); err != nil || string(got) != "keep" {
			t.Fatalf("content symlink target touched: %q %v", got, err)
		}
	})
	t.Run("hostile near-match name ignored", func(t *testing.T) {
		state := t.TempDir()
		near := ".transfer-0123456789abcdef0123456g.new"
		makeResidualDir(t, state, near, map[string]string{"marker": "keep"}, old)
		count, err := GarbageCollectExpired(state, now)
		if err != nil || count != 0 {
			t.Fatalf("near-match should be outside GC namespace: count=%d err=%v", count, err)
		}
		if _, err := os.Stat(filepath.Join(state, near, "marker")); err != nil {
			t.Fatalf("near-match content removed: %v", err)
		}
	})
}

func TestGarbageCollectScanIsBounded(t *testing.T) {
	state := t.TempDir()
	for i := 0; i <= maxGCScannedEntries; i++ {
		if err := os.WriteFile(filepath.Join(state, fmt.Sprintf("hostile-%04d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	count, err := GarbageCollectExpired(state, time.Now())
	if count != 0 || !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("unbounded hostile root scan: count=%d err=%v", count, err)
	}
}

func TestGarbageCollectNeverAgeDeletesPossibleResume(t *testing.T) {
	state := t.TempDir()
	now := time.Unix(1_900_000_000, 0)
	id := "0123456789abcdef0123456789abcdef"
	path := filepath.Join(state, id)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "expires.at"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "content.part"), []byte("resume-me"), 0600); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-10 * DefaultStateRetention)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	count, err := GarbageCollectExpired(state, now)
	if count != 0 || err == nil {
		t.Fatalf("malformed possible resume was treated as expired: count=%d err=%v", count, err)
	}
	if got, err := os.ReadFile(filepath.Join(path, "content.part")); err != nil || string(got) != "resume-me" {
		t.Fatalf("possible resume content was changed: %q %v", got, err)
	}
}

func TestGarbageCollectResidualCrashRetry(t *testing.T) {
	state := t.TempDir()
	now := time.Unix(1_900_000_000, 0)
	old := now.Add(-DefaultStateRetention - time.Hour)
	name := ".cancel-" +
		"0123456789abcdef0123456789abcdef" +
		"-0123456789abcdef"
	makeResidualDir(t, state, name, map[string]string{"transfer.lock": ""}, old)
	original := syncDirectory
	var once sync.Once
	syncDirectory = func(root *os.Root) error {
		var injected error
		once.Do(func() { injected = errors.New("injected crash barrier") })
		if injected != nil {
			return injected
		}
		return original(root)
	}
	_, firstErr := GarbageCollectExpired(state, now)
	syncDirectory = original
	if !errors.Is(firstErr, ErrDurability) {
		t.Fatalf("durability failure was not surfaced: %v", firstErr)
	}
	count, err := GarbageCollectExpired(state, now)
	if err != nil || count != 1 {
		t.Fatalf("crash residual was not retryable: count=%d err=%v", count, err)
	}
}

func TestGarbageCollectQuarantinesBeforeDestructiveCleanup(t *testing.T) {
	state := t.TempDir()
	now := time.Unix(1_900_000_000, 0)
	id := "0123456789abcdef0123456789abcdef"
	path := filepath.Join(state, id)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	expiry := encodeExpiry(now.Add(-time.Hour).Unix())
	if err := os.WriteFile(filepath.Join(path, "expires.at"), expiry[:], 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "content.part"), []byte("survive-until-quarantine-durable"), 0600); err != nil {
		t.Fatal(err)
	}

	original := syncDirectory
	defer func() { syncDirectory = original }()
	var once sync.Once
	syncDirectory = func(root *os.Root) error {
		var injected error
		once.Do(func() { injected = errors.New("injected quarantine barrier failure") })
		if injected != nil {
			return injected
		}
		return original(root)
	}
	count, firstErr := GarbageCollectExpired(state, now)
	syncDirectory = original
	if count != 0 || !errors.Is(firstErr, ErrDurability) {
		t.Fatalf("quarantine durability failure not surfaced: count=%d err=%v", count, firstErr)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canonical state survived visible quarantine rename: %v", err)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 1 || residualKind(entries[0].Name()) != residualGC {
		t.Fatalf("expected one recoverable GC quarantine, entries=%v err=%v", entries, err)
	}
	residual := filepath.Join(state, entries[0].Name())
	if got, err := os.ReadFile(filepath.Join(residual, "content.part")); err != nil ||
		string(got) != "survive-until-quarantine-durable" {
		t.Fatalf("state was destroyed before quarantine became durable: %q %v", got, err)
	}
	count, err = GarbageCollectExpired(state, now)
	if err != nil || count != 1 {
		t.Fatalf("durable quarantine was not retryable: count=%d err=%v", count, err)
	}
}

func TestCancelQuarantinesBeforeDestructiveCleanup(t *testing.T) {
	_, offer, keys, _ := newTransfer(t, []byte("cancel-crash"), 4)
	state := t.TempDir()
	r, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}

	original := syncDirectory
	defer func() { syncDirectory = original }()
	var once sync.Once
	syncDirectory = func(root *os.Root) error {
		var injected error
		once.Do(func() { injected = errors.New("injected cancel quarantine barrier failure") })
		if injected != nil {
			return injected
		}
		return original(root)
	}
	cancelErr := r.Cancel()
	syncDirectory = original
	if !errors.Is(cancelErr, ErrDurability) {
		t.Fatalf("cancel quarantine durability failure not surfaced: %v", cancelErr)
	}
	entries, err := os.ReadDir(state)
	var residualName string
	for _, entry := range entries {
		if residualKind(entry.Name()) == residualCancel {
			residualName = entry.Name()
		}
	}
	if err != nil || residualName == "" {
		t.Fatalf("expected one recoverable cancel quarantine, entries=%v err=%v", entries, err)
	}
	residual := filepath.Join(state, residualName)
	if _, err := os.Stat(filepath.Join(residual, "content.part")); err != nil {
		t.Fatalf("cancel destroyed state before quarantine became durable: %v", err)
	}
	count, err := GarbageCollectExpired(state, keys.now)
	if err != nil || count != 1 {
		t.Fatalf("cancel quarantine was not retryable: count=%d err=%v", count, err)
	}
}

func TestRetainedQuotaFairness(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxRetainedTransfers = 4
	quota.MaxRetainedPerTenant = 2
	quota.MaxRetainedPerDevice = 1
	manager, err := NewAdmissionManager(quota)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(tenant, device, key string) error {
		a, err := manager.begin(tenant, device)
		if err != nil {
			return err
		}
		defer a.closeActive()
		return a.claimReservation(key, 1)
	}
	if err := claim("tenant-a", "device-a", "a1"); err != nil {
		t.Fatal(err)
	}
	if err := claim("tenant-a", "device-a", "a2"); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("one device occupied multiple retained slots: %v", err)
	}
	if err := claim("tenant-a", "device-b", "a3"); err != nil {
		t.Fatal(err)
	}
	if err := claim("tenant-a", "device-c", "a4"); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("one tenant occupied beyond its fair share: %v", err)
	}
	if err := claim("tenant-b", "device-a", "b1"); err != nil {
		t.Fatalf("first principal starved another tenant: %v", err)
	}
}

func TestRetainedQuotaConcurrentNeverExceedsPrincipalCap(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxRetainedTransfers = 32
	quota.MaxRetainedPerTenant = 16
	quota.MaxRetainedPerDevice = 3
	quota.MaxActiveTransfers = 32
	quota.MaxActivePerTenant = 32
	quota.MaxActivePerDevice = 32
	manager, err := NewAdmissionManager(quota)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, err := manager.begin("tenant", "device")
			if err == nil {
				_ = a.claimReservation(fmt.Sprintf("key-%d", i), 1)
				a.closeActive()
			}
		}(i)
	}
	wg.Wait()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if got := len(manager.reservations); got != int(quota.MaxRetainedPerDevice) {
		t.Fatalf("principal retained %d slots, want %d", got, quota.MaxRetainedPerDevice)
	}
}

func TestCompletionTransitionNeverOpensRetainedQuotaGap(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxRetainedTransfers = 1
	quota.MaxRetainedPerTenant = 1
	quota.MaxRetainedPerDevice = 1
	manager, err := NewAdmissionManager(quota)
	if err != nil {
		t.Fatal(err)
	}
	current, err := manager.begin("tenant", "device")
	if err != nil {
		t.Fatal(err)
	}
	if err := current.claimReservation("current", 1); err != nil {
		t.Fatal(err)
	}
	current.markCompleted()
	current.closeActive()
	next, err := manager.begin("other-tenant", "other-device")
	if err != nil {
		t.Fatal(err)
	}
	defer next.closeActive()
	if err := next.claimReservation("next", 1); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("reservation-to-completed transition opened a global quota gap: %v", err)
	}
}

func TestRetainedQuotaRestartReconcilePreservesResumeAndFairness(t *testing.T) {
	state := t.TempDir()
	id := "0123456789abcdef0123456789abcdef"
	dir := filepath.Join(state, id)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	reservation, err := encodeReservation("tenant-a", "device-a", 17)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "reservation.state"), reservation, 0600); err != nil {
		t.Fatal(err)
	}
	quota := DefaultQuota()
	quota.MaxRetainedTransfers = 4
	quota.MaxRetainedPerTenant = 2
	quota.MaxRetainedPerDevice = 1
	manager, err := NewAdmissionManager(quota)
	if err != nil {
		t.Fatal(err)
	}
	root, err := openVerifiedStateRoot(state, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.loadPersistent(root, state); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := reservationKey(state, id)
	if err != nil {
		t.Fatal(err)
	}
	resume, err := manager.begin("tenant-a", "device-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := resume.claimReservation(key, 17); err != nil {
		t.Fatalf("restart reconcile blocked the valid existing resume: %v", err)
	}
	resume.closeActive()
	next, err := manager.begin("tenant-a", "device-a")
	if err != nil {
		t.Fatal(err)
	}
	defer next.closeActive()
	if err := next.claimReservation(key+"-new", 1); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("restart reconcile lost principal retained usage: %v", err)
	}
}

func TestCompletedPrincipalPersistsForRestartQuota(t *testing.T) {
	state := t.TempDir()
	id := "fedcba9876543210fedcba9876543210"
	dir := filepath.Join(state, id)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	reservation, err := encodeReservation("tenant-a", "device-a", 99)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "reservation.state"), reservation, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "consumed.state"), []byte("authenticated-elsewhere"), 0600); err != nil {
		t.Fatal(err)
	}
	quota := DefaultQuota()
	quota.MaxRetainedTransfers = 4
	quota.MaxRetainedPerTenant = 2
	quota.MaxRetainedPerDevice = 1
	manager, err := NewAdmissionManager(quota)
	if err != nil {
		t.Fatal(err)
	}
	root, err := openVerifiedStateRoot(state, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.loadPersistent(root, state); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := manager.begin("tenant-a", "device-a")
	if err != nil {
		t.Fatal(err)
	}
	defer next.closeActive()
	if err := next.claimReservation("new", 1); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("completed principal did not consume its retained slot after restart: %v", err)
	}
}
