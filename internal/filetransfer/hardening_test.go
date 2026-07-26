package filetransfer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestManifestCommitmentIsUnlinkableAcrossRetransfers(t *testing.T) {
	keys := newTestKeys(t)
	source := filepath.Join(t.TempDir(), "same.bin")
	if err := os.WriteFile(source, bytes.Repeat([]byte("same-content"), 100), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := NewSender(context.Background(), source, keys.sender, keys.recipientPeer, keys.now.Add(time.Hour), 128, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewSender(context.Background(), source, keys.sender, keys.recipientPeer, keys.now.Add(time.Hour), 128, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.Manifest().ContentHash != second.Manifest().ContentHash {
		t.Fatal("test inputs did not produce the same manifest")
	}
	if first.Offer().ManifestCommitment == second.Offer().ManifestCommitment {
		t.Fatal("same file exposed a stable public manifest commitment")
	}
}

func TestTransferLeaseAcrossManagersAndReopen(t *testing.T) {
	_, offer, keys, _ := newTransfer(t, []byte("leased"), 4)
	state := t.TempDir()
	firstManager, err := NewAdmissionManager(DefaultQuota())
	if err != nil {
		t.Fatal(err)
	}
	secondManager, err := NewAdmissionManager(DefaultQuota())
	if err != nil {
		t.Fatal(err)
	}
	first, err := OpenReceiverWithManager(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}, firstManager)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReceiverWithManager(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}, secondManager); !errors.Is(err, ErrTransferBusy) {
		t.Fatalf("second store acquired live transfer lease: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenReceiverWithManager(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}, secondManager)
	if err != nil {
		t.Fatalf("reopen after process-style lease release: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTransferLeaseReleasedAfterProcessCrash(t *testing.T) {
	state := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestTransferLeaseCrashHelper$")
	cmd.Env = append(os.Environ(), "RATELMESH_LEASE_HELPER="+state)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "locked" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("lease helper did not lock: %v", scanner.Err())
	}
	root, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireTransferLease(root); !errors.Is(err, ErrTransferBusy) {
		_ = root.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("parent acquired child lease: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	lease, err := acquireTransferLease(root)
	if err != nil {
		_ = root.Close()
		t.Fatalf("lease remained stale after crash: %v", err)
	}
	if err := lease.close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTransferLeaseCrashHelper(t *testing.T) {
	state := os.Getenv("RATELMESH_LEASE_HELPER")
	if state == "" {
		return
	}
	root, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := acquireTransferLease(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.close()
	defer root.Close()
	if _, err := os.Stdout.WriteString("locked\n"); err != nil {
		t.Fatal(err)
	}
	select {}
}

func TestAdmissionAggregateLimitsAndRelease(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxActiveTransfers = 1
	manager, err := NewAdmissionManager(quota)
	if err != nil {
		t.Fatal(err)
	}
	_, firstOffer, firstKeys, _ := newTransfer(t, []byte("first"), 4)
	_, secondOffer, secondKeys, _ := newTransfer(t, []byte("second"), 4)
	first, err := OpenReceiverWithManager(context.Background(), t.TempDir(), firstOffer, firstKeys.recipient, firstKeys.senderPeer, firstKeys.now, Limits{}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReceiverWithManager(context.Background(), t.TempDir(), secondOffer, secondKeys.recipient, secondKeys.senderPeer, secondKeys.now, Limits{}, manager); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("aggregate active limit bypassed: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenReceiverWithManager(context.Background(), t.TempDir(), secondOffer, secondKeys.recipient, secondKeys.senderPeer, secondKeys.now, Limits{}, manager)
	if err != nil {
		t.Fatalf("admission not released on close: %v", err)
	}
	_ = reopened.Close()
}

func TestCloseRetainsDiskReservationUntilCancel(t *testing.T) {
	_, firstOffer, firstKeys, _ := newTransfer(t, bytes.Repeat([]byte("a"), 1024), 128)
	_, secondOffer, secondKeys, _ := newTransfer(t, bytes.Repeat([]byte("b"), 1024), 128)
	quota := DefaultQuota()
	quota.MaxReservedBytes = 2000
	quota.MaxReservedBytesPerTenant = 2000
	quota.MaxReservedBytesPerDevice = 2000
	manager, err := NewAdmissionManager(quota)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	first, err := OpenReceiverWithManager(context.Background(), state, firstOffer, firstKeys.recipient, firstKeys.senderPeer, firstKeys.now, Limits{}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReceiverWithManager(context.Background(), state, secondOffer, secondKeys.recipient, secondKeys.senderPeer, secondKeys.now, Limits{}, manager); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("Close released persistent disk reservation: %v", err)
	}
	first, err = OpenReceiverWithManager(context.Background(), state, firstOffer, firstKeys.recipient, firstKeys.senderPeer, firstKeys.now, Limits{}, manager)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Cancel(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenReceiverWithManager(context.Background(), state, secondOffer, secondKeys.recipient, secondKeys.senderPeer, secondKeys.now, Limits{}, manager)
	if err != nil {
		t.Fatalf("Cancel did not release disk reservation: %v", err)
	}
	_ = second.Cancel()
}

func TestNewManagerLoadsPersistentReservations(t *testing.T) {
	_, firstOffer, firstKeys, _ := newTransfer(t, bytes.Repeat([]byte("a"), 1024), 128)
	_, secondOffer, secondKeys, _ := newTransfer(t, bytes.Repeat([]byte("b"), 1024), 128)
	quota := DefaultQuota()
	quota.MaxReservedBytes = 2000
	quota.MaxReservedBytesPerTenant = 2000
	quota.MaxReservedBytesPerDevice = 2000
	state := t.TempDir()
	manager1, _ := NewAdmissionManager(quota)
	first, err := OpenReceiverWithManager(context.Background(), state, firstOffer, firstKeys.recipient, firstKeys.senderPeer, firstKeys.now, Limits{}, manager1)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	manager2, _ := NewAdmissionManager(quota)
	if _, err := OpenReceiverWithManager(context.Background(), state, secondOffer, secondKeys.recipient, secondKeys.senderPeer, secondKeys.now, Limits{}, manager2); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("fresh manager ignored persisted reservation ledger: %v", err)
	}
}

func TestAdmissionReservedBytesOverflowSafe(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxReservedBytes = int64(^uint64(0) >> 1)
	quota.MaxReservedBytesPerTenant = quota.MaxReservedBytes
	quota.MaxReservedBytesPerDevice = quota.MaxReservedBytes
	manager, err := NewAdmissionManager(quota)
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.begin("tenant", "device")
	if err != nil {
		t.Fatal(err)
	}
	defer first.closeActive()
	if err := first.claimReservation("first", quota.MaxReservedBytes); err != nil {
		t.Fatal(err)
	}
	defer first.releaseReservation()
	second, err := manager.begin("tenant", "device")
	if err != nil {
		t.Fatal(err)
	}
	defer second.closeActive()
	if err := second.claimReservation("second", 1); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("integer-safe aggregate limit bypassed: %v", err)
	}
}

func TestProtocolV1OfferFailsClosed(t *testing.T) {
	_, offer, _, _ := newTransfer(t, []byte("versioned"), 4)
	wire, err := offer.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wire[4], wire[5] = 0, 1
	if _, err := ParseOffer(wire, Limits{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("legacy offer did not fail closed: %v", err)
	}
}

func TestFinalizeRemovesReceiverDuplicateAndDurabilityRetry(t *testing.T) {
	s, offer, keys, _ := newTransfer(t, []byte("durable-content"), 4)
	state := t.TempDir()
	r, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < s.Manifest().ChunkCount(); i++ {
		chunk, err := s.EncryptChunk(context.Background(), i)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.ReceiveChunk(context.Background(), chunk); err != nil {
			t.Fatal(err)
		}
	}
	destination, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	originalSync := syncDirectory
	failed := false
	syncDirectory = func(root *os.Root) error {
		if !failed {
			failed = true
			return errors.New("injected directory sync failure")
		}
		return originalSync(root)
	}
	err = r.Finalize(context.Background(), destination, "published.bin")
	syncDirectory = originalSync
	if !errors.Is(err, ErrDurability) {
		t.Fatalf("publish did not fail closed on directory sync: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatalf("reopen after published crash point: %v", err)
	}
	defer r.Close()
	if err := r.Finalize(context.Background(), destination, "published.bin"); err != nil {
		t.Fatalf("durability retry failed: %v", err)
	}
	id := filepath.Join(state, filepath.Base(filepath.Dir(r.partPath)))
	if _, err := os.Stat(filepath.Join(id, "content.part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("finalize retained content.part: %v", err)
	}
}

func TestConsumedTombstoneRejectsReplayAndExpires(t *testing.T) {
	s, offer, keys, _ := newTransfer(t, []byte("consumed"), 4)
	state := t.TempDir()
	r, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < s.Manifest().ChunkCount(); i++ {
		chunk, _ := s.EncryptChunk(context.Background(), i)
		if err := r.ReceiveChunk(context.Background(), chunk); err != nil {
			t.Fatal(err)
		}
	}
	destination, _ := os.OpenRoot(t.TempDir())
	defer destination.Close()
	if err := r.Finalize(context.Background(), destination, "done.bin"); err != nil {
		t.Fatal(err)
	}
	transferDir := filepath.Dir(r.partPath)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}); !errors.Is(err, ErrAlreadyCompleted) {
		t.Fatalf("consumed offer replay accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(transferDir, "consumed.state")); err != nil {
		t.Fatalf("consumed tombstone missing: %v", err)
	}
	if count, err := GarbageCollectExpired(state, time.Unix(offer.ExpiresAtUnix, 0)); err != nil || count != 1 {
		t.Fatalf("expired tombstone GC = %d, %v", count, err)
	}
	if _, err := os.Stat(transferDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("GC retained transfer directory: %v", err)
	}
}

func TestCancelAndExpiredGCDestroyStateContent(t *testing.T) {
	_, offer, keys, _ := newTransfer(t, []byte("cancel"), 4)
	state := t.TempDir()
	r, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	transferDir := filepath.Dir(r.partPath)
	if err := r.Cancel(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(transferDir, "content.part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancel retained content: %v", err)
	}

	_, expiringOffer, expiringKeys, _ := newTransfer(t, []byte("expire"), 4)
	expiringState := t.TempDir()
	expiring, err := OpenReceiver(context.Background(), expiringState, expiringOffer, expiringKeys.recipient, expiringKeys.senderPeer, expiringKeys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	expiringDir := filepath.Dir(expiring.partPath)
	if err := expiring.Close(); err != nil {
		t.Fatal(err)
	}
	count, err := GarbageCollectExpired(expiringState, time.Unix(expiringOffer.ExpiresAtUnix, 0))
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expired GC removed %d transfers, want 1", count)
	}
	if _, err := os.Stat(filepath.Join(expiringDir, "content.part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired GC retained content: %v", err)
	}
}

func TestGCContinuesPastPoisonedEntry(t *testing.T) {
	_, poisonOffer, poisonKeys, _ := newTransfer(t, []byte("poison"), 4)
	_, goodOffer, goodKeys, _ := newTransfer(t, []byte("good"), 4)
	state := t.TempDir()
	poison, err := OpenReceiver(context.Background(), state, poisonOffer, poisonKeys.recipient, poisonKeys.senderPeer, poisonKeys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	poisonDir := filepath.Dir(poison.partPath)
	_ = poison.Close()
	good, err := OpenReceiver(context.Background(), state, goodOffer, goodKeys.recipient, goodKeys.senderPeer, goodKeys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	_ = good.Close()
	if err := os.WriteFile(filepath.Join(poisonDir, "expires.at"), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(poisonDir, "unknown-dir"), 0700); err != nil {
		t.Fatal(err)
	}
	old := time.Unix(poisonOffer.ExpiresAtUnix, 0).Add(-DefaultStateRetention - time.Hour)
	if err := os.Chtimes(poisonDir, old, old); err != nil {
		t.Fatal(err)
	}
	count, gcErr := GarbageCollectExpired(state, time.Unix(goodOffer.ExpiresAtUnix, 0))
	if count != 1 {
		t.Fatalf("GC stopped before healthy entry: count=%d err=%v", count, gcErr)
	}
	if gcErr == nil {
		t.Fatal("poisoned entry was not reported")
	}
}

func TestGCRejectsStateRootSymlinkWithoutTouchingTarget(t *testing.T) {
	target := t.TempDir()
	marker := filepath.Join(target, "marker")
	if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := GarbageCollectExpired(link, time.Now()); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("GC accepted reboundable root: %v", err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "keep" {
		t.Fatalf("GC touched symlink target: %q %v", got, err)
	}
}

func TestResumePersistenceUsesPlatformDirectorySync(t *testing.T) {
	s, offer, keys, _ := newTransfer(t, []byte("persist-seam"), 4)
	original := syncDirectory
	var calls int
	syncDirectory = func(root *os.Root) error {
		calls++
		return original(root)
	}
	defer func() { syncDirectory = original }()
	r, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Cancel()
	afterOpen := calls
	if afterOpen == 0 {
		t.Fatal("initial resume persist bypassed platform directory sync")
	}
	chunk, err := s.EncryptChunk(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ReceiveChunk(context.Background(), chunk); err != nil {
		t.Fatal(err)
	}
	if calls <= afterOpen {
		t.Fatal("ReceiveChunk resume persist bypassed platform directory sync")
	}
}

func TestAdmissionReconcilesExternallyRecreatedRoot(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxRetainedTransfers = 2
	manager, err := NewAdmissionManager(quota)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	state := filepath.Join(base, "state")
	for i := 0; i < 70; i++ {
		_, offer, keys, _ := newTransfer(t, []byte{byte(i)}, 1)
		r, err := OpenReceiverWithManager(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}, manager)
		if err != nil {
			t.Fatalf("iteration %d retained stale root state: %v", i, err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(state); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdmissionConcurrentReconcile(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxActiveTransfers = 16
	quota.MaxActivePerTenant = 16
	quota.MaxActivePerDevice = 16
	quota.MaxRetainedTransfers = 32
	manager, _ := NewAdmissionManager(quota)
	base := t.TempDir()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		_, offer, keys, _ := newTransfer(t, []byte{byte(i)}, 1)
		state := filepath.Join(base, fmt.Sprintf("state-%d", i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := OpenReceiverWithManager(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}, manager)
			if err == nil {
				err = r.Cancel()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSharedReservationSurvivesFirstClaimantFailure(t *testing.T) {
	_, offer, keys, _ := newTransfer(t, bytes.Repeat([]byte("q"), 1024), 128)
	_, otherOffer, otherKeys, _ := newTransfer(t, bytes.Repeat([]byte("z"), 1024), 128)
	quota := DefaultQuota()
	quota.MaxReservedBytes = 2000
	quota.MaxReservedBytesPerTenant = 2000
	quota.MaxReservedBytesPerDevice = 2000
	manager, _ := NewAdmissionManager(quota)
	state := t.TempDir()
	if _, err := trustedTransferTime(state, keys.now, keys.recipientPeer.keyVersion); err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(offer.TransferID[:])
	key, err := reservationKey(state, id)
	if err != nil {
		t.Fatal(err)
	}
	original := syncDirectory
	var syncCalls atomic.Int32
	firstSync := make(chan struct{})
	releaseFirst := make(chan struct{})
	syncDirectory = func(root *os.Root) error {
		if syncCalls.Add(1) == 1 {
			close(firstSync)
			<-releaseFirst
			return errors.New("injected first claimant staging sync failure")
		}
		return original(root)
	}
	defer func() { syncDirectory = original }()
	type openResult struct {
		receiver *Receiver
		err      error
	}
	firstResult := make(chan openResult, 1)
	secondResult := make(chan openResult, 1)
	go func() {
		r, err := OpenReceiverWithManager(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}, manager)
		firstResult <- openResult{r, err}
	}()
	<-firstSync
	go func() {
		r, err := OpenReceiverWithManager(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}, manager)
		secondResult <- openResult{r, err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		manager.mu.Lock()
		refs := manager.refs[key]
		manager.mu.Unlock()
		if refs >= 2 {
			break
		}
		if time.Now().After(deadline) {
			close(releaseFirst)
			t.Fatal("second opener never shared reservation")
		}
		time.Sleep(time.Millisecond)
	}
	close(releaseFirst)
	first := <-firstResult
	if first.err == nil {
		if first.receiver != nil {
			_ = first.receiver.Cancel()
		}
		t.Fatal("injected first claimant failure did not fail")
	}
	second := <-secondResult
	if second.err != nil {
		t.Fatalf("second claimant failed after sharing reservation: %v", second.err)
	}
	defer second.receiver.Cancel()
	manager.mu.Lock()
	_, reserved := manager.reservations[key]
	reservedBytes := manager.total.bytes
	manager.mu.Unlock()
	if !reserved || reservedBytes == 0 {
		t.Fatalf("first claimant abort released shared reservation: present=%v bytes=%d", reserved, reservedBytes)
	}
	if _, err := OpenReceiverWithManager(context.Background(), t.TempDir(), otherOffer, otherKeys.recipient, otherKeys.senderPeer, otherKeys.now, Limits{}, manager); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("shared reservation no longer counted against quota: %v", err)
	}
}
