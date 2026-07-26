package filetransfer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

type testKeys struct {
	authorityPublic  ed25519.PublicKey
	authorityPrivate ed25519.PrivateKey
	sender           *LocalDevice
	recipient        *LocalDevice
	senderPeer       Peer
	recipientPeer    Peer
	now              time.Time
}

func newTestKeys(t *testing.T) testKeys {
	t.Helper()
	apub, apriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spub, spriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rpub, rpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sx, err := GenerateExchangeIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rx, err := GenerateExchangeIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	makeBinding := func(device string, signing ed25519.PublicKey, exchange []byte) DeviceKeyBinding {
		var b DeviceKeyBinding
		b.Version, b.TenantID, b.DeviceID, b.KeyVersion = ProtocolVersion, "tenant-a", device, 7
		b.NotBeforeUnix, b.NotAfterUnix = now.Add(-time.Hour).Unix(), now.Add(24*time.Hour).Unix()
		copy(b.SigningPublic[:], signing)
		copy(b.ExchangePublic[:], exchange)
		signed, signErr := SignDeviceKeyBinding(b, apriv)
		if signErr != nil {
			t.Fatal(signErr)
		}
		return signed
	}
	sb := makeBinding("sender", spub, sx.Public)
	rb := makeBinding("recipient", rpub, rx.Public)
	sender, err := OpenLocalDevice(sb, spriv, sx.Private, apub, "tenant-a", "sender", now, 7)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := OpenLocalDevice(rb, rpriv, rx.Private, apub, "tenant-a", "recipient", now, 7)
	if err != nil {
		t.Fatal(err)
	}
	senderPeer, err := VerifyDeviceBinding(sb, apub, "tenant-a", "sender", now, 7)
	if err != nil {
		t.Fatal(err)
	}
	recipientPeer, err := VerifyDeviceBinding(rb, apub, "tenant-a", "recipient", now, 7)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.Close)
	t.Cleanup(recipient.Close)
	return testKeys{
		authorityPublic: apub, authorityPrivate: apriv, sender: sender, recipient: recipient,
		senderPeer: senderPeer, recipientPeer: recipientPeer, now: now,
	}
}

func newTransfer(t *testing.T, data []byte, chunkSize uint32) (*Sender, Offer, testKeys, string) {
	t.Helper()
	keys := newTestKeys(t)
	src := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewSender(context.Background(), src, keys.sender, keys.recipientPeer, keys.now.Add(time.Hour), chunkSize, Limits{MaxFileSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, s.Offer(), keys, src
}

func TestRoundTripArbitraryOrderAndAtomicFinalize(t *testing.T) {
	data := bytes.Repeat([]byte("ratelmesh-transfer-"), 500)
	s, offer, keys, _ := newTransfer(t, data, 257)
	state := t.TempDir()
	r, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{MaxFileSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	count := s.Manifest().ChunkCount()
	for i := count; i > 0; i-- {
		c, err := s.EncryptChunk(context.Background(), i-1)
		if err != nil {
			t.Fatal(err)
		}
		wire := c.MarshalBinary()
		parsed, err := ParseEncryptedChunk(wire, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.ReceiveChunk(context.Background(), parsed); err != nil {
			t.Fatal(err)
		}
		if err := r.ReceiveChunk(context.Background(), parsed); err != nil {
			t.Fatalf("identical duplicate: %v", err)
		}
	}
	if !r.Complete() {
		t.Fatal("receiver not complete")
	}
	missing, err := s.MissingChunks(r.ResumeToken())
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing=%v err=%v", missing, err)
	}
	destDir := t.TempDir()
	root, err := os.OpenRoot(destDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := r.Finalize(context.Background(), root, "received.bin"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, "received.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("final content differs")
	}
	if err := r.Finalize(context.Background(), root, "again.bin"); !errors.Is(err, ErrAlreadyFinalized) {
		t.Fatalf("second finalize = %v", err)
	}
}

func TestRestartResumeRevalidatesLocalBytes(t *testing.T) {
	data := bytes.Repeat([]byte("resume"), 1000)
	s, offer, keys, _ := newTransfer(t, data, 300)
	state := t.TempDir()
	r, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []uint32{0, 3, 7} {
		c, encErr := s.EncryptChunk(context.Background(), i)
		if encErr != nil {
			t.Fatal(encErr)
		}
		if err := r.ReceiveChunk(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	partPath := r.partPath
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// Authenticated resume metadata never makes unverified local bytes trusted.
	f, err := os.OpenFile(partPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("corrupt"), 0); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	r2, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	missing, err := s.MissingChunks(r2.ResumeToken())
	if err != nil {
		t.Fatal(err)
	}
	if !contains(missing, 0) || contains(missing, 3) || contains(missing, 7) {
		t.Fatalf("unexpected missing set %v", missing)
	}
	for _, i := range missing {
		c, encErr := s.EncryptChunk(context.Background(), i)
		if encErr != nil {
			t.Fatal(encErr)
		}
		if err := r2.ReceiveChunk(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	if !r2.Complete() {
		t.Fatal("resume did not complete")
	}
}

func TestTamperWrongPeersAndWrongKeysRejected(t *testing.T) {
	s, offer, keys, _ := newTransfer(t, []byte("secret payload"), 4)
	badOffer := offer
	badOffer.Ciphertext = append([]byte(nil), offer.Ciphertext...)
	badOffer.Ciphertext[0] ^= 1
	if _, err := OpenReceiver(context.Background(), t.TempDir(), badOffer, keys.recipient, keys.senderPeer, keys.now, Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered offer = %v", err)
	}
	other := newTestKeys(t)
	if _, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, other.senderPeer, keys.now, Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong sender = %v", err)
	}
	if _, err := OpenReceiver(context.Background(), t.TempDir(), offer, other.recipient, keys.senderPeer, keys.now, Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong exchange key = %v", err)
	}
	r, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c, err := s.EncryptChunk(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	c.Ciphertext[0] ^= 1
	if err := r.ReceiveChunk(context.Background(), c); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered chunk = %v", err)
	}
}

func TestTruncationLimitsAndManifestTamperingRejected(t *testing.T) {
	_, offer, keys, _ := newTransfer(t, []byte("123456789"), 3)
	wire, err := offer.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(wire); i++ {
		if _, err := ParseOffer(wire[:i], Limits{}); err == nil {
			t.Fatalf("accepted offer prefix length %d", i)
		}
	}
	parsed, err := ParseOffer(wire, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, offer) {
		t.Fatal("offer round trip differs")
	}
	if _, err := ParseOffer(wire, Limits{MaxOfferBytes: 32}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("offer limit = %v", err)
	}
	tampered := offer
	tampered.Signature[0] ^= 1
	if _, err := OpenReceiver(context.Background(), t.TempDir(), tampered, keys.recipient, keys.senderPeer, keys.now, Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("manifest/envelope signature tamper = %v", err)
	}
}

func TestConflictingReplayAndResumeForgeryRejected(t *testing.T) {
	s, offer, keys, _ := newTransfer(t, bytes.Repeat([]byte("x"), 100), 25)
	r, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c, err := s.EncryptChunk(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ReceiveChunk(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if _, err := r.part.WriteAt([]byte("not-identical-local-content"), 0); err != nil {
		t.Fatal(err)
	}
	if err := r.ReceiveChunk(context.Background(), c); !errors.Is(err, ErrConflictingChunk) {
		t.Fatalf("conflicting replay = %v", err)
	}
	token := r.ResumeToken()
	token.Completed[0] ^= 1
	if _, err := s.MissingChunks(token); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("forged resume = %v", err)
	}
}

func TestCancellationLeavesResumableState(t *testing.T) {
	s, offer, keys, _ := newTransfer(t, bytes.Repeat([]byte("cancel"), 100), 50)
	state := t.TempDir()
	r, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.EncryptChunk(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.ReceiveChunk(ctx, c); !errors.Is(err, context.Canceled) {
		t.Fatalf("receive cancel = %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r2, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatalf("resume after cancel: %v", err)
	}
	defer r2.Close()
}

func TestFinalizeRejectsTraversalSymlinkAndOverwrite(t *testing.T) {
	s, offer, keys, _ := newTransfer(t, []byte("finished"), 64)
	r, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c, _ := s.EncryptChunk(context.Background(), 0)
	if err := r.ReceiveChunk(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"../escape", "/tmp/escape", `..\escape`, "CON"} {
		if err := r.Finalize(context.Background(), root, name); err == nil {
			t.Fatalf("accepted unsafe destination %q", name)
		}
	}
	if err := os.WriteFile(filepath.Join(dest, "exists"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.Finalize(context.Background(), root, "exists"); err == nil {
		t.Fatal("overwrote existing destination")
	}
	got, _ := os.ReadFile(filepath.Join(dest, "exists"))
	if string(got) != "keep" {
		t.Fatal("existing destination changed")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dest, "outside")); err != nil {
		t.Fatal(err)
	}
	if err := r.Finalize(context.Background(), root, "outside/file"); err == nil {
		t.Fatal("accepted path through symlink")
	}
}

func TestSourceMutationRejected(t *testing.T) {
	data := bytes.Repeat([]byte("a"), 100)
	s, _, _, src := newTransfer(t, data, 50)
	if err := os.WriteFile(src, bytes.Repeat([]byte("b"), 100), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EncryptChunk(context.Background(), 0); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("mutated source = %v", err)
	}
}

func TestTenantAuthorityBindingRejectsCoordinatorSubstitution(t *testing.T) {
	keys := newTestKeys(t)
	_, attackerSigning, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerX, err := GenerateExchangeIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var substituted DeviceKeyBinding
	substituted.Version = ProtocolVersion
	substituted.TenantID, substituted.DeviceID = "tenant-a", "recipient"
	substituted.KeyVersion = 8
	substituted.NotBeforeUnix, substituted.NotAfterUnix = keys.now.Add(-time.Hour).Unix(), keys.now.Add(time.Hour).Unix()
	copy(substituted.SigningPublic[:], attackerSigning.Public().(ed25519.PublicKey))
	copy(substituted.ExchangePublic[:], attackerX.Public)
	// A malicious Coordinator cannot mint the offline Tenant authority signature.
	if _, err := VerifyDeviceBinding(substituted, keys.authorityPublic, "tenant-a", "recipient", keys.now, 7); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unsigned substituted key = %v", err)
	}
	substituted, err = SignDeviceKeyBinding(substituted, keys.authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	unknownAuthority, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDeviceBinding(substituted, unknownAuthority, "tenant-a", "recipient", keys.now, 7); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unknown authority = %v", err)
	}
	if _, err := VerifyDeviceBinding(substituted, keys.authorityPublic, "tenant-b", "recipient", keys.now, 7); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("cross-tenant substitution = %v", err)
	}
}

func TestBindingRotationFloorRejectsDowngrade(t *testing.T) {
	keys := newTestKeys(t)
	old := DeviceKeyBinding{
		Version:       ProtocolVersion,
		TenantID:      "tenant-a",
		DeviceID:      "recipient",
		KeyVersion:    6,
		NotBeforeUnix: keys.now.Add(-time.Hour).Unix(),
		NotAfterUnix:  keys.now.Add(time.Hour).Unix(),
	}
	old.SigningPublic = keys.recipient.peer.signingPublic
	old.ExchangePublic = keys.recipient.peer.exchangePublic
	signed, err := SignDeviceKeyBinding(old, keys.authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDeviceBinding(signed, keys.authorityPublic, "tenant-a", "recipient", keys.now, 7); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("accepted downgraded binding = %v", err)
	}
	if _, err := VerifyDeviceBinding(signed, keys.authorityPublic, "tenant-a", "recipient", keys.now, 6); err != nil {
		t.Fatalf("valid rotation version rejected: %v", err)
	}
}

func TestSenderImpersonationAndExpiredOfferRejected(t *testing.T) {
	_, offer, keys, _ := newTransfer(t, []byte("identity-bound"), 4)
	attacker := newTestKeys(t)
	if _, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, attacker.senderPeer, keys.now, Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("sender impersonation = %v", err)
	}
	if _, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, time.Unix(offer.ExpiresAtUnix, 0), Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expired offer = %v", err)
	}
	if _, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, keys.now.Add(-2*time.Hour), Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("offer accepted before device binding validity = %v", err)
	}
	tampered := offer
	tampered.ManifestCommitment[0] ^= 1
	if _, err := OpenReceiver(context.Background(), t.TempDir(), tampered, keys.recipient, keys.senderPeer, keys.now, Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("manifest commitment substitution = %v", err)
	}
}

func TestExpiredOfferCannotReviveAfterClockRollback(t *testing.T) {
	_, offer, keys, _ := newTransfer(t, []byte("clock-floor"), 4)
	state := t.TempDir()
	expiredAt := time.Unix(offer.ExpiresAtUnix, 0)

	if _, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, expiredAt, Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expired offer = %v", err)
	}
	if _, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expired offer revived after clock rollback: %v", err)
	}
}

func TestTrustedTransferTimeSerializesConcurrentAdvances(t *testing.T) {
	state := t.TempDir()
	base := time.Unix(1_800_000_000, 0)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := trustedTransferTime(state, base.Add(time.Duration(i)*time.Second), 1)
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
	got, err := trustedTransferTime(state, base.Add(-time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	want := base.Add(31 * time.Second).UTC()
	if !got.Equal(want) {
		t.Fatalf("trusted time = %v, want %v", got, want)
	}
}

func TestTrustedTransferTimeRecoversOnlyOnHigherBindingVersion(t *testing.T) {
	state := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	future := now.Add(20 * 365 * 24 * time.Hour)
	if got, err := trustedTransferTime(state, future, 4); err != nil || !got.Equal(future.UTC()) {
		t.Fatalf("record future observation = %v, %v", got, err)
	}
	if got, err := trustedTransferTime(state, now, 4); err != nil || !got.Equal(future.UTC()) {
		t.Fatalf("same version rolled time back = %v, %v", got, err)
	}
	if got, err := trustedTransferTime(state, now, 5); err != nil || !got.Equal(now.UTC()) {
		t.Fatalf("higher signed binding did not recover = %v, %v", got, err)
	}
	if _, err := trustedTransferTime(state, now, 4); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("older binding version recovered floor: %v", err)
	}
}

func TestTrustedTransferTimeMigratesLegacyFloorWithoutReset(t *testing.T) {
	state := t.TempDir()
	future := time.Unix(2_000_000_000, 0)
	legacy := encodeExpiry(future.Unix())
	if err := os.WriteFile(filepath.Join(state, trustedTimeState), legacy[:], 0600); err != nil {
		t.Fatal(err)
	}
	got, err := trustedTransferTime(state, future.Add(-time.Hour), 7)
	if err != nil || !got.Equal(future.UTC()) {
		t.Fatalf("legacy migration reset floor = %v, %v", got, err)
	}
	persisted, err := os.ReadFile(filepath.Join(state, trustedTimeState))
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted) != trustedTimeBytes || binary.BigEndian.Uint64(persisted[8:]) != 7 {
		t.Fatalf("legacy state was not bound to current key version: %x", persisted)
	}
}

func TestChunkNonceUniquenessAndIndexBinding(t *testing.T) {
	s, offer, keys, _ := newTransfer(t, bytes.Repeat([]byte("nonce"), 20), 25)
	seen := make(map[[12]byte]bool)
	for i := uint32(0); i < s.Manifest().ChunkCount(); i++ {
		n := chunkNonce(s.contentKey, offer.TransferID, i)
		if seen[n] {
			t.Fatalf("nonce reused at chunk %d", i)
		}
		seen[n] = true
		if got := binary.BigEndian.Uint32(n[8:]); got != i {
			t.Fatalf("nonce does not injectively encode index: got %d want %d", got, i)
		}
	}
	first := chunkNonce(s.contentKey, offer.TransferID, 0)
	lastIndex := DefaultLimits().MaxChunks - 1
	last := chunkNonce(s.contentKey, offer.TransferID, lastIndex)
	if first == last || binary.BigEndian.Uint32(last[8:]) != lastIndex {
		t.Fatalf("nonce boundary is not injective: first=%x last=%x", first, last)
	}
	r, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c, err := s.EncryptChunk(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	c.Index = 1
	if err := r.ReceiveChunk(context.Background(), c); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("chunk index substitution = %v", err)
	}
}

func TestCrossTenantTransferRequiresExplicitCapability(t *testing.T) {
	keys := newTestKeys(t)
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic := otherPrivate.Public().(ed25519.PublicKey)
	otherX, err := GenerateExchangeIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var binding DeviceKeyBinding
	binding.Version, binding.TenantID, binding.DeviceID = ProtocolVersion, "tenant-b", "other"
	binding.KeyVersion = 1
	binding.NotBeforeUnix, binding.NotAfterUnix = keys.now.Add(-time.Hour).Unix(), keys.now.Add(time.Hour).Unix()
	copy(binding.SigningPublic[:], otherPublic)
	copy(binding.ExchangePublic[:], otherX.Public)
	binding, err = SignDeviceKeyBinding(binding, keys.authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	otherPeer, err := VerifyDeviceBinding(binding, keys.authorityPublic, "tenant-b", "other", keys.now, 1)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "cross-tenant.bin")
	if err := os.WriteFile(src, []byte("denied"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSender(context.Background(), src, keys.sender, otherPeer, keys.now.Add(time.Minute), 64, Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("cross-tenant sender = %v", err)
	}
	_, offer, _, _ := newTransfer(t, []byte("denied"), 64)
	if _, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, otherPeer, keys.now, Limits{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("cross-tenant receiver = %v", err)
	}
}

func TestDirectOfferSizeLimitCannotBeBypassed(t *testing.T) {
	_, offer, keys, _ := newTransfer(t, []byte("bounded"), 4)
	offer.Ciphertext = make([]byte, 2048)
	if _, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, keys.now, Limits{MaxOfferBytes: 1024}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized direct Offer = %v", err)
	}
}

func TestStateSymlinksRejectedWithoutTouchingTarget(t *testing.T) {
	_, offer, keys, _ := newTransfer(t, []byte("state-safe"), 4)
	parent := t.TempDir()
	actual := t.TempDir()
	rootLink := filepath.Join(parent, "state-link")
	if err := os.Symlink(actual, rootLink); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReceiver(context.Background(), rootLink, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}); err == nil {
		t.Fatal("accepted symlink state root")
	}

	state := filepath.Join(parent, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	transferDir := filepath.Join(state, hex.EncodeToString(offer.TransferID[:]))
	if err := os.Mkdir(transferDir, 0700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(parent, "victim")
	if err := os.WriteFile(victim, []byte("do-not-touch"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(transferDir, "content.part")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{}); err == nil {
		t.Fatal("accepted symlink partial file")
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "do-not-touch" {
		t.Fatalf("victim changed: %q err=%v", got, err)
	}
}

func TestFinalizeRecoversVerifiedStalePublish(t *testing.T) {
	data := []byte("recover-after-link-crash")
	s, offer, keys, _ := newTransfer(t, data, 64)
	r, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c, err := s.EncryptChunk(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ReceiveChunk(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	tmpName := ".ratelmesh-" + hex.EncodeToString(offer.TransferID[:]) + ".partial"
	if err := os.WriteFile(filepath.Join(dest, tmpName), data, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := r.Finalize(context.Background(), root, "recovered.bin"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "recovered.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("recovered content = %q err=%v", got, err)
	}
}

func TestFinalizeRestartReplacesInvalidReservedPartial(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, path string, data []byte) string
	}{
		{
			name: "truncated crash residue",
			setup: func(t *testing.T, path string, data []byte) string {
				t.Helper()
				if err := os.WriteFile(path, data[:len(data)/2], 0600); err != nil {
					t.Fatal(err)
				}
				return ""
			},
		},
		{
			name: "wrong full-size residue",
			setup: func(t *testing.T, path string, data []byte) string {
				t.Helper()
				if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, len(data)), 0600); err != nil {
					t.Fatal(err)
				}
				return ""
			},
		},
		{
			name: "symlink residue",
			setup: func(t *testing.T, path string, _ []byte) string {
				t.Helper()
				victim := filepath.Join(t.TempDir(), "victim")
				if err := os.WriteFile(victim, []byte("do-not-touch"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
				return victim
			},
		},
		{
			name: "empty directory residue",
			setup: func(t *testing.T, path string, _ []byte) string {
				t.Helper()
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				return ""
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Repeat([]byte("crash-recovery-"), 32)
			s, offer, keys, _ := newTransfer(t, data, 128)
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
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}

			// Simulate a new process opening authenticated resume state after
			// the previous process died while copying its destination partial.
			restarted, err := OpenReceiver(context.Background(), state, offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			dest := t.TempDir()
			tmpName := ".ratelmesh-" + hex.EncodeToString(offer.TransferID[:]) + ".partial"
			victim := tc.setup(t, filepath.Join(dest, tmpName), data)
			root, err := os.OpenRoot(dest)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := restarted.Finalize(context.Background(), root, "recovered.bin"); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(dest, "recovered.bin"))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("recovered content mismatch: len=%d err=%v", len(got), err)
			}
			if _, err := os.Lstat(filepath.Join(dest, tmpName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("reserved partial remains: %v", err)
			}
			if victim != "" {
				got, err := os.ReadFile(victim)
				if err != nil || string(got) != "do-not-touch" {
					t.Fatalf("symlink target changed: %q err=%v", got, err)
				}
			}
		})
	}
}

func TestFinalizeCancellationCanRetryInvalidReservedPartial(t *testing.T) {
	data := bytes.Repeat([]byte("cancel-retry-"), 32)
	s, offer, keys, _ := newTransfer(t, data, 128)
	r, err := OpenReceiver(context.Background(), t.TempDir(), offer, keys.recipient, keys.senderPeer, keys.now, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i := uint32(0); i < s.Manifest().ChunkCount(); i++ {
		chunk, err := s.EncryptChunk(context.Background(), i)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.ReceiveChunk(context.Background(), chunk); err != nil {
			t.Fatal(err)
		}
	}
	dest := t.TempDir()
	tmpName := ".ratelmesh-" + hex.EncodeToString(offer.TransferID[:]) + ".partial"
	if err := os.WriteFile(filepath.Join(dest, tmpName), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Finalize(ctx, root, "after-cancel.bin"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled finalize = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "after-cancel.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled finalize published destination: %v", err)
	}
	if err := r.Finalize(context.Background(), root, "after-cancel.bin"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "after-cancel.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("retry content mismatch: len=%d err=%v", len(got), err)
	}
}

func TestLocalDeviceConcurrentCloseIsRaceFree(t *testing.T) {
	keys := newTestKeys(t)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			identity, exchange, _, err := keys.sender.snapshot()
			if err == nil {
				zero(identity.SigningPrivate)
				zero(exchange[:])
			}
		}()
	}
	keys.sender.Close()
	wg.Wait()
	if _, _, _, err := keys.sender.snapshot(); err == nil {
		t.Fatal("closed local device still usable")
	}
}

func contains(v []uint32, want uint32) bool {
	for _, n := range v {
		if n == want {
			return true
		}
	}
	return false
}
