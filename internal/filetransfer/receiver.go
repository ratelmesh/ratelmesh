package filetransfer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Receiver struct {
	mu           sync.Mutex
	partPath     string
	stateID      string
	stateRoot    *os.Root
	transferRoot *os.Root
	part         *os.File
	lease        *transferLease
	admission    *admission
	manifest     Manifest
	contentKey   []byte
	resumeKey    []byte
	offer        Offer
	completed    []byte
	finalized    bool
	closed       bool
	limits       Limits
}

func OpenReceiver(ctx context.Context, stateDir string, offer Offer, recipient *LocalDevice, expectedSender Peer, now time.Time, limits Limits) (*Receiver, error) {
	return OpenReceiverWithManager(ctx, stateDir, offer, recipient, expectedSender, now, limits, defaultAdmissionManager)
}

// OpenReceiverWithManager admits the transfer against aggregate process,
// tenant, and recipient-device quotas before creating on-disk state.
func OpenReceiverWithManager(ctx context.Context, stateDir string, offer Offer, recipient *LocalDevice, expectedSender Peer, now time.Time, limits Limits, manager *AdmissionManager) (*Receiver, error) {
	limits = limits.normalized()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	identity, _, recipientPeer, err := recipient.snapshot()
	if err != nil {
		return nil, err
	}
	zero(identity.SigningPrivate)
	trustedNow, err := trustedTransferTime(stateDir, now, recipientPeer.keyVersion)
	if err != nil {
		return nil, err
	}
	admit, err := manager.begin(recipientPeer.tenantID, recipientPeer.deviceID)
	if err != nil {
		return nil, err
	}
	opened, err := openOffer(ctx, offer, recipient, expectedSender, trustedNow, limits)
	if err != nil {
		admit.closeActive()
		return nil, err
	}
	reserved := opened.manifest.Size
	overhead := int64(len(encodeManifest(opened.manifest)) + bitmapLen(opened.manifest.ChunkCount()) + resumeTokenFixedSize)
	if reserved > int64(^uint64(0)>>1)-overhead {
		admit.closeActive()
		zero(opened.contentKey)
		return nil, fmt.Errorf("%w: reservation overflow", ErrLimitExceeded)
	}
	reserved += overhead
	fail := true
	reservationPersistent := false
	var stateRoot, transferRoot *os.Root
	var part *os.File
	var lease *transferLease
	var stagingName string
	stagingPublished := false
	defer func() {
		if fail {
			admit.closeActive()
			if !reservationPersistent {
				admit.abortNewReservation()
			}
			zero(opened.contentKey)
			if part != nil {
				_ = part.Close()
			}
			if lease != nil {
				_ = lease.close()
			}
			if transferRoot != nil {
				_ = transferRoot.Close()
			}
			if stateRoot != nil {
				if stagingName != "" && !stagingPublished {
					_ = cleanupStaging(stateRoot, stagingName)
				}
				_ = stateRoot.Close()
			}
		}
	}()
	resumeKey, err := deriveResumeKey(opened.contentKey, offer.TransferID, offer.ManifestCommitment, offer.SenderSigning, offer.RecipientSigning, offer.SenderBinding, offer.RecipientBinding)
	if err != nil {
		return nil, fmt.Errorf("derive resume key: %w", err)
	}
	defer func() {
		if fail {
			zero(resumeKey)
		}
	}()
	stateRoot, err = openVerifiedStateRoot(stateDir, true)
	if err != nil {
		return nil, fmt.Errorf("open transfer state root: %w", err)
	}
	if err := manager.loadPersistent(stateRoot, stateDir); err != nil {
		return nil, fmt.Errorf("load persisted transfer reservations: %w", err)
	}
	if err := stateRoot.Chmod(".", 0700); err != nil {
		return nil, fmt.Errorf("secure transfer state root: %w", err)
	}
	id := hex.EncodeToString(offer.TransferID[:])
	resKey, err := reservationKey(stateDir, id)
	if err != nil {
		return nil, err
	}
	if err := admit.claimReservation(resKey, reserved); err != nil {
		return nil, err
	}
	dir := stateDir + string(os.PathSeparator) + id
	if _, statErr := stateRoot.Lstat(id); errors.Is(statErr, os.ErrNotExist) {
		var suffix [12]byte
		if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
			return nil, fmt.Errorf("generate transfer staging directory: %w", err)
		}
		stage := ".transfer-" + hex.EncodeToString(suffix[:]) + ".new"
		stagingName = stage
		if err := stateRoot.Mkdir(stage, 0700); err != nil {
			return nil, fmt.Errorf("create transfer staging state: %w", err)
		}
		stageRoot, err := stateRoot.OpenRoot(stage)
		if err != nil {
			return nil, fmt.Errorf("open transfer staging state: %w", err)
		}
		// Lease the staging inode before writing metadata. The lease survives the
		// rename to the published transfer name, so crash-recovery GC can never
		// mistake an in-flight staging transaction for an orphan.
		lease, err = acquireTransferLease(stageRoot)
		if err != nil {
			_ = stageRoot.Close()
			return nil, fmt.Errorf("lease transfer staging state: %w", err)
		}
		expiry := encodeExpiry(offer.ExpiresAtUnix)
		reservationBytes, metaErr := encodeReservation(recipientPeer.tenantID, recipientPeer.deviceID, reserved)
		if metaErr == nil {
			metaErr = atomicWriteState(stageRoot, "expires.at", expiry[:])
		}
		if metaErr == nil {
			metaErr = atomicWriteState(stageRoot, "reservation.state", reservationBytes)
		}
		closeErr := stageRoot.Close()
		if metaErr != nil || closeErr != nil {
			return nil, errors.Join(metaErr, closeErr)
		}
		if err := stateRoot.Rename(stage, id); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return nil, fmt.Errorf("publish transfer state: %w", err)
			}
			if err := lease.close(); err != nil {
				return nil, fmt.Errorf("release losing transfer staging lease: %w", err)
			}
			lease = nil
		} else {
			reservationPersistent = true
			stagingPublished = true
		}
	} else if statErr != nil {
		return nil, fmt.Errorf("inspect transfer state: %w", statErr)
	}
	if err := syncRootDir(stateRoot); err != nil {
		return nil, fmt.Errorf("sync transfer state root: %w", err)
	}
	transferRoot, err = openVerifiedChild(stateRoot, id)
	if err != nil {
		return nil, fmt.Errorf("open transfer state: %w", err)
	}
	if !admit.completed {
		reservationData, err := readBoundedRootFile(transferRoot, "reservation.state", 512)
		if err != nil {
			return nil, fmt.Errorf("read transfer reservation: %w", err)
		}
		rec, err := decodeReservation(reservationData)
		if err != nil || rec.tenant != recipientPeer.tenantID || rec.device != recipientPeer.deviceID || rec.bytes != reserved {
			return nil, fmt.Errorf("%w: transfer reservation mismatch", ErrAuthentication)
		}
	}
	reservationPersistent = true
	admit.markReservationPersistent()
	if err := transferRoot.Chmod(".", 0700); err != nil {
		return nil, fmt.Errorf("secure transfer state: %w", err)
	}
	if lease == nil {
		lease, err = acquireTransferLease(transferRoot)
		if err != nil {
			return nil, err
		}
	}
	if err := syncRootDir(transferRoot); err != nil {
		return nil, fmt.Errorf("sync transfer lease directory: %w", err)
	}
	if err := persistExpiry(transferRoot, offer.ExpiresAtUnix); err != nil {
		return nil, err
	}
	probe := &Receiver{
		transferRoot: transferRoot, manifest: opened.manifest, contentKey: opened.contentKey,
		resumeKey: resumeKey, offer: offer,
	}
	if consumed, consumedErr := probe.verifyConsumed("consumed.state"); consumedErr != nil {
		return nil, consumedErr
	} else if consumed {
		admit.markCompleted()
		return nil, ErrAlreadyCompleted
	} else if admit.completed {
		return nil, ErrAuthentication
	}
	partPath := dir + string(os.PathSeparator) + "content.part"
	if partInfo, statErr := transferRoot.Lstat("content.part"); statErr == nil {
		if !partInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: transfer partial is not a regular file", ErrInvalidInput)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect transfer partial: %w", statErr)
	}
	part, err = transferRoot.OpenFile("content.part", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("open transfer partial: %w", err)
	}
	if err := part.Chmod(0600); err != nil {
		_ = part.Close()
		return nil, fmt.Errorf("secure transfer partial: %w", err)
	}
	info, err := part.Stat()
	if err != nil {
		_ = part.Close()
		return nil, fmt.Errorf("stat transfer partial: %w", err)
	}
	if info.Size() > opened.manifest.Size {
		if err := part.Truncate(opened.manifest.Size); err != nil {
			_ = part.Close()
			return nil, fmt.Errorf("truncate transfer partial: %w", err)
		}
	}
	currentPartInfo, err := transferRoot.Lstat("content.part")
	if err != nil || !currentPartInfo.Mode().IsRegular() || !os.SameFile(info, currentPartInfo) {
		return nil, fmt.Errorf("%w: transfer partial changed while opening", ErrInvalidInput)
	}
	r := &Receiver{
		partPath: partPath, stateID: id, stateRoot: stateRoot, transferRoot: transferRoot, part: part,
		lease: lease, admission: admit,
		manifest: opened.manifest, contentKey: opened.contentKey,
		resumeKey: resumeKey, offer: offer, completed: make([]byte, bitmapLen(opened.manifest.ChunkCount())),
		limits: limits,
	}
	if stateInfo, statErr := transferRoot.Lstat("resume.state"); statErr == nil {
		if !stateInfo.Mode().IsRegular() || stateInfo.Size() < 0 ||
			uint64(stateInfo.Size()) > uint64(limits.MaxResumeBytes) {
			_ = part.Close()
			return nil, fmt.Errorf("%w: resume state file", ErrLimitExceeded)
		}
		stateFile, openErr := transferRoot.Open("resume.state")
		if openErr != nil {
			_ = part.Close()
			return nil, fmt.Errorf("open resume state: %w", openErr)
		}
		openedStateInfo, statErr := stateFile.Stat()
		currentStateInfo, currentErr := transferRoot.Lstat("resume.state")
		if statErr != nil || currentErr != nil || !openedStateInfo.Mode().IsRegular() ||
			!os.SameFile(stateInfo, openedStateInfo) || !os.SameFile(openedStateInfo, currentStateInfo) {
			_ = stateFile.Close()
			return nil, fmt.Errorf("%w: resume state changed while opening", ErrInvalidInput)
		}
		stateBytes, readErr := io.ReadAll(io.LimitReader(stateFile, int64(limits.MaxResumeBytes)+1))
		closeErr := stateFile.Close()
		if readErr != nil {
			_ = part.Close()
			return nil, fmt.Errorf("read resume state: %w", readErr)
		}
		if closeErr != nil {
			_ = part.Close()
			return nil, fmt.Errorf("close resume state: %w", closeErr)
		}
		if uint64(len(stateBytes)) > uint64(limits.MaxResumeBytes) {
			_ = part.Close()
			return nil, fmt.Errorf("%w: resume state bytes", ErrLimitExceeded)
		}
		token, parseErr := ParseResumeToken(stateBytes, limits)
		if parseErr != nil || !r.validToken(token) {
			_ = part.Close()
			return nil, ErrAuthentication
		}
		copy(r.completed, token.Completed)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		_ = part.Close()
		return nil, fmt.Errorf("inspect resume state: %w", statErr)
	}
	if err := r.revalidateCompleted(ctx); err != nil {
		_ = part.Close()
		return nil, err
	}
	if err := r.persist(); err != nil {
		_ = part.Close()
		return nil, err
	}
	if stagingName != "" && !stagingPublished {
		if err := cleanupStaging(stateRoot, stagingName); err != nil {
			return nil, fmt.Errorf("cleanup transfer staging state: %w", err)
		}
		stagingName = ""
	}
	fail = false
	return r, nil
}

func (r *Receiver) Manifest() Manifest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneManifest(r.manifest)
}

func (r *Receiver) ResumeToken() ResumeToken {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resumeToken()
}

func (r *Receiver) resumeToken() ResumeToken {
	t := ResumeToken{
		Version: ProtocolVersion, TransferID: r.offer.TransferID, ManifestCommitment: r.offer.ManifestCommitment,
		SenderSigning: r.offer.SenderSigning, RecipientSigning: r.offer.RecipientSigning,
		SenderBinding: r.offer.SenderBinding, RecipientBinding: r.offer.RecipientBinding,
		Completed: append([]byte(nil), r.completed...),
	}
	signResume(&t, r.resumeKey)
	return t
}

func (r *Receiver) validToken(t ResumeToken) bool {
	return t.Version == ProtocolVersion && t.TransferID == r.offer.TransferID &&
		t.ManifestCommitment == r.offer.ManifestCommitment && t.SenderSigning == r.offer.SenderSigning &&
		t.RecipientSigning == r.offer.RecipientSigning && t.SenderBinding == r.offer.SenderBinding &&
		t.RecipientBinding == r.offer.RecipientBinding && len(t.Completed) == len(r.completed) &&
		verifyResume(t, r.resumeKey)
}

func (r *Receiver) revalidateCompleted(ctx context.Context) error {
	buf := make([]byte, int(r.manifest.ChunkSize))
	changed := false
	for i := uint32(0); i < r.manifest.ChunkCount(); i++ {
		if !bitSet(r.completed, i) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		n := expectedPlaintextSize(r.manifest.Size, r.manifest.ChunkSize, i, r.manifest.ChunkCount())
		read, err := r.part.ReadAt(buf[:n], int64(i)*int64(r.manifest.ChunkSize))
		if read != int(n) || (err != nil && err != io.EOF) || sha256.Sum256(buf[:n]) != r.manifest.ChunkHashes[i] {
			clearBit(r.completed, i)
			changed = true
		}
	}
	zero(buf)
	if changed {
		return r.persist()
	}
	return nil
}

func (r *Receiver) ReceiveChunk(ctx context.Context, chunk EncryptedChunk) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	if r.finalized {
		return ErrAlreadyFinalized
	}
	if chunk.Index >= r.manifest.ChunkCount() {
		return fmt.Errorf("%w: chunk index", ErrInvalidInput)
	}
	want := expectedPlaintextSize(r.manifest.Size, r.manifest.ChunkSize, chunk.Index, r.manifest.ChunkCount())
	if chunk.PlaintextSize != want || uint64(len(chunk.Ciphertext)) != uint64(want)+16 {
		return fmt.Errorf("%w: chunk size", ErrInvalidInput)
	}
	aead, err := chunkAEAD(r.contentKey)
	if err != nil {
		return err
	}
	nonce := chunkNonce(r.contentKey, r.offer.TransferID, chunk.Index)
	aad := chunkAAD(r.offer.TransferID, r.offer.ManifestCommitment, chunk.Index, want)
	plain, err := aead.Open(nil, nonce[:], chunk.Ciphertext, aad)
	if err != nil {
		return ErrAuthentication
	}
	defer zero(plain)
	if sha256.Sum256(plain) != r.manifest.ChunkHashes[chunk.Index] {
		return ErrIntegrity
	}
	offset := int64(chunk.Index) * int64(r.manifest.ChunkSize)
	if bitSet(r.completed, chunk.Index) {
		existing := make([]byte, len(plain))
		n, readErr := r.part.ReadAt(existing, offset)
		same := n == len(existing) && (readErr == nil || readErr == io.EOF) &&
			sha256.Sum256(existing) == r.manifest.ChunkHashes[chunk.Index]
		zero(existing)
		if same {
			return nil
		}
		return ErrConflictingChunk
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := r.part.WriteAt(plain, offset)
	if err != nil {
		return fmt.Errorf("write verified chunk: %w", err)
	}
	if n != len(plain) {
		return fmt.Errorf("write verified chunk: %w", io.ErrShortWrite)
	}
	if err := r.part.Sync(); err != nil {
		return fmt.Errorf("sync verified chunk: %w", err)
	}
	setBit(r.completed, chunk.Index)
	if err := r.persist(); err != nil {
		clearBit(r.completed, chunk.Index)
		return err
	}
	return nil
}

func (r *Receiver) persist() error {
	token := r.resumeToken().MarshalBinary()
	var f *os.File
	var tmpName string
	for range 5 {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return fmt.Errorf("generate resume state name: %w", err)
		}
		tmpName = "resume-" + hex.EncodeToString(suffix[:]) + ".new"
		var err error
		f, err = r.transferRoot.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create resume state: %w", err)
		}
	}
	if f == nil {
		return fmt.Errorf("create resume state: %w", os.ErrExist)
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = r.transferRoot.Remove(tmpName)
		return fmt.Errorf("secure resume state: %w", err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = r.transferRoot.Remove(tmpName)
		}
	}()
	if _, err := f.Write(token); err != nil {
		return fmt.Errorf("write resume state: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync resume state: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close resume state: %w", err)
	}
	if err := r.transferRoot.Rename(tmpName, "resume.state"); err != nil {
		return fmt.Errorf("publish resume state: %w", err)
	}
	if err := syncRootDir(r.transferRoot); err != nil {
		return fmt.Errorf("sync resume state directory: %w", err)
	}
	ok = true
	return nil
}

func (r *Receiver) Complete() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := uint32(0); i < r.manifest.ChunkCount(); i++ {
		if !bitSet(r.completed, i) {
			return false
		}
	}
	return true
}

// Finalize publishes a verified file under destinationName. destination is an
// os.Root so traversal and symlinks escaping the selected directory fail
// closed. A hard-link publish provides no-overwrite atomicity.
func (r *Receiver) Finalize(ctx context.Context, destination *os.Root, destinationName string) error {
	if destination == nil {
		return fmt.Errorf("%w: nil destination root", ErrInvalidInput)
	}
	if _, err := sanitizeFilename(destinationName, r.limits.MaxFilenameBytes); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	if r.finalized {
		return ErrAlreadyFinalized
	}
	tmpName := ".ratelmesh-" + hex.EncodeToString(r.offer.TransferID[:]) + ".partial"
	for i := uint32(0); i < r.manifest.ChunkCount(); i++ {
		if !bitSet(r.completed, i) {
			return ErrIncomplete
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.stageConsumed(); err != nil {
		return err
	}
	if _, err := destination.Lstat(destinationName); err == nil {
		if verifyErr := verifyRootFile(ctx, destination, destinationName, r.manifest.Size, r.manifest.ContentHash); verifyErr != nil {
			return fmt.Errorf("destination already exists with different content: %w", verifyErr)
		}
		if tmpInfo, tmpErr := destination.Lstat(tmpName); tmpErr == nil {
			if tmpInfo.IsDir() {
				return fmt.Errorf("%w: destination partial is a directory", ErrInvalidInput)
			}
			if err := destination.Remove(tmpName); err != nil {
				return fmt.Errorf("remove recovered destination partial: %w", err)
			}
		} else if !errors.Is(tmpErr, os.ErrNotExist) {
			return fmt.Errorf("inspect recovered destination partial: %w", tmpErr)
		}
		if err := syncRootDir(destination); err != nil {
			return fmt.Errorf("sync existing destination directory: %w", err)
		}
		return r.finalizeStateLocked()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination: %w", err)
	}
	if err := r.part.Truncate(r.manifest.Size); err != nil {
		return fmt.Errorf("truncate completed transfer: %w", err)
	}
	if _, err := r.part.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek completed transfer: %w", err)
	}
	h := sha256.New()
	buf := make([]byte, 1<<20)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			zero(buf)
			return err
		}
		n, readErr := r.part.Read(buf)
		if n > 0 {
			total += int64(n)
			_, _ = h.Write(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			zero(buf)
			return fmt.Errorf("verify completed transfer: %w", readErr)
		}
	}
	zero(buf)
	if total != r.manifest.Size || !equalHash(h.Sum(nil), r.manifest.ContentHash[:]) {
		return ErrIntegrity
	}
	if _, err := destination.Lstat(tmpName); err == nil {
		if verifyErr := verifyRootFile(ctx, destination, tmpName, r.manifest.Size, r.manifest.ContentHash); verifyErr == nil {
			if err := destination.Link(tmpName, destinationName); err != nil {
				if verifyErr := verifyRootFile(ctx, destination, destinationName, r.manifest.Size, r.manifest.ContentHash); verifyErr != nil {
					return fmt.Errorf("recover destination publish: %w", err)
				}
			}
			if err := syncRootDir(destination); err != nil {
				return fmt.Errorf("sync recovered destination publish: %w", err)
			}
			if err := verifyRootFile(ctx, destination, destinationName, r.manifest.Size, r.manifest.ContentHash); err != nil {
				return fmt.Errorf("verify recovered destination: %w", err)
			}
			if err := destination.Remove(tmpName); err != nil {
				return fmt.Errorf("remove recovered destination partial: %w", err)
			}
			if err := syncRootDir(destination); err != nil {
				return fmt.Errorf("sync recovered destination cleanup: %w", err)
			}
			return r.finalizeStateLocked()
		} else {
			if err := ctx.Err(); err != nil {
				return err
			}
			// This basename is reserved for this transfer. Remove only the
			// confined directory entry itself; os.Root.Remove does not follow
			// a symlink and never touches destinationName.
			if err := destination.Remove(tmpName); err != nil {
				return fmt.Errorf("remove invalid destination partial: %w", err)
			}
			if err := syncRootDir(destination); err != nil {
				return fmt.Errorf("sync invalid destination partial cleanup: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination partial: %w", err)
	}
	out, err := destination.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create destination partial: %w", err)
	}
	removeTmp := true
	defer func() {
		_ = out.Close()
		if removeTmp {
			_ = destination.Remove(tmpName)
		}
	}()
	if _, err := r.part.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek completed transfer: %w", err)
	}
	copiedHash := sha256.New()
	if _, err := copyWithContext(ctx, io.MultiWriter(out, copiedHash), r.part, r.manifest.Size); err != nil {
		return err
	}
	if !equalHash(copiedHash.Sum(nil), r.manifest.ContentHash[:]) {
		return ErrIntegrity
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync destination partial: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close destination partial: %w", err)
	}
	if err := destination.Link(tmpName, destinationName); err != nil {
		return fmt.Errorf("atomically publish destination: %w", err)
	}
	// Once published, retain the verified temporary link until both the
	// publication and its later removal have crossed directory barriers.
	removeTmp = false
	if err := syncRootDir(destination); err != nil {
		return fmt.Errorf("sync destination publish: %w", err)
	}
	if err := verifyRootFile(ctx, destination, destinationName, r.manifest.Size, r.manifest.ContentHash); err != nil {
		return fmt.Errorf("verify published destination: %w", err)
	}
	if err := destination.Remove(tmpName); err != nil {
		return fmt.Errorf("remove destination partial: %w", err)
	}
	if err := syncRootDir(destination); err != nil {
		return fmt.Errorf("sync destination cleanup: %w", err)
	}
	return r.finalizeStateLocked()
}

func (r *Receiver) finalizeStateLocked() error {
	if err := r.commitConsumed(); err != nil {
		return err
	}
	if r.part != nil {
		if err := r.part.Close(); err != nil {
			return fmt.Errorf("close finalized transfer state: %w", err)
		}
		r.part = nil
	}
	// Keep reservation.state beside the consumed tombstone. It is the durable
	// principal identity used to reconcile per-principal retained quotas after a
	// restart; it reserves no content bytes once markCompleted runs.
	for _, name := range []string{"content.part", "resume.state", "consumed.pending"} {
		if err := r.transferRoot.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove finalized transfer state %s: %w", name, err)
		}
	}
	if err := syncRootDir(r.transferRoot); err != nil {
		return fmt.Errorf("sync finalized transfer state: %w", err)
	}
	r.finalized = true
	r.admission.markCompleted()
	r.admission.closeActive()
	return nil
}

func persistExpiry(root *os.Root, expires int64) error {
	encoded := encodeExpiry(expires)
	if _, err := root.Lstat("expires.at"); err == nil {
		got, readErr := readExpiry(root)
		if readErr != nil || got != encoded {
			return fmt.Errorf("%w: conflicting transfer expiry", ErrAuthentication)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWriteState(root, "expires.at", encoded[:])
}

func readExpiry(root *os.Root) ([8]byte, error) {
	var encoded [8]byte
	before, err := root.Lstat("expires.at")
	if err != nil {
		return encoded, err
	}
	if !before.Mode().IsRegular() || before.Size() != int64(len(encoded)) {
		return encoded, fmt.Errorf("%w: transfer expiry", ErrInvalidInput)
	}
	f, err := root.Open("expires.at")
	if err != nil {
		return encoded, err
	}
	opened, statErr := f.Stat()
	current, currentErr := root.Lstat("expires.at")
	if statErr != nil || currentErr != nil || !opened.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(opened, current) {
		_ = f.Close()
		return encoded, fmt.Errorf("%w: transfer expiry changed while opening", ErrInvalidInput)
	}
	_, readErr := io.ReadFull(f, encoded[:])
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return encoded, errors.Join(readErr, closeErr)
	}
	return encoded, nil
}

func removeStateContent(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open transfer state for cleanup: %w", err)
	}
	const maxStateEntries = 32
	entries, readErr := dir.ReadDir(maxStateEntries + 1)
	closeErr := dir.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if len(entries) > maxStateEntries {
		return fmt.Errorf("%w: too many transfer state entries", ErrLimitExceeded)
	}
	removable := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		info, err := root.Lstat(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("inspect transfer state cleanup entry: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: transfer state cleanup entry is not a regular file", ErrInvalidInput)
		}
		remove, known := transferStateEntry(name)
		if !known {
			return fmt.Errorf("%w: unknown transfer state entry %q", ErrInvalidInput, name)
		}
		if remove {
			removable = append(removable, name)
		}
	}
	// Validation is deliberately a complete first pass. A hostile or future
	// unknown entry therefore cannot cause partial destruction of resumable state.
	for _, name := range removable {
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove transfer state %s: %w", name, err)
		}
	}
	return nil
}

func transferStateEntry(name string) (remove, known bool) {
	switch name {
	case "transfer.lock":
		return false, true
	case "content.part", "resume.state", "expires.at", "reservation.state",
		"consumed.pending", "consumed.state":
		return true, true
	}
	if exactStateTemporary(name, "resume-", ".new") ||
		exactStateTemporary(name, ".expires.at-", ".new") ||
		exactStateTemporary(name, ".reservation.state-", ".new") ||
		exactStateTemporary(name, ".consumed.pending-", ".new") {
		return true, true
	}
	return false, false
}

func exactStateTemporary(name, prefix, suffix string) bool {
	if len(name) != len(prefix)+24+len(suffix) ||
		name[:len(prefix)] != prefix || name[len(name)-len(suffix):] != suffix {
		return false
	}
	return isLowerHex(name[len(prefix) : len(prefix)+24])
}

func isLowerHex(value string) bool {
	if value == "" {
		return false
	}
	for i := range value {
		if !((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')) {
			return false
		}
	}
	return true
}

// Cancel destroys resumable content while holding the exclusive transfer
// lease. The durable lease inode is intentionally retained for safe reuse.
func (r *Receiver) Cancel() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if r.part != nil {
		if err := r.part.Close(); err != nil {
			return fmt.Errorf("close canceled transfer: %w", err)
		}
		r.part = nil
	}
	var suffix [8]byte
	if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
		return fmt.Errorf("generate canceled transfer quarantine: %w", err)
	}
	quarantine := ".cancel-" + r.stateID + "-" + hex.EncodeToString(suffix[:])
	if err := r.stateRoot.Rename(r.stateID, quarantine); err != nil {
		return fmt.Errorf("quarantine canceled transfer: %w", err)
	}
	quarantineSyncErr := syncRootDir(r.stateRoot)
	var cleanupErr error
	if quarantineSyncErr == nil {
		// Do not destroy resumable state until the quarantine name is durable.
		// Any later crash is recoverable through the exact .cancel-* namespace.
		if err := removeStateContent(r.transferRoot); err != nil {
			cleanupErr = err
		} else if err := syncRootDir(r.transferRoot); err != nil {
			cleanupErr = fmt.Errorf("sync canceled transfer state: %w", err)
		}
	}
	r.closed = true
	zero(r.contentKey)
	zero(r.resumeKey)
	r.contentKey, r.resumeKey = nil, nil
	r.admission.releaseReservation()
	r.admission.closeActive()
	leaseErr := r.lease.close()
	lockErr := r.transferRoot.Remove("transfer.lock")
	dirSyncErr := syncRootDir(r.transferRoot)
	transferErr := r.transferRoot.Close()
	removeErr := r.stateRoot.Remove(quarantine)
	rootSyncErr := syncRootDir(r.stateRoot)
	stateErr := r.stateRoot.Close()
	return errors.Join(quarantineSyncErr, cleanupErr, leaseErr, lockErr, dirSyncErr, transferErr, removeErr, rootSyncErr, stateErr)
}

func verifyRootFile(ctx context.Context, root *os.Root, name string, size int64, expected [sha256.Size]byte) error {
	before, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Size() != size {
		return ErrIntegrity
	}
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	current, currentErr := root.Lstat(name)
	if err != nil || currentErr != nil || !opened.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return ErrIntegrity
	}
	h := sha256.New()
	n, err := copyWithContext(ctx, h, io.LimitReader(f, size+1), size+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if n != size || !equalHash(h.Sum(nil), expected[:]) {
		return ErrIntegrity
	}
	return nil
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader, expected int64) (int64, error) {
	buf := make([]byte, 1<<20)
	defer zero(buf)
	var total int64
	for total < expected {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		want := int64(len(buf))
		if expected-total < want {
			want = expected - total
		}
		n, err := src.Read(buf[:want])
		if n > 0 {
			w, writeErr := dst.Write(buf[:n])
			total += int64(w)
			if writeErr != nil {
				return total, fmt.Errorf("write destination partial: %w", writeErr)
			}
			if w != n {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF && total == expected {
				break
			}
			return total, fmt.Errorf("read completed transfer: %w", err)
		}
	}
	return total, nil
}

func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func (r *Receiver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	zero(r.contentKey)
	zero(r.resumeKey)
	r.contentKey, r.resumeKey = nil, nil
	var partErr error
	if r.part != nil {
		partErr = r.part.Close()
		r.part = nil
	}
	r.admission.closeActive()
	leaseErr := r.lease.close()
	transferErr := r.transferRoot.Close()
	stateErr := r.stateRoot.Close()
	return errors.Join(partErr, leaseErr, transferErr, stateErr)
}
