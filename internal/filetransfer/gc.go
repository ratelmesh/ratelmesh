package filetransfer

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const DefaultStateRetention = 7 * 24 * time.Hour

const (
	maxGCScannedEntries = 4096
	maxGCRemovals       = 256
	gcReadBatch         = 128
)

func GarbageCollectExpired(stateDir string, now time.Time) (int, error) {
	return GarbageCollectExpiredWithManager(stateDir, now, DefaultStateRetention, defaultAdmissionManager)
}

// GarbageCollectExpiredWithManager isolates malformed entries, quarantines an
// expired directory while its lease is held, and only then removes its inode.
func GarbageCollectExpiredWithManager(stateDir string, now time.Time, retention time.Duration, manager *AdmissionManager) (int, error) {
	if retention <= 0 || manager == nil {
		return 0, fmt.Errorf("%w: GC configuration", ErrInvalidInput)
	}
	root, err := openVerifiedStateRoot(stateDir, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("open transfer state root: %w", err)
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return 0, err
	}
	removed := 0
	scanned := 0
	var entryErrors []error
	for {
		entries, readErr := dir.ReadDir(gcReadBatch)
		for _, entry := range entries {
			scanned++
			if scanned > maxGCScannedEntries {
				entryErrors = append(entryErrors, fmt.Errorf("%w: too many state-root entries", ErrLimitExceeded))
				break
			}
			if removed >= maxGCRemovals {
				entryErrors = append(entryErrors, fmt.Errorf("%w: GC removal budget", ErrLimitExceeded))
				break
			}
			name := entry.Name()
			switch {
			case validTransferID(name):
				if err := collectOne(root, stateDir, name, now, retention, manager); err != nil {
					if !errors.Is(err, ErrTransferBusy) {
						entryErrors = append(entryErrors, fmt.Errorf("%s: %w", name, err))
					}
					continue
				}
				removed++
			case residualKind(name) != residualUnknown:
				didRemove, err := collectResidual(root, name, now, retention)
				if err != nil {
					if !errors.Is(err, ErrTransferBusy) {
						entryErrors = append(entryErrors, fmt.Errorf("%s: %w", name, err))
					}
					continue
				}
				if didRemove {
					removed++
				}
			}
		}
		if scanned > maxGCScannedEntries || removed >= maxGCRemovals {
			break
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			entryErrors = append(entryErrors, readErr)
			break
		}
	}
	closeErr := dir.Close()
	return removed, errors.Join(append(entryErrors, closeErr)...)
}

func validTransferID(name string) bool {
	return len(name) == transferIDSize*2 && isLowerHex(name)
}

type crashResidualKind uint8

const (
	residualUnknown crashResidualKind = iota
	residualStaging
	residualGC
	residualCancel
)

func residualKind(name string) crashResidualKind {
	if len(name) == len(".transfer-")+24+len(".new") &&
		name[:len(".transfer-")] == ".transfer-" &&
		name[len(name)-len(".new"):] == ".new" &&
		isLowerHex(name[len(".transfer-"):len(name)-len(".new")]) {
		return residualStaging
	}
	for _, candidate := range []struct {
		prefix string
		kind   crashResidualKind
	}{
		{".gc-", residualGC},
		{".cancel-", residualCancel},
	} {
		if len(name) == len(candidate.prefix)+transferIDSize*2+1+16 &&
			name[:len(candidate.prefix)] == candidate.prefix &&
			name[len(candidate.prefix)+transferIDSize*2] == '-' &&
			isLowerHex(name[len(candidate.prefix):len(candidate.prefix)+transferIDSize*2]) &&
			isLowerHex(name[len(name)-16:]) {
			return candidate.kind
		}
	}
	return residualUnknown
}

func collectResidual(root *os.Root, name string, now time.Time, retention time.Duration) (bool, error) {
	kind := residualKind(name)
	if kind == residualUnknown {
		return false, fmt.Errorf("%w: residual name", ErrInvalidInput)
	}
	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: residual is not a real directory", ErrInvalidInput)
	}
	// Staging names can still belong to a live transaction. Age is a second,
	// conservative proof in addition to the inode lease.
	if kind == residualStaging && info.ModTime().Add(retention).After(now) {
		return false, ErrTransferBusy
	}
	child, err := openVerifiedChild(root, name)
	if err != nil {
		return false, err
	}
	defer child.Close()
	lease, err := acquireTransferLease(child)
	if err != nil {
		return false, err
	}
	defer lease.close()
	if err := validateResidualContent(child, kind); err != nil {
		return false, err
	}
	if err := removeStateContent(child); err != nil {
		return false, err
	}
	if err := syncRootDir(child); err != nil {
		return false, err
	}
	if err := lease.close(); err != nil {
		return false, err
	}
	if err := child.Remove("transfer.lock"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := syncRootDir(child); err != nil {
		return false, err
	}
	if err := child.Close(); err != nil {
		return false, err
	}
	if err := root.Remove(name); err != nil {
		return false, err
	}
	if err := syncRootDir(root); err != nil {
		return false, err
	}
	return true, nil
}

func validateResidualContent(root *os.Root, kind crashResidualKind) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(33)
	closeErr := dir.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if len(entries) > 32 {
		return fmt.Errorf("%w: too many residual entries", ErrLimitExceeded)
	}
	for _, entry := range entries {
		name := entry.Name()
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: residual contains non-regular entry", ErrInvalidInput)
		}
		if kind == residualStaging {
			remove, known := transferStateEntry(name)
			if !known || (!remove && name != "transfer.lock") ||
				(name == "content.part" || name == "resume.state" ||
					name == "consumed.pending" || name == "consumed.state") {
				return fmt.Errorf("%w: unknown staging content %q", ErrInvalidInput, name)
			}
			continue
		}
		if _, known := transferStateEntry(name); !known {
			return fmt.Errorf("%w: unknown quarantine content %q", ErrInvalidInput, name)
		}
	}
	return nil
}

func collectOne(root *os.Root, stateDir, id string, now time.Time, retention time.Duration, manager *AdmissionManager) error {
	info, err := root.Lstat(id)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidInput
	}
	transfer, err := openVerifiedChild(root, id)
	if err != nil {
		return err
	}
	lease, err := acquireTransferLease(transfer)
	if err != nil {
		_ = transfer.Close()
		return err
	}
	expired, expiryErr := transferExpired(transfer, now)
	if expiryErr != nil {
		// A normal transfer directory may contain the only resumable copy. Never
		// turn malformed/missing authenticated state into permission to delete it;
		// age-based recovery applies only to the unpublishable .transfer-*.new
		// namespace.
		_ = lease.close()
		_ = transfer.Close()
		return expiryErr
	}
	if !expired {
		_ = lease.close()
		_ = transfer.Close()
		return ErrTransferBusy
	}
	var suffix [8]byte
	if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
		_ = lease.close()
		_ = transfer.Close()
		return err
	}
	quarantine := ".gc-" + id + "-" + hex.EncodeToString(suffix[:])
	if err := root.Rename(id, quarantine); err != nil {
		_ = lease.close()
		_ = transfer.Close()
		return err
	}
	if err := syncRootDir(root); err != nil {
		_ = lease.close()
		_ = transfer.Close()
		return err
	}
	// Only destroy resumable state after the quarantine rename is durable. A
	// crash before this point leaves the complete canonical directory; a crash
	// after it leaves an exact .gc-* residual that recovery can safely finish.
	if err := removeStateContent(transfer); err != nil {
		_ = lease.close()
		_ = transfer.Close()
		return err
	}
	if err := syncRootDir(transfer); err != nil {
		_ = lease.close()
		_ = transfer.Close()
		return err
	}
	leaseErr := lease.close()
	lockErr := transfer.Remove("transfer.lock")
	syncErr := syncRootDir(transfer)
	closeErr := transfer.Close()
	if leaseErr != nil || (lockErr != nil && !errors.Is(lockErr, os.ErrNotExist)) || syncErr != nil || closeErr != nil {
		return errors.Join(leaseErr, lockErr, syncErr, closeErr)
	}
	if err := root.Remove(quarantine); err != nil {
		return err
	}
	if err := syncRootDir(root); err != nil {
		return err
	}
	key, err := reservationKey(stateDir, id)
	if err == nil {
		manager.dropReservation(key)
	}
	return nil
}

func transferExpired(root *os.Root, now time.Time) (bool, error) {
	encoded, err := readExpiry(root)
	if err != nil {
		return false, fmt.Errorf("read transfer expiry: %w", err)
	}
	expiry := binary.BigEndian.Uint64(encoded[:])
	if now.Unix() < 0 {
		return false, nil
	}
	return expiry <= uint64(now.Unix()), nil
}
