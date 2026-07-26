package filetransfer

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

const reservationMagic = "RMQR"

const (
	trustedTimeState = ".trusted-time.state"
	trustedTimeLock  = ".trusted-time.lock"
	trustedTimeBytes = 16
)

func encodeReservation(tenant, device string, reserved int64) ([]byte, error) {
	if len(tenant) == 0 || len(tenant) > maxTenantIDBytes || len(device) == 0 ||
		len(device) > maxDeviceIDBytes || reserved < 0 {
		return nil, fmt.Errorf("%w: reservation metadata", ErrInvalidInput)
	}
	b := append([]byte{}, reservationMagic...)
	b = appendU16(b, ProtocolVersion)
	b = appendU16(b, uint16(len(tenant)))
	b = append(b, tenant...)
	b = appendU16(b, uint16(len(device)))
	b = append(b, device...)
	b = appendU64(b, uint64(reserved))
	return b, nil
}

func decodeReservation(b []byte) (reservationRecord, error) {
	if len(b) > 4+2+2+maxTenantIDBytes+2+maxDeviceIDBytes+8 {
		return reservationRecord{}, fmt.Errorf("%w: reservation metadata", ErrLimitExceeded)
	}
	d := decoder{b: b}
	magic, err := d.take(4)
	if err != nil || !bytes.Equal(magic, []byte(reservationMagic)) {
		return reservationRecord{}, fmt.Errorf("%w: reservation magic", ErrInvalidInput)
	}
	version, err := d.u16()
	if err != nil || version != ProtocolVersion {
		return reservationRecord{}, fmt.Errorf("%w: reservation version", ErrInvalidInput)
	}
	tenantLen, err := d.u16()
	if err != nil || tenantLen == 0 || tenantLen > maxTenantIDBytes {
		return reservationRecord{}, fmt.Errorf("%w: reservation tenant", ErrInvalidInput)
	}
	tenant, err := d.take(int(tenantLen))
	if err != nil {
		return reservationRecord{}, err
	}
	deviceLen, err := d.u16()
	if err != nil || deviceLen == 0 || deviceLen > maxDeviceIDBytes {
		return reservationRecord{}, fmt.Errorf("%w: reservation device", ErrInvalidInput)
	}
	device, err := d.take(int(deviceLen))
	if err != nil {
		return reservationRecord{}, err
	}
	reserved, err := d.u64()
	if err != nil || reserved > uint64(^uint64(0)>>1) {
		return reservationRecord{}, fmt.Errorf("%w: reservation bytes", ErrLimitExceeded)
	}
	if err := d.done(); err != nil {
		return reservationRecord{}, err
	}
	return reservationRecord{tenant: string(tenant), device: string(device), bytes: int64(reserved)}, nil
}

func atomicWriteState(root *os.Root, name string, data []byte) error {
	var suffix [12]byte
	if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
		return fmt.Errorf("generate state filename: %w", err)
	}
	tmp := "." + name + "-" + hex.EncodeToString(suffix[:]) + ".new"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		_ = f.Close()
		if !published {
			_ = root.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		return err
	}
	if err := syncRootDir(root); err != nil {
		return err
	}
	published = true
	return nil
}

func readBoundedRootFile(root *os.Root, name string, maximum int64) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maximum {
		return nil, fmt.Errorf("%w: state file", ErrInvalidInput)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, statErr := f.Stat()
	current, currentErr := root.Lstat(name)
	if statErr != nil || currentErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, current) {
		_ = f.Close()
		return nil, fmt.Errorf("%w: state file changed", ErrInvalidInput)
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maximum+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("%w: state file", ErrLimitExceeded)
	}
	return data, nil
}

func encodeExpiry(expires int64) [8]byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(expires))
	return encoded
}

// trustedTransferTime advances a state-root-wide wall-clock floor before an
// offer is authenticated. Persisting rejected observations is intentional: an
// expired offer must not become valid again after a restart and clock rollback.
func trustedTransferTime(stateDir string, now time.Time, keyVersion uint64) (time.Time, error) {
	if now.IsZero() || now.Unix() < 0 || keyVersion == 0 {
		return time.Time{}, fmt.Errorf("%w: transfer time", ErrInvalidInput)
	}
	root, err := openVerifiedStateRoot(stateDir, true)
	if err != nil {
		return time.Time{}, fmt.Errorf("open transfer state root: %w", err)
	}
	defer root.Close()
	if err := root.Chmod(".", 0700); err != nil {
		return time.Time{}, fmt.Errorf("secure transfer state root: %w", err)
	}
	lock, err := openTrustedTimeLock(root)
	if err != nil {
		return time.Time{}, err
	}
	defer func() {
		_ = unlockFile(lock)
		_ = lock.Close()
	}()

	floor := int64(0)
	storedVersion := uint64(0)
	legacy := false
	data, err := readBoundedRootFile(root, trustedTimeState, trustedTimeBytes)
	switch {
	case err == nil:
		if len(data) != 8 && len(data) != trustedTimeBytes {
			return time.Time{}, fmt.Errorf("%w: trusted transfer time", ErrInvalidInput)
		}
		encoded := binary.BigEndian.Uint64(data)
		if encoded > uint64(^uint64(0)>>1) {
			return time.Time{}, fmt.Errorf("%w: trusted transfer time", ErrInvalidInput)
		}
		floor = int64(encoded)
		if len(data) == 8 {
			// The original format did not record a binding version. Preserve
			// its time floor during the one-time migration and bind it to the
			// already verified local identity instead of treating the current
			// key as a recovery event.
			storedVersion = keyVersion
			legacy = true
		} else {
			storedVersion = binary.BigEndian.Uint64(data[8:])
			if storedVersion == 0 {
				return time.Time{}, fmt.Errorf("%w: trusted transfer time", ErrInvalidInput)
			}
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return time.Time{}, fmt.Errorf("read trusted transfer time: %w", err)
	}
	if storedVersion > keyVersion {
		return time.Time{}, fmt.Errorf("%w: device key version rollback", ErrAuthentication)
	}
	changed := legacy || storedVersion == 0
	if storedVersion < keyVersion && storedVersion != 0 {
		// A higher binding version is authority-signed and its private keys were
		// proven by LocalDevice, making it the safe recovery boundary for an
		// accidental future clock observation. Offers for the old recipient
		// binding cannot authenticate under the new LocalDevice.
		floor = now.Unix()
		storedVersion = keyVersion
		changed = true
	} else if now.Unix() > floor {
		floor = now.Unix()
		changed = true
	}
	if storedVersion == 0 {
		storedVersion = keyVersion
	}
	if changed {
		var encoded [trustedTimeBytes]byte
		binary.BigEndian.PutUint64(encoded[:8], uint64(floor))
		binary.BigEndian.PutUint64(encoded[8:], storedVersion)
		if err := atomicWriteState(root, trustedTimeState, encoded[:]); err != nil {
			return time.Time{}, fmt.Errorf("persist trusted transfer time: %w", err)
		}
	}
	return time.Unix(floor, 0).UTC(), nil
}

func openTrustedTimeLock(root *os.Root) (*os.File, error) {
	if info, err := root.Lstat(trustedTimeLock); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("%w: trusted time lock", ErrInvalidInput)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect trusted time lock: %w", err)
	}
	var lock *os.File
	var err error
	for range 8 {
		lock, err = root.OpenFile(trustedTimeLock, os.O_CREATE|os.O_RDWR, 0600)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			break
		}
		// os.Root may transiently report ENOENT while another first opener is
		// publishing the same create. Retry without ever replacing the inode.
		runtime.Gosched()
	}
	if err != nil {
		return nil, fmt.Errorf("open trusted time lock: %w", err)
	}
	if err := lock.Chmod(0600); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("secure trusted time lock: %w", err)
	}
	opened, statErr := lock.Stat()
	current, currentErr := root.Lstat(trustedTimeLock)
	if statErr != nil || currentErr != nil || !opened.Mode().IsRegular() ||
		!os.SameFile(opened, current) {
		_ = lock.Close()
		return nil, fmt.Errorf("%w: trusted time lock changed", ErrInvalidInput)
	}
	if err := lockFileBlocking(lock); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock trusted transfer time: %w", err)
	}
	return lock, nil
}

func openVerifiedStateRoot(stateDir string, create bool) (*os.Root, error) {
	if create {
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			return nil, fmt.Errorf("create transfer state root: %w", err)
		}
	}
	before, err := os.Lstat(stateDir)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: transfer state root is not a real directory", ErrInvalidInput)
	}
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return nil, err
	}
	opened, statErr := root.Stat(".")
	current, currentErr := os.Lstat(stateDir)
	if statErr != nil || currentErr != nil || !os.SameFile(before, opened) ||
		!os.SameFile(opened, current) || current.Mode()&os.ModeSymlink != 0 {
		_ = root.Close()
		return nil, fmt.Errorf("%w: transfer state root changed while opening", ErrInvalidInput)
	}
	return root, nil
}

func openVerifiedChild(root *os.Root, name string) (*os.Root, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: transfer state is not a real directory", ErrInvalidInput)
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, statErr := child.Stat(".")
	current, currentErr := root.Lstat(name)
	if statErr != nil || currentErr != nil || !os.SameFile(before, opened) ||
		!os.SameFile(opened, current) || current.Mode()&os.ModeSymlink != 0 {
		_ = child.Close()
		return nil, fmt.Errorf("%w: transfer state changed while opening", ErrInvalidInput)
	}
	return child, nil
}

func cleanupStaging(root *os.Root, name string) error {
	staging, err := root.OpenRoot(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	removeErr := removeStateContent(staging)
	closeErr := staging.Close()
	if removeErr != nil || closeErr != nil {
		return errors.Join(removeErr, closeErr)
	}
	if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncRootDir(root)
}
