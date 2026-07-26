//go:build windows

package filetransfer

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const lockfileFailImmediately = 0x00000001
const lockfileExclusiveLock = 0x00000002
const errorLockViolation syscall.Errno = 33
const errorIOPending syscall.Errno = 997

var (
	errWouldBlock  = errors.New("lease would block")
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx = kernel32.NewProc("LockFileEx")
	procUnlockFile = kernel32.NewProc("UnlockFileEx")
)

func lockFile(f *os.File) error {
	var overlapped syscall.Overlapped
	ok, _, callErr := procLockFileEx.Call(
		f.Fd(), lockfileExclusiveLock|lockfileFailImmediately,
		0, 1, 0, uintptr(unsafe.Pointer(&overlapped)),
	)
	if ok != 0 {
		return nil
	}
	if errors.Is(callErr, errorLockViolation) || errors.Is(callErr, errorIOPending) {
		return errWouldBlock
	}
	return callErr
}

func lockFileBlocking(f *os.File) error {
	var overlapped syscall.Overlapped
	ok, _, callErr := procLockFileEx.Call(
		f.Fd(), lockfileExclusiveLock,
		0, 1, 0, uintptr(unsafe.Pointer(&overlapped)),
	)
	if ok != 0 {
		return nil
	}
	return callErr
}

func unlockFile(f *os.File) error {
	var overlapped syscall.Overlapped
	ok, _, callErr := procUnlockFile.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if ok != 0 {
		return nil
	}
	return callErr
}
