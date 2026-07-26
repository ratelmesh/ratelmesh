//go:build windows

package filetransfer

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	genericWrite            = 0x40000000
	fileShareRead           = 0x00000001
	fileShareWrite          = 0x00000002
	fileShareDelete         = 0x00000004
	openExisting            = 3
	fileFlagBackupSemantics = 0x02000000
)

var (
	durabilityKernel32        = syscall.NewLazyDLL("kernel32.dll")
	procGetFinalPathName      = durabilityKernel32.NewProc("GetFinalPathNameByHandleW")
	procCreateDirectoryHandle = durabilityKernel32.NewProc("CreateFileW")
	procFlushFileBuffers      = durabilityKernel32.NewProc("FlushFileBuffers")
	windowsDirectoryFlush     = flushWindowsDirectory
)

func platformSyncDirectory(root *os.Root) error {
	probe, err := root.Open(".")
	if err != nil {
		return err
	}
	defer probe.Close()
	path, err := finalPathName(probe.Fd())
	if err != nil {
		return err
	}
	return windowsDirectoryFlush(path)
}

func finalPathName(handle uintptr) (string, error) {
	buffer := make([]uint16, 512)
	for {
		n, _, callErr := procGetFinalPathName.Call(handle, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
		if n == 0 {
			return "", callErr
		}
		if n < uintptr(len(buffer)) {
			return syscall.UTF16ToString(buffer[:n]), nil
		}
		buffer = make([]uint16, n+1)
	}
}

func flushWindowsDirectory(path string) error {
	utf16Path, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, _, callErr := procCreateDirectoryHandle.Call(
		uintptr(unsafe.Pointer(utf16Path)), genericWrite,
		fileShareRead|fileShareWrite|fileShareDelete, 0, openExisting,
		fileFlagBackupSemantics, 0,
	)
	if handle == uintptr(syscall.InvalidHandle) {
		return callErr
	}
	defer syscall.CloseHandle(syscall.Handle(handle))
	ok, _, callErr := procFlushFileBuffers.Call(handle)
	if ok == 0 {
		return callErr
	}
	return nil
}
