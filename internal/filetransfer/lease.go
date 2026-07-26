package filetransfer

import (
	"errors"
	"fmt"
	"os"
)

type transferLease struct {
	file *os.File
}

func acquireTransferLease(root *os.Root) (*transferLease, error) {
	if info, err := root.Lstat("transfer.lock"); err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: transfer lease is not regular", ErrInvalidInput)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect transfer lease: %w", err)
	}
	f, err := root.OpenFile("transfer.lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("open transfer lease: %w", err)
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("secure transfer lease: %w", err)
	}
	opened, err := f.Stat()
	current, currentErr := root.Lstat("transfer.lock")
	if err != nil || currentErr != nil || !opened.Mode().IsRegular() || !os.SameFile(opened, current) {
		_ = f.Close()
		return nil, fmt.Errorf("%w: transfer lease changed while opening", ErrInvalidInput)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		if errors.Is(err, errWouldBlock) {
			return nil, ErrTransferBusy
		}
		return nil, fmt.Errorf("lock transfer lease: %w", err)
	}
	return &transferLease{file: f}, nil
}

func (l *transferLease) close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}
