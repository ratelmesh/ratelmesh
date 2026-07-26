//go:build windows

package filetransfer

import (
	"errors"
	"os"
	"testing"
)

func TestWindowsDirectorySyncIsUsable(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := syncRootDir(root); err != nil {
		t.Fatalf("Windows receiver directory sync unavailable: %v", err)
	}
}

func TestWindowsDirectorySyncFailureIsExplicit(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	original := windowsDirectoryFlush
	windowsDirectoryFlush = func(string) error { return errors.New("injected flush failure") }
	defer func() { windowsDirectoryFlush = original }()
	if err := syncRootDir(root); !errors.Is(err, ErrDurability) {
		t.Fatalf("flush failure did not fail closed: %v", err)
	}
}
