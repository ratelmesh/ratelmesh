//go:build !windows

package filetransfer

import (
	"os"
	"testing"
)

func TestDirectorySyncAdapter(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := syncRootDir(root); err != nil {
		t.Fatalf("directory durability unavailable on supported filesystem: %v", err)
	}
}
