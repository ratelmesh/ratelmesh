//go:build !windows

package atomicfile

import "os"

// SyncDir flushes directory metadata so a rename is durable across power loss.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
