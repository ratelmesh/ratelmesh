// Package atomicfile writes files atomically and durably: temp file in the
// destination directory, mode 0600, fsync, rename over the destination, then
// a parent-directory sync where the platform supports it. It is the single
// implementation behind the coord state snapshot, the daemon's identity/state
// files, and the Windows tunnel-service configuration, so the durability
// contract (survive power loss, never expose a partial file) cannot drift
// between callers.
package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
)

// WriteFile atomically replaces path with data (mode 0600).
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// Windows cannot always replace an existing destination atomically
		// (e.g. while another handle holds it without FILE_SHARE_DELETE).
		// Remove and retry; callers stop any reader/service first.
		if runtime.GOOS != "windows" || os.Remove(path) != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	ok = true
	return SyncDir(dir)
}
