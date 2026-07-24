//go:build windows

package atomicfile

// SyncDir is a no-op on Windows: directory handles opened read-only cannot be
// flushed (FlushFileBuffers needs write access), and NTFS journals the rename
// metadata itself. Failing every save would be worse than skipping the flush.
func SyncDir(string) error { return nil }
