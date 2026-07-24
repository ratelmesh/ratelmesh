package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// maxUnixSocketPath is the platform limit on sockaddr_un.sun_path. It is 104 on
// darwin/BSD and 108 on Linux; use the smaller so a path that works locally also
// works on macOS.
const maxUnixSocketPath = 104

const (
	macOSLaunchDaemonPath = "/Library/LaunchDaemons/com.ratelmesh.daemon.plist"
	macOSSystemSocketPath = "/var/run/ratelmesh.sock"
)

// DefaultSocketPath returns the local API socket path both ratelmeshd and the CLI
// agree on. It lives in a short runtime directory (never the possibly-deep
// state dir) to stay under the sun_path limit (see the macOS bug this avoids).
func DefaultSocketPath() string {
	if v := os.Getenv("RATELMESH_SOCKET"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		return `\\.\pipe\RatelMesh`
	}
	if socket := installedMacOSSocketPath(runtime.GOOS, func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}); socket != "" {
		return socket
	}
	dir := runtimeDir()
	return filepath.Join(dir, "ratelmeshd.sock")
}

func installedMacOSSocketPath(goos string, exists func(string) bool) string {
	if goos == "darwin" && exists(macOSLaunchDaemonPath) {
		return macOSSystemSocketPath
	}
	return ""
}

// runtimeDir picks a short, user-writable directory for the socket.
func runtimeDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "darwin" {
		// $TMPDIR on macOS is per-user and reasonably short.
		if d := os.Getenv("TMPDIR"); d != "" {
			return d
		}
	}
	return os.TempDir()
}

// ValidateSocketPath returns a helpful error if the path would exceed the OS
// limit, rather than surfacing the opaque "invalid argument" bind failure.
func ValidateSocketPath(path string) error {
	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(strings.ToLower(path), `\\.\pipe\`) || len(path) <= len(`\\.\pipe\`) {
			return fmt.Errorf("invalid Windows named-pipe path %q (want \\\\.\\pipe\\<name>)", path)
		}
		return nil
	}
	if len(path) >= maxUnixSocketPath {
		return fmt.Errorf("socket path too long (%d >= %d bytes): %s — set a shorter -socket or $RATELMESH_SOCKET",
			len(path), maxUnixSocketPath, path)
	}
	return nil
}
