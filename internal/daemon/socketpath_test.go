package daemon

import "testing"

func TestInstalledMacOSSocketPath(t *testing.T) {
	t.Run("installed macOS app", func(t *testing.T) {
		var checked string
		got := installedMacOSSocketPath("darwin", func(path string) bool {
			checked = path
			return true
		})
		if checked != macOSLaunchDaemonPath {
			t.Fatalf("checked path = %q, want %q", checked, macOSLaunchDaemonPath)
		}
		if got != macOSSystemSocketPath {
			t.Fatalf("socket path = %q, want %q", got, macOSSystemSocketPath)
		}
	})

	t.Run("macOS development build", func(t *testing.T) {
		if got := installedMacOSSocketPath("darwin", func(string) bool { return false }); got != "" {
			t.Fatalf("socket path = %q, want empty", got)
		}
	})

	t.Run("other operating system", func(t *testing.T) {
		if got := installedMacOSSocketPath("linux", func(string) bool { return true }); got != "" {
			t.Fatalf("socket path = %q, want empty", got)
		}
	})
}

func TestDefaultSocketPathEnvironmentOverride(t *testing.T) {
	t.Setenv("RATELMESH_SOCKET", "/tmp/ratelmesh-test.sock")
	if got := DefaultSocketPath(); got != "/tmp/ratelmesh-test.sock" {
		t.Fatalf("DefaultSocketPath() = %q", got)
	}
}
