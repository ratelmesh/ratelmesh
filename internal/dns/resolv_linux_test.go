package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvFileCrashRecoveryUsesPersistedOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	backup := filepath.Join(dir, "resolv.conf.ratelmesh-backup")
	original := []byte("nameserver 192.0.2.53\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	first := &resolvFile{path: path, backupPath: backup}
	if err := first.Install("127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash: a fresh process sees managed resolv.conf plus the durable
	// backup, and must never select its own loopback listener as an upstream.
	restarted := &resolvFile{path: path, backupPath: backup}
	if got := restarted.CurrentUpstreams(); len(got) != 1 || got[0] != "192.0.2.53:53" {
		t.Fatalf("recovered upstreams=%v", got)
	}
	if err := restarted.Install("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Restore(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(original) {
		t.Fatalf("restored resolv.conf=%q", got)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("backup remained after restore: %v", err)
	}
}

func TestResolvFilePreservesSystemLoopbackButExcludesStaleSelf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	_ = os.WriteFile(path, []byte("nameserver 127.0.0.1\nnameserver ::1\nnameserver 1.1.1.1\n"), 0o644)
	got := (&resolvFile{path: path}).CurrentUpstreams()
	if len(got) != 3 {
		t.Fatalf("upstreams=%v", got)
	}
	_ = os.WriteFile(path, []byte("# managed by ratelmeshd (MagicDNS); original backed up\nnameserver 127.0.0.53\n"), 0o644)
	if stale := (&resolvFile{path: path}).CurrentUpstreams(); len(stale) != 0 {
		t.Fatalf("stale self-upstream was accepted: %v", stale)
	}
}

func TestResolvFileRecognizesLegacyManagedMeshResolver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	backup := filepath.Join(dir, "resolv.conf.ratelmesh-backup")
	legacyMarker := "# " + "managed by h" + "bmd (MagicDNS); original backed up\n"
	if err := os.WriteFile(path, []byte(legacyMarker+"nameserver 100.64.0.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &resolvFile{path: path, backupPath: backup}
	if got := m.CurrentUpstreams(); len(got) != 0 {
		t.Fatalf("legacy mesh DNS became its own upstream: %v", got)
	}
	if err := m.Install("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("stale managed file persisted as original backup: %v", err)
	}
}
