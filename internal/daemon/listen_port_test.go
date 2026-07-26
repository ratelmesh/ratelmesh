package daemon

import (
	"testing"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

func TestDeviceListenPortIsStableAndDeviceSpecific(t *testing.T) {
	keyA := types.Key{1}
	keyB := types.Key{2}

	portA := deviceListenPort(keyA)
	if again := deviceListenPort(keyA); again != portA {
		t.Fatalf("listen port changed: %d != %d", portA, again)
	}
	if portA < autoListenPortMin || portA > autoListenPortMax {
		t.Fatalf("listen port %d outside automatic range", portA)
	}
	if portB := deviceListenPort(keyB); portB == portA {
		t.Fatalf("test identities mapped to the same port %d", portA)
	}
}

func TestNewSelectsStablePortUnlessExplicitlyOverridden(t *testing.T) {
	dir := t.TempDir()
	first, err := New(Config{CoordURL: "https://coord.example", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(Config{CoordURL: "https://coord.example", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if first.cfg.ListenPort != second.cfg.ListenPort {
		t.Fatalf("port did not persist with identity: %d != %d", first.cfg.ListenPort, second.cfg.ListenPort)
	}
	if first.cfg.ListenPort < autoListenPortMin || first.cfg.ListenPort > autoListenPortMax {
		t.Fatalf("automatic port %d outside range", first.cfg.ListenPort)
	}

	const explicit = uint16(43123)
	overridden, err := New(Config{CoordURL: "https://coord.example", StateDir: t.TempDir(), ListenPort: explicit})
	if err != nil {
		t.Fatal(err)
	}
	if overridden.cfg.ListenPort != explicit {
		t.Fatalf("explicit port = %d, want %d", overridden.cfg.ListenPort, explicit)
	}
}
