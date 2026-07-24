//go:build wgreal && darwin

package wgengine

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateUtunDarwinManagedOwnsForegroundProcess(t *testing.T) {
	bin := t.TempDir()
	fake := filepath.Join(bin, "wireguard-go")
	script := `#!/bin/sh
test "$WG_PROCESS_FOREGROUND" = "1" || exit 41
printf 'utun-test' > "$WG_TUN_NAME_FILE"
trap 'exit 0' INT TERM
while :; do sleep 1; done
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	name, process, done, err := createUtunDarwinManaged(log)
	if err != nil {
		t.Fatalf("createUtunDarwinManaged: %v", err)
	}
	if name != "utun-test" || process == nil || done == nil {
		t.Fatalf("got name=%q process=%v done=%v", name, process, done)
	}

	if err := process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal managed process: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("managed process exit: %v", err)
		}
	case <-time.After(3 * time.Second):
		_ = process.Kill()
		t.Fatal("managed wireguard-go process did not exit after signal")
	}
}

func TestRecoverDataPlaneReplacesFailedUtunAndReplaysConfig(t *testing.T) {
	bin := t.TempDir()
	writeExecutable := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable("wireguard-go", `#!/bin/sh
test "$WG_PROCESS_FOREGROUND" = "1" || exit 41
printf 'utun-recovered' > "$WG_TUN_NAME_FILE"
trap 'exit 0' INT TERM
while :; do sleep 1; done
`)
	writeExecutable("wg", `#!/bin/sh
if test "$1" = "show" && test "$2" = "utun-old"; then exit 1; fi
exit 0
`)
	writeExecutable("ifconfig", "#!/bin/sh\nexit 0\n")
	writeExecutable("route", `#!/bin/sh
if test "$2" = "get"; then
  printf 'gateway: 192.0.2.1\ninterface: en0\n'
fi
exit 0
`)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	old := exec.Command("sleep", "30")
	if err := old.Start(); err != nil {
		t.Fatal(err)
	}
	oldDone := make(chan error, 1)
	go func() {
		oldDone <- old.Wait()
		close(oldDone)
	}()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &RealEngine{
		log:           log,
		up:            true,
		iface:         "utun-old",
		confDir:       t.TempDir(),
		darwinProcess: old.Process,
		darwinDone:    oldDone,
		cfg:           Config{ListenPort: 51820},
	}
	if err := e.RecoverDataPlane(); err != nil {
		t.Fatalf("RecoverDataPlane: %v", err)
	}
	if e.iface != "utun-recovered" || !e.up || e.darwinProcess == nil {
		t.Fatalf("recovered engine: iface=%q up=%v process=%v", e.iface, e.up, e.darwinProcess)
	}
	select {
	case <-oldDone:
	case <-time.After(3 * time.Second):
		t.Fatal("old wireguard-go process was not stopped")
	}
	if err := e.Down(); err != nil {
		t.Fatalf("Down after recovery: %v", err)
	}
}
