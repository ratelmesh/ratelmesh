package daemon

import (
	"strings"
	"testing"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

func TestSetExitRejectsKnownOfflinePeerWithoutChangingIntent(t *testing.T) {
	private, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		cfg:           Config{StateDir: t.TempDir()},
		preferredExit: "current-exit",
		lastNetmap: types.Netmap{Peers: []types.Node{{
			Key:    private.Public(),
			Name:   "offline-exit",
			Role:   types.RoleExit,
			Online: false,
		}}},
	}

	err = d.SetExit("offline-exit")
	if err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("SetExit error = %v, want an offline error", err)
	}
	d.mu.Lock()
	preferred := d.preferredExit
	d.mu.Unlock()
	if preferred != "current-exit" {
		t.Fatalf("preferred exit changed to %q", preferred)
	}
}
