package daemon

import (
	"net/netip"
	"testing"

	"github.com/shan25519/ratelmesh/internal/wgengine"
)

func TestCoordFrontDoorDerivation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		coordURL   string
		frontDoor  string
		wantAddr   string
		wantServer string
	}{
		{
			name:       "default: coordinator host on 443",
			coordURL:   "https://control.ratelmesh.com",
			wantAddr:   "control.ratelmesh.com:443",
			wantServer: "control.ratelmesh.com",
		},
		{
			name:       "explicit hostname front door names the TLS/ws identity",
			coordURL:   "https://control.ratelmesh.com",
			frontDoor:  "edge.example.net:443",
			wantAddr:   "edge.example.net:443",
			wantServer: "edge.example.net",
		},
		{
			name:       "bare-IP front door keeps the coordinator host as SNI",
			coordURL:   "https://control.ratelmesh.com",
			frontDoor:  "203.0.113.9:443",
			wantAddr:   "203.0.113.9:443",
			wantServer: "control.ratelmesh.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, server := coordFrontDoor(tc.coordURL, tc.frontDoor)
			if addr != tc.wantAddr || server != tc.wantServer {
				t.Fatalf("coordFrontDoor(%q,%q) = (%q,%q); want (%q,%q)",
					tc.coordURL, tc.frontDoor, addr, server, tc.wantAddr, tc.wantServer)
			}
		})
	}
}

// TestNewCoordClientPlainByDefault pins that the camouflage path is strictly
// opt-in: with no CoordTransport, a client is still built (plain HTTPS) and
// nothing panics.
func TestNewCoordClientPlainByDefault(t *testing.T) {
	if c := newCoordClient(Config{CoordURL: "https://control.ratelmesh.com"}); c == nil {
		t.Fatal("newCoordClient returned nil for the default (plain) path")
	}
	if c := newCoordClient(Config{
		CoordURL:       "https://control.ratelmesh.com",
		CoordTransport: "wss",
	}); c == nil {
		t.Fatal("newCoordClient returned nil for the wss path")
	}
}

// TestExitPhysicalEndpointsPinsFrontDoor proves that when the control plane rides
// a camouflage transport, the FRONT DOOR (what the socket actually dials) is
// pinned out of the exit — not just the coordinator host. Without this, a tunnel
// drop would sever the connection used to recover, since the coordinator IP the
// pin guards is never actually connected to.
func TestExitPhysicalEndpointsPinsFrontDoor(t *testing.T) {
	engine := wgengine.NewStub(nil)
	d, err := New(Config{
		CoordURL:       "https://control.ratelmesh.com",
		CoordTransport: "wss",
		CoordFrontDoor: "203.0.113.9:443", // IP literal → no DNS in the test
		StateDir:       t.TempDir(),
		Engine:         engine,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := netip.MustParseAddr("203.0.113.9")
	found := false
	for _, a := range d.exitPhysicalEndpoints(nil) {
		if a == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("front door %s was not pinned out of the exit: %v", want, d.exitPhysicalEndpoints(nil))
	}
}
