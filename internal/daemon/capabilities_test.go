package daemon

import (
	"net/netip"
	"testing"

	"github.com/shan25519/ratelmesh/internal/types"
	"github.com/shan25519/ratelmesh/internal/wgengine"
)

type capabilityNAT struct {
	enabled  int
	disabled int
}

func (n *capabilityNAT) Enable(_, _ string) error { n.enabled++; return nil }
func (n *capabilityNAT) Disable() error           { n.disabled++; return nil }

func TestCloudExitCapabilityReconcilesNAT(t *testing.T) {
	d, err := New(Config{
		CoordURL: "https://control.example.com", StateDir: t.TempDir(),
		Role: types.RolePlain, Engine: wgengine.NewStub(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	nat := &capabilityNAT{}
	d.exitNAT = nat
	exitMap := types.Netmap{Version: 1, Self: types.Node{
		ID: "n-self", Key: d.PublicKey(), MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")},
		Role: types.RoleExit, Capabilities: types.NodeCapabilities{Exit: true},
	}}
	if err := d.applyNetmap(exitMap); err != nil {
		t.Fatal(err)
	}
	if nat.enabled != 1 || nat.disabled != 0 {
		t.Fatalf("exit grant NAT enable=%d disable=%d", nat.enabled, nat.disabled)
	}
	plainMap := exitMap
	plainMap.Version = 2
	plainMap.Self.Role = types.RolePlain
	plainMap.Self.Capabilities.Exit = false
	if err := d.applyNetmap(plainMap); err != nil {
		t.Fatal(err)
	}
	if nat.enabled != 1 || nat.disabled != 1 {
		t.Fatalf("exit revoke NAT enable=%d disable=%d", nat.enabled, nat.disabled)
	}
}
