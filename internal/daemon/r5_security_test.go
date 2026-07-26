package daemon

import (
	"net/netip"
	"testing"

	"github.com/ratelmesh/ratelmesh/internal/sign"
	"github.com/ratelmesh/ratelmesh/internal/types"
	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

func TestTamperedSignedAllowedIPsAreDropped(t *testing.T) {
	authority, err := sign.GenerateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	engine := wgengine.NewStub(nil)
	d, err := New(Config{
		CoordURL: "https://coord.example", StateDir: t.TempDir(), Engine: engine,
		VerifyKey: authority.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	peerKey, _ := types.GenerateKey()
	peer := types.Node{
		ID: "n-peer", User: "user:peer@example.com", Name: "peer", Key: peerKey.Public(),
		Role: types.RolePlain, MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		AllowedIPs: []string{"100.64.0.3/32"},
	}
	peer.Sig = authority.Sign(peer)
	peer.RouteSig = authority.SignRoutes(peer)
	peer.AllowedIPs = append(peer.AllowedIPs, "0.0.0.0/0") // compromised-coord rewrite

	if err := d.applyNetmap(types.Netmap{
		Version: 1,
		Self:    types.Node{MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}},
		Peers:   []types.Node{peer},
	}); err != nil {
		t.Fatal(err)
	}
	if got := len(engine.LastConfig().Peers); got != 0 {
		t.Fatalf("programmed %d peers with tampered signed routes, want 0", got)
	}
}

func TestLegacyPeerWithoutRouteSignatureSurvivesRollingUpgrade(t *testing.T) {
	authority, err := sign.GenerateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	engine := wgengine.NewStub(nil)
	d, err := New(Config{
		CoordURL: "https://coord.example", StateDir: t.TempDir(), Engine: engine,
		VerifyKey: authority.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	peerKey, _ := types.GenerateKey()
	peer := types.Node{
		ID: "n-legacy", Name: "legacy-peer", Key: peerKey.Public(), Role: types.RolePlain,
		MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")}, AllowedIPs: []string{"100.64.0.3/32", "0.0.0.0/0"},
	}
	peer.Sig = authority.Sign(peer)
	if err := d.applyNetmap(types.Netmap{
		Version: 1, Self: types.Node{MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}},
		Peers: []types.Node{peer},
	}); err != nil {
		t.Fatal(err)
	}
	if got := len(engine.LastConfig().Peers); got != 1 {
		t.Fatalf("legacy signed peer count=%d, want 1", got)
	}
	allowed := engine.LastConfig().Peers[0].AllowedIPs
	if len(allowed) != 1 || allowed[0] != netip.MustParsePrefix("100.64.0.3/32") {
		t.Fatalf("legacy unsigned routes were not clamped: %v", allowed)
	}
}

func TestIPv4OnlyExitBlackholesPhysicalIPv6(t *testing.T) {
	engine := wgengine.NewStub(nil)
	d, err := New(Config{
		CoordURL: "https://coord.example", StateDir: t.TempDir(), Engine: engine,
		KillSwitch: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	d.preferredExit = "tokyo"
	exitKey, _ := types.GenerateKey()
	if err := d.applyNetmap(types.Netmap{
		Version: 1,
		Self:    types.Node{MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}},
		Peers: []types.Node{{
			ID: "n-exit", Name: "tokyo", Key: exitKey.Public(), Role: types.RoleExit,
			MeshIPs:    []netip.Addr{netip.MustParseAddr("100.64.0.3")},
			AllowedIPs: []string{"100.64.0.3/32", "0.0.0.0/0"},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	want := map[netip.Prefix]bool{
		netip.MustParsePrefix("::/1"):     false,
		netip.MustParsePrefix("8000::/1"): false,
	}
	for _, prefix := range engine.LastConfig().BlockRoutes {
		if _, ok := want[prefix]; ok {
			want[prefix] = true
		}
	}
	for prefix, found := range want {
		if !found {
			t.Fatalf("IPv4-only exit did not block physical IPv6 route %s: %v", prefix, engine.LastConfig().BlockRoutes)
		}
	}
}
