package wgengine

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/shan25519/ratelmesh/internal/types"
)

func TestPlanWindowsRoutesForFullTunnel(t *testing.T) {
	cfg := Config{
		Peers: []Peer{
			{
				Endpoints:  []string{"203.0.113.7:51820"},
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
			{
				Endpoints:  []string{"198.51.100.9:51820"},
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")},
			},
		},
		DirectRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		BlockRoutes:  []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")},
		PhysicalEndpoints: []netip.Addr{
			netip.MustParseAddr("192.0.2.44"),
			netip.MustParseAddr("203.0.113.7"), // duplicate of the exit endpoint
		},
	}

	got := planWindowsRoutes(cfg)
	if !got.hasDefault {
		t.Fatal("full-tunnel peer was not detected")
	}
	if len(got.direct) != 1 || got.direct[0] != cfg.DirectRoutes[0] {
		t.Fatalf("direct routes = %v", got.direct)
	}
	if len(got.block) != 1 || got.block[0] != cfg.BlockRoutes[0] {
		t.Fatalf("block routes = %v", got.block)
	}
	// Only the default-route peer's endpoint is pinned to the physical path;
	// mesh-only peers never need (or get) a pin.
	if len(got.pins) != 2 || got.pins[0] != netip.MustParseAddr("203.0.113.7") || got.pins[1] != netip.MustParseAddr("192.0.2.44") {
		t.Fatalf("endpoint pins = %v, want deduped exit + bootstrap endpoints", got.pins)
	}
}

func TestPlanWindowsRoutesDedupsAndSkipsUnparseablePins(t *testing.T) {
	cfg := Config{
		Peers: []Peer{
			{
				Endpoints:  []string{"203.0.113.7:51820"},
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
			{
				Endpoints:  []string{"203.0.113.7:443"}, // same host, different port
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
			{
				Endpoints:  []string{"not-an-endpoint"},
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
		},
	}
	got := planWindowsRoutes(cfg)
	if len(got.pins) != 1 {
		t.Fatalf("endpoint pins = %v, want one deduped pin", got.pins)
	}
}

func TestPlanWindowsRoutesIgnoresOverridesWithoutExit(t *testing.T) {
	cfg := Config{
		Peers: []Peer{{
			Endpoints:  []string{"not-an-endpoint"},
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")},
		}},
		DirectRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		BlockRoutes:  []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")},
	}

	got := planWindowsRoutes(cfg)
	if got.hasDefault || len(got.direct) != 0 || len(got.block) != 0 {
		t.Fatalf("unexpected route plan without exit: %+v", got)
	}
}

func TestWindowsTunnelConfigSplitsIPv4Default(t *testing.T) {
	cfg := Config{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")},
		Peers: []Peer{{
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.9/32"),
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
		}},
	}

	got := windowsTunnelConfig(cfg)
	for _, want := range []string{"Address = 100.64.0.5/32", "100.64.0.9/32", "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		if !strings.Contains(got, want) {
			t.Errorf("Windows config missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "0.0.0.0/0") {
		t.Fatalf("Windows config retained IPv4 /0 kill-switch trigger:\n%s", got)
	}
	if strings.Contains(got, "::/0") {
		t.Fatalf("Windows config retained IPv6 /0 kill-switch trigger:\n%s", got)
	}
	if cfg.Peers[0].AllowedIPs[1].String() != "0.0.0.0/0" {
		t.Fatalf("rendering mutated source config: %v", cfg.Peers[0].AllowedIPs)
	}
}

func TestWindowsTunnelConfigPreservesDefaultsForKillSwitch(t *testing.T) {
	cfg := Config{
		KillSwitch: true,
		Peers: []Peer{{AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}}},
	}

	got := windowsTunnelConfig(cfg)
	if !strings.Contains(got, "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Fatalf("kill-switch config did not preserve /0 defaults:\n%s", got)
	}
	for _, split := range []string{"0.0.0.0/1", "128.0.0.0/1", "8000::/1"} {
		if strings.Contains(got, split) {
			t.Fatalf("kill-switch config unexpectedly contains %s:\n%s", split, got)
		}
	}
}

func TestWindowsTunnelConfigIncludesMagicDNS(t *testing.T) {
	cfg := Config{
		DNSServers: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Peers:      []Peer{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")}}},
	}

	if got := windowsTunnelConfig(cfg); !strings.Contains(got, "DNS = 127.0.0.1") {
		t.Fatalf("Windows config does not install MagicDNS on the tunnel adapter:\n%s", got)
	}
}

func testWindowsBaseConfig(t *testing.T) Config {
	t.Helper()
	priv, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	exitKey, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		PrivateKey: priv,
		ListenPort: 51820,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")},
		Peers: []Peer{
			{
				PublicKey:  exitKey.Public(),
				Endpoints:  []string{"203.0.113.7:51820"},
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.6/32"), netip.MustParsePrefix("0.0.0.0/0")},
			},
			{
				PublicKey:  peerKey.Public(),
				Endpoints:  []string{"198.51.100.9:51820"},
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")},
			},
		},
	}
}

func TestWindowsReconfigureUnchangedSkipsIdenticalSnapshots(t *testing.T) {
	prev := testWindowsBaseConfig(t)
	next := testWindowsBaseConfig(t)
	next.PrivateKey = prev.PrivateKey
	next.Peers = append([]Peer(nil), prev.Peers...)

	if !windowsReconfigureUnchanged(prev, next) {
		t.Fatal("identical snapshots should be reported unchanged")
	}
	next.Peers = append([]Peer(nil), prev.Peers...)
	next.Peers[1].Endpoints = []string{"198.51.100.10:51820"}
	if windowsReconfigureUnchanged(prev, next) {
		t.Fatal("an endpoint change must not be reported unchanged")
	}
}

func TestWindowsSyncconfSufficient(t *testing.T) {
	base := testWindowsBaseConfig(t)
	clonePeers := func() []Peer {
		out := make([]Peer, len(base.Peers))
		copy(out, base.Peers)
		return out
	}

	// A mesh peer roaming to a new endpoint is exactly what syncconf handles.
	next := base
	next.Peers = clonePeers()
	next.Peers[1].Endpoints = []string{"198.51.100.10:51820"}
	if !windowsSyncconfSufficient(base, next) {
		t.Fatal("non-exit endpoint roam should be syncconf-able")
	}

	// The exit peer's endpoint is host-route pinned, but the engine now stages
	// the replacement pin before applying the endpoint with syncconf.
	next = base
	next.Peers = clonePeers()
	next.Peers[0].Endpoints = []string{"203.0.113.99:51820"}
	if !windowsSyncconfSufficient(base, next) {
		t.Fatal("default-route peer endpoint roam should be syncconf-able")
	}

	next = base
	next.Peers = clonePeers()
	next.PhysicalEndpoints = []netip.Addr{netip.MustParseAddr("192.0.2.44")}
	if !windowsSyncconfSufficient(base, next) {
		t.Fatal("physical endpoint refresh should be syncconf-able")
	}

	// AllowedIPs drive the service's routes: never syncconf them.
	next = base
	next.Peers = clonePeers()
	next.Peers[1].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")}
	if windowsSyncconfSufficient(base, next) {
		t.Fatal("AllowedIPs change must force a reinstall")
	}

	// Peer set changes add/remove routes.
	next = base
	next.Peers = clonePeers()[:1]
	if windowsSyncconfSufficient(base, next) {
		t.Fatal("peer removal must force a reinstall")
	}

	// Kill-switch mode flips the /0-vs-/1 rendering: reinstall.
	next = base
	next.Peers = clonePeers()
	next.KillSwitch = true
	if windowsSyncconfSufficient(base, next) {
		t.Fatal("kill-switch change must force a reinstall")
	}
}
