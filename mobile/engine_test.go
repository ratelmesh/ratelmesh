package mobile

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/ratelmesh/ratelmesh/internal/types"
	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

func TestBindingEngineExportsNativeTunnelContract(t *testing.T) {
	priv, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPriv, _ := types.GenerateKey()
	e := newBindingEngine([]string{"1.1.1.1", "2606:4700:4700::1111"})
	if err := e.Up(); err != nil {
		t.Fatal(err)
	}
	if err := e.Reconfigure(wgengine.Config{
		PrivateKey: priv,
		ListenPort: 51820,
		KillSwitch: true,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.64.0.8/32")},
		Peers: []wgengine.Peer{{
			PublicKey: peerPriv.Public(), Endpoints: []string{"203.0.113.7:51820"},
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Keepalive: 25,
		}},
		DirectRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		BlockRoutes:  []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}); err != nil {
		t.Fatal(err)
	}

	var got tunnelConfig
	if err := json.Unmarshal([]byte(e.configJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Active || got.PrivateKey != priv.String() || got.ListenPort != 51820 || !got.KillSwitch {
		t.Fatalf("unexpected interface config: %+v", got)
	}
	if len(got.Addresses) != 1 || got.Addresses[0] != "100.64.0.8/32" {
		t.Fatalf("addresses = %v", got.Addresses)
	}
	if len(got.Peers) != 1 || got.Peers[0].Endpoint != "203.0.113.7:51820" || got.Peers[0].PersistentKeepalive != 25 {
		t.Fatalf("peers = %+v", got.Peers)
	}
	if len(got.DNSServers) != 2 || len(got.DirectRoutes) != 1 || len(got.BlockRoutes) != 1 {
		t.Fatalf("policy metadata missing: %+v", got)
	}
	statsJSON := `[{"publicKey":"` + peerPriv.Public().String() + `","latestHandshakeUnix":1234,"rxBytes":99}]`
	if err := e.updateStatsJSON(statsJSON); err != nil {
		t.Fatal(err)
	}
	stats, err := e.PeerStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats[peerPriv.Public()].RxBytes != 99 || stats[peerPriv.Public()].LatestHandshake.Unix() != 1234 {
		t.Fatalf("native stats were not imported: %+v", stats)
	}
	beforeDown := e.configVersion()
	if err := e.Down(); err != nil {
		t.Fatal(err)
	}
	if e.configVersion() <= beforeDown {
		t.Fatal("tunnel version did not advance on shutdown")
	}
	if err := json.Unmarshal([]byte(e.configJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Active || got.PrivateKey != "" || len(got.Peers) != 0 {
		t.Fatalf("inactive config leaked tunnel secrets/state: %+v", got)
	}
}

func TestNewAppWithOptionsRejectsInvalidInput(t *testing.T) {
	if _, err := NewAppWithOptions(`{"coordURL":`); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if _, err := NewAppWithOptions(`{"coordURL":"https://coord.example","stateDir":"/tmp/ratelmesh","listenPort":70000}`); err == nil {
		t.Fatal("invalid listenPort accepted")
	}
	if _, err := NewAppWithOptions(`{"coordURL":"https://coord.example","stateDir":"/tmp/ratelmesh","endpoints":["not-an-endpoint"]}`); err == nil {
		t.Fatal("invalid endpoint candidate accepted")
	}
}

func TestBindingEngineSkipsIdenticalTunnelSnapshot(t *testing.T) {
	e := newBindingEngine(nil)
	if err := e.Up(); err != nil {
		t.Fatal(err)
	}
	cfg := wgengine.Config{
		PrivateKey: types.Key{1},
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")},
		Peers: []wgengine.Peer{{
			PublicKey:  types.Key{2},
			Endpoints:  []string{"203.0.113.7:51820"},
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		}},
	}
	if err := e.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	version := e.configVersion()
	if err := e.Reconfigure(cloneEngineConfig(cfg)); err != nil {
		t.Fatal(err)
	}
	if got := e.configVersion(); got != version {
		t.Fatalf("identical snapshot bumped version from %d to %d", version, got)
	}

	changed := cloneEngineConfig(cfg)
	changed.Peers[0].Endpoints = []string{"198.51.100.8:51820"}
	if err := e.Reconfigure(changed); err != nil {
		t.Fatal(err)
	}
	if got := e.configVersion(); got != version+1 {
		t.Fatalf("endpoint change version = %d, want %d", got, version+1)
	}
}
