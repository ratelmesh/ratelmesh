package daemon

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/netguard"
	"github.com/ratelmesh/ratelmesh/internal/types"
	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

type gatedTestEngine struct {
	*wgengine.StubEngine
	statsErr error
}

func (*gatedTestEngine) RequiresExitHandshake() bool { return true }

func (e *gatedTestEngine) PeerStats() (map[types.Key]wgengine.PeerStat, error) {
	if e.statsErr != nil {
		return nil, e.statsErr
	}
	return e.StubEngine.PeerStats()
}

func TestPhysicalTransportAddrsRejectsMeshCandidates(t *testing.T) {
	got := physicalTransportAddrs([]string{
		"100.64.0.3:51820",
		"198.51.100.44:53168",
		"[2001:db8::44]:53168",
	})
	if slices.Contains(got, netip.MustParseAddr("100.64.0.3")) {
		t.Fatalf("physical pins contain inner Mesh address: %v", got)
	}
	for _, want := range []netip.Addr{
		netip.MustParseAddr("198.51.100.44"),
		netip.MustParseAddr("2001:db8::44"),
	} {
		if !slices.Contains(got, want) {
			t.Errorf("physical pins %v missing transport %s", got, want)
		}
	}
}

func TestClearExitPersistsDirectBeforeWaitingForRouteApply(t *testing.T) {
	dir := t.TempDir()
	d, err := New(Config{
		CoordURL: "https://203.0.113.10",
		StateDir: dir,
		Engine:   wgengine.NewStub(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	d.preferredExit = "tokyo"
	if err := savePreferredExit(dir, "tokyo"); err != nil {
		t.Fatal(err)
	}

	// Model a wedged route apply. ClearExit must record DIRECT before it waits,
	// so a forced daemon restart cannot restore the old EXIT preference.
	d.applyMu.Lock()
	done := make(chan error, 1)
	go func() { done <- d.ClearExit() }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		st, loadErr := loadOrCreateState(dir)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if st.PreferredExit == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DIRECT intent was not persisted while route apply was blocked")
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.applyMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExitWaitsForHandshakeAndPinsBootstrapEndpoints(t *testing.T) {
	eng := &gatedTestEngine{StubEngine: wgengine.NewStub(nil)}
	guard := netguard.NewStubEnforcer(nil)
	d, err := New(Config{
		CoordURL: "https://203.0.113.10", StateDir: t.TempDir(), Engine: eng,
		RelayAddr:  "198.51.100.21:443|wss|relay.example",
		KillSwitch: true, Enforcer: guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	d.preferredExit = "tokyo"
	d.relayAddr = netip.MustParseAddrPort("198.51.100.20:443")

	exitPriv, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	exitKey := exitPriv.Public()
	peerPriv, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerKey := peerPriv.Public()
	nm := types.Netmap{
		Version: 1,
		Self: types.Node{
			MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		},
		Peers: []types.Node{{
			Name:       "tokyo",
			Key:        exitKey,
			Role:       types.RoleExit,
			MeshIPs:    []netip.Addr{netip.MustParseAddr("100.64.0.3")},
			Endpoints:  []string{"192.0.2.30:51820"},
			AllowedIPs: []string{"100.64.0.3/32", "0.0.0.0/0", "::/0"},
		}, {
			Name:       "remote-mac",
			Key:        peerKey,
			MeshIPs:    []netip.Addr{netip.MustParseAddr("100.64.0.4")},
			Endpoints:  []string{"198.51.100.44:53168"},
			AllowedIPs: []string{"100.64.0.4/32"},
		}},
	}
	liveRoamedEndpoint := netip.MustParseAddrPort("203.0.113.44:61234")
	eng.SetPeerStat(peerKey, wgengine.PeerStat{Endpoint: liveRoamedEndpoint})

	// A new exit selection is staged without defaults until WireGuard proves
	// that the direct/relay path can handshake.
	if err := d.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	if peerHasDefault(eng.LastConfig().Peers[0]) {
		t.Fatal("default route installed before the exit handshake")
	}
	if !guard.Current().Enabled {
		t.Fatal("kill switch must arm while the selected exit waits for a handshake")
	}
	if !slices.Contains(guard.Current().TunnelEndpoints, netip.MustParseAddrPort("198.51.100.44:53168")) {
		t.Fatalf("kill switch omitted ordinary Mesh peer transport: %v", guard.Current().TunnelEndpoints)
	}
	if !slices.Contains(guard.Current().TunnelEndpoints, liveRoamedEndpoint) {
		t.Fatalf("kill switch omitted WireGuard's authenticated roamed endpoint: %v", guard.Current().TunnelEndpoints)
	}
	if got := len(guard.Current().TunnelEndpoints); got != 3 {
		t.Fatalf("kill switch endpoints were not deduplicated: %v", guard.Current().TunnelEndpoints)
	}
	if st := d.Status(); st.SelectedExit != "tokyo" || st.ActiveExit != "" {
		t.Fatalf("staged exit status = %+v, want selected only", st)
	}

	now := time.Now()
	eng.SetPeerStat(exitKey, wgengine.PeerStat{LatestHandshake: now, RxBytes: 1})
	if name, ready, changed := d.checkExitRouteTransition(map[types.Key]wgengine.PeerStat{
		exitKey: {LatestHandshake: now, RxBytes: 1},
	}, now); name != "tokyo" || !ready || !changed {
		t.Fatalf("ready transition = (%q, %v, %v)", name, ready, changed)
	}
	if err := d.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	if st := d.Status(); st.SelectedExit != "tokyo" || st.ActiveExit != "tokyo" {
		t.Fatalf("active exit status = %+v, want selected and active", st)
	}
	cfg := eng.LastConfig()
	if !peerHasDefault(cfg.Peers[0]) {
		t.Fatal("default route not installed after a fresh exit handshake")
	}
	for _, want := range []netip.Addr{
		netip.MustParseAddr("203.0.113.10"),
		netip.MustParseAddr("203.0.113.44"),
		netip.MustParseAddr("198.51.100.44"),
		netip.MustParseAddr("198.51.100.20"),
		netip.MustParseAddr("198.51.100.21"),
	} {
		if !containsAddr(cfg.PhysicalEndpoints, want) {
			t.Errorf("bootstrap pins %v missing %s", cfg.PhysicalEndpoints, want)
		}
	}

	// Availability mode keeps the working exit, but disarms fail-closed pf/WFP.
	if err := d.SetInternetFallback(true); err != nil {
		t.Fatal(err)
	}
	if d.Status().KillSwitch || !d.Status().InternetFallback {
		t.Fatalf("fallback status = %+v", d.Status())
	}
	if guard.Current().Enabled {
		t.Fatal("internet fallback left the kill switch armed")
	}
	if !peerHasDefault(eng.LastConfig().Peers[0]) {
		t.Fatal("enabling fallback unnecessarily removed a healthy exit")
	}

	// An idle tunnel is still healthy while its current-path handshake is fresh.
	// RX counters advance only when applications exchange data; treating silence
	// as failure caused a working EXIT to flap back to DIRECT every 20 seconds.
	d.mu.Lock()
	d.rxProgress[exitKey] = now.Add(-livenessWindow - time.Second)
	d.lastRx[exitKey] = 1
	d.mu.Unlock()
	idleAt := now.Add(livenessWindow + 2*time.Second)
	if _, ready, changed := d.checkExitRouteTransition(map[types.Key]wgengine.PeerStat{
		exitKey: {LatestHandshake: idleAt, RxBytes: 1},
	}, idleAt); !ready || changed {
		t.Fatalf("idle fresh-handshake transition = (ready=%v, changed=%v)", ready, changed)
	}

	// Three consecutive data-plane failures withdraw the dead full-tunnel route,
	// allowing the physical default route to carry internet traffic again.
	eng.statsErr = errors.New("wg unavailable")
	for range dataPlaneRecoveryThreshold {
		d.recordDataPlaneHealth(eng.statsErr)
	}
	if peerHasDefault(eng.LastConfig().Peers[0]) {
		t.Fatal("internet fallback retained default routes after data-plane failure")
	}
	eng.statsErr = nil
	recoveryAt := idleAt.Add(2 * time.Second)
	eng.SetPeerStat(exitKey, wgengine.PeerStat{LatestHandshake: recoveryAt, RxBytes: 3})
	if _, ready, changed := d.checkExitRouteTransition(map[types.Key]wgengine.PeerStat{
		exitKey: {LatestHandshake: recoveryAt, RxBytes: 3},
	}, recoveryAt); !ready || !changed {
		t.Fatalf("data-plane recovery transition = (ready=%v, changed=%v)", ready, changed)
	}
	if err := d.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	if !peerHasDefault(eng.LastConfig().Peers[0]) {
		t.Fatal("fresh handshake did not restore the preferred exit after fallback")
	}

	// A stale handshake removes defaults again, but the kill switch remains
	// disarmed in availability mode so direct internet remains usable.
	stale := now.Add(-exitHandshakeFresh - time.Second)
	eng.SetPeerStat(exitKey, wgengine.PeerStat{LatestHandshake: stale, RxBytes: 1})
	if _, ready, changed := d.checkExitRouteTransition(map[types.Key]wgengine.PeerStat{
		exitKey: {LatestHandshake: stale, RxBytes: 1},
	}, now); ready || !changed {
		t.Fatalf("stale transition = (ready=%v, changed=%v)", ready, changed)
	}
	if err := d.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	if peerHasDefault(eng.LastConfig().Peers[0]) {
		t.Fatal("stale exit handshake retained a default route")
	}
	if guard.Current().Enabled {
		t.Fatal("internet fallback armed fail-closed protection")
	}
}

func peerHasDefault(peer wgengine.Peer) bool {
	for _, prefix := range peer.AllowedIPs {
		if prefix.Bits() == 0 {
			return true
		}
	}
	return false
}

func containsAddr(addrs []netip.Addr, want netip.Addr) bool {
	for _, addr := range addrs {
		if addr == want {
			return true
		}
	}
	return false
}
