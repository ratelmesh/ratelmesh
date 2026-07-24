package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/magicsock"
	"github.com/ratelmesh/ratelmesh/internal/netguard"
	"github.com/ratelmesh/ratelmesh/internal/types"
	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

type recoveryEngine struct {
	recoveries        int
	networkRecoveries int
	enabled           bool
	name              string
	nextName          string
	probeErr          error
	networkRecovered  chan struct{}
}

type silentRecoveryEngine struct {
	*gatedTestEngine
	networkRecoveries int
}

func (*silentRecoveryEngine) DataPlaneRecoveryEnabled() bool { return true }
func (*silentRecoveryEngine) RecoverDataPlane() error        { return nil }
func (e *silentRecoveryEngine) RecoverNetworkPath() error {
	e.networkRecoveries++
	return nil
}

func (*recoveryEngine) Up() error                         { return nil }
func (*recoveryEngine) Reconfigure(wgengine.Config) error { return nil }
func (*recoveryEngine) Peers() []types.Key                { return nil }
func (*recoveryEngine) Down() error                       { return nil }
func (*recoveryEngine) Close() error                      { return nil }
func (e *recoveryEngine) DataPlaneRecoveryEnabled() bool  { return e.enabled }
func (e *recoveryEngine) RecoverDataPlane() error {
	e.recoveries++
	if e.nextName != "" {
		e.name = e.nextName
	}
	return nil
}
func (e *recoveryEngine) RecoverNetworkPath() error {
	e.networkRecoveries++
	if e.networkRecovered != nil {
		select {
		case e.networkRecovered <- struct{}{}:
		default:
		}
	}
	if e.nextName != "" {
		e.name = e.nextName
	}
	return nil
}
func (e *recoveryEngine) InterfaceName() string { return e.name }
func (e *recoveryEngine) ProbeEndpoint(context.Context, netip.AddrPort) error {
	return e.probeErr
}

func TestControlRetryKeepsAppliedTunnelRunning(t *testing.T) {
	d := &Daemon{state: StateStarting, status: Status{State: StateStarting}}
	d.markControlRetrying()
	if got := d.Status().State; got != StateStarting {
		t.Fatalf("before first netmap state = %s, want Starting", got)
	}

	d.lastNetmap.Version = 7
	d.markControlRetrying()
	if got := d.Status().State; got != StateRunning {
		t.Fatalf("after applied netmap state = %s, want Running", got)
	}
}

func TestRepeatedDataPlaneFailuresTriggerOneRecovery(t *testing.T) {
	engine := &recoveryEngine{enabled: true}
	d := &Daemon{
		engine:     engine,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		lastNetmap: types.Netmap{Version: 9},
	}
	healthErr := errors.New("wg show failed")

	for range dataPlaneRecoveryThreshold - 1 {
		d.recordDataPlaneHealth(healthErr)
	}
	if engine.recoveries != 0 {
		t.Fatalf("recoveries before threshold = %d, want 0", engine.recoveries)
	}
	d.recordDataPlaneHealth(healthErr)
	if engine.recoveries != 1 {
		t.Fatalf("recoveries at threshold = %d, want 1", engine.recoveries)
	}

	// A successful health check resets the next failure window.
	d.recordDataPlaneHealth(nil)
	d.recordDataPlaneHealth(healthErr)
	d.recordDataPlaneHealth(healthErr)
	if engine.recoveries != 1 {
		t.Fatalf("recoveries after reset and two failures = %d, want 1", engine.recoveries)
	}
}

func TestNetworkPathBindingFailureForcesRecovery(t *testing.T) {
	engine := &recoveryEngine{enabled: true}
	d := &Daemon{
		engine:     engine,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		lastNetmap: types.Netmap{Version: 9},
	}
	pathErr := fmt.Errorf("send endpoint probe: %w", syscall.EADDRNOTAVAIL)
	if !isLocalSocketBindingError(pathErr) {
		t.Fatal("wrapped EADDRNOTAVAIL was not recognized")
	}
	d.recoverNetworkPath(pathErr)
	if engine.networkRecoveries != 1 {
		t.Fatalf("network recoveries = %d, want 1", engine.networkRecoveries)
	}
	if isLocalSocketBindingError(context.DeadlineExceeded) {
		t.Fatal("ordinary candidate timeout was treated as a dead local socket")
	}
}

func TestSilentExitRecoveryStagesRoutesAndRequiresNewHandshake(t *testing.T) {
	stub := wgengine.NewStub(nil)
	engine := &silentRecoveryEngine{gatedTestEngine: &gatedTestEngine{StubEngine: stub}}
	guard := netguard.NewStubEnforcer(nil)
	d, err := New(Config{
		CoordURL: "https://203.0.113.10", StateDir: t.TempDir(),
		Engine: engine, KillSwitch: true, Enforcer: guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	exitPriv, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	exitKey := exitPriv.Public()
	d.preferredExit = "home-exit"
	nm := types.Netmap{
		Version: 1,
		Self: types.Node{
			MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		},
		Peers: []types.Node{{
			Name:       "home-exit",
			Key:        exitKey,
			Role:       types.RoleExit,
			MeshIPs:    []netip.Addr{netip.MustParseAddr("100.64.0.3")},
			Endpoints:  []string{"192.0.2.30:51820"},
			AllowedIPs: []string{"100.64.0.3/32", "0.0.0.0/0", "::/0"},
		}},
	}
	now := time.Now()
	stub.SetPeerStat(exitKey, wgengine.PeerStat{LatestHandshake: now, RxBytes: 100, TxBytes: 100})
	if err := d.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	if !peerHasDefault(stub.LastConfig().Peers[0]) {
		t.Fatal("test setup did not activate the exit")
	}

	d.recoverSilentExitPath(now)
	if engine.networkRecoveries != 1 {
		t.Fatalf("network recoveries = %d, want 1", engine.networkRecoveries)
	}
	if peerHasDefault(stub.LastConfig().Peers[0]) {
		t.Fatal("silent-path rebuild retained full-tunnel routes before a new handshake")
	}
	if !guard.Current().Enabled {
		t.Fatal("silent-path rebuild disarmed the fail-closed kill switch")
	}

	recoveredAt := now.Add(3 * time.Second)
	stub.SetPeerStat(exitKey, wgengine.PeerStat{
		LatestHandshake: recoveredAt, RxBytes: 101, TxBytes: 101,
	})
	if err := d.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	if !peerHasDefault(stub.LastConfig().Peers[0]) {
		t.Fatal("new handshake did not restore full-tunnel routes")
	}
}

func TestExactSocketProbeRecoversDeadBinding(t *testing.T) {
	priv, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	recovered := make(chan struct{}, 1)
	engine := &recoveryEngine{
		probeErr:         fmt.Errorf("send endpoint probe: %w", syscall.EADDRNOTAVAIL),
		networkRecovered: recovered,
	}
	d := &Daemon{
		engine:     engine,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		lastNetmap: types.Netmap{Version: 9},
		probing:    make(map[types.Key]bool),
		pathType:   make(map[types.Key]string),
	}
	peerPath := magicsock.NewPeerPath(priv.Public())
	target := netip.MustParseAddrPort("198.51.100.8:51820")
	d.startExactSocketProbe(priv.Public(), peerPath, []netip.AddrPort{target}, engine)
	select {
	case <-recovered:
	case <-time.After(2 * time.Second):
		t.Fatal("dead exact-socket binding did not trigger network recovery")
	}
}

func TestDataPlaneRecoveryRequiresAppliedNetmapAndSupport(t *testing.T) {
	healthErr := errors.New("wg show failed")
	for _, tc := range []struct {
		name    string
		version uint64
		enabled bool
	}{
		{name: "no netmap", enabled: true},
		{name: "recovery disabled", version: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := &recoveryEngine{enabled: tc.enabled}
			d := &Daemon{
				engine:     engine,
				log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
				lastNetmap: types.Netmap{Version: tc.version},
			}
			for range dataPlaneRecoveryThreshold {
				d.recordDataPlaneHealth(healthErr)
			}
			if engine.recoveries != 0 {
				t.Fatalf("recoveries = %d, want 0", engine.recoveries)
			}
		})
	}
}

func TestDataPlaneRecoveryRepinsKillSwitchInterface(t *testing.T) {
	exitPrivate, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	engine := &recoveryEngine{enabled: true, name: "utun4", nextName: "utun9"}
	guard := netguard.NewStubEnforcer(nil)
	d := &Daemon{
		cfg:    Config{CoordURL: "https://203.0.113.10", KillSwitch: true},
		engine: engine,
		guard:  guard,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		lastNetmap: types.Netmap{Version: 9, Peers: []types.Node{{
			Name: "tokyo", Role: types.RoleExit, Key: exitPrivate.Public(),
			Endpoints: []string{"198.51.100.8:51820"},
		}}},
		preferredExit: "tokyo",
		status:        Status{KillSwitch: true},
	}
	for range dataPlaneRecoveryThreshold {
		d.recordDataPlaneHealth(errors.New("wg show failed"))
	}
	if got := guard.Current().TunnelInterface; got != "utun9" {
		t.Fatalf("recovered kill switch interface = %q, want utun9", got)
	}
	if !d.Status().KillSwitch {
		t.Fatal("status lost armed kill switch after successful recovery")
	}
}

type failingReconfigureEngine struct{}

func (*failingReconfigureEngine) Up() error { return nil }
func (*failingReconfigureEngine) Reconfigure(wgengine.Config) error {
	return errors.New("route apply failed")
}
func (*failingReconfigureEngine) Peers() []types.Key { return nil }
func (*failingReconfigureEngine) Down() error        { return nil }
func (*failingReconfigureEngine) Close() error       { return nil }

func TestFailedNetmapApplyDoesNotCommitDaemonState(t *testing.T) {
	d, err := New(Config{
		CoordURL: "http://127.0.0.1:8080", StateDir: t.TempDir(), Hostname: "client",
		Engine: &failingReconfigureEngine{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	oldExit, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newExit, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	d.lastNetmap = types.Netmap{Version: 4}
	d.exitPeerKey = oldExit.Public()
	d.exitRouted = true
	d.preferredExit = "tokyo"
	d.status = Status{Version: 4, ActiveExit: "old"}
	d.epSeen[newExit.Public()] = "198.51.100.1:51820"
	d.relayed[newExit.Public()] = true
	d.directSince[newExit.Public()] = time.Now()

	err = d.applyNetmap(types.Netmap{Version: 5, Peers: []types.Node{{
		Name: "tokyo", Role: types.RoleExit, Key: newExit.Public(),
		Endpoints: []string{"198.51.100.9:51820"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"},
	}}})
	if err == nil {
		t.Fatal("netmap apply unexpectedly succeeded")
	}
	if d.lastNetmap.Version != 4 || d.status.Version != 4 {
		t.Fatalf("failed apply advanced versions: netmap=%d status=%d", d.lastNetmap.Version, d.status.Version)
	}
	if d.exitPeerKey != oldExit.Public() || !d.exitRouted {
		t.Fatal("failed apply committed candidate exit state")
	}
	if d.epSeen[newExit.Public()] != "198.51.100.1:51820" || !d.relayed[newExit.Public()] {
		t.Fatal("failed apply committed candidate endpoint/fallback state")
	}
	if _, ok := d.directSince[newExit.Public()]; !ok {
		t.Fatal("failed apply cleared live path timing state")
	}
}

func TestNetmapVersionCannotRollbackOrEquivocate(t *testing.T) {
	d, err := New(Config{
		CoordURL: "http://127.0.0.1:1", StateDir: t.TempDir(), Hostname: "client",
		Engine: wgengine.NewStub(nil), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	base := types.Netmap{Version: 9, Self: types.Node{Name: "client"}}
	if err := d.applyNetmap(base); err != nil {
		t.Fatal(err)
	}
	if err := d.applyNetmap(types.Netmap{Version: 8}); !errors.Is(err, ErrNetmapRollback) {
		t.Fatalf("rollback error = %v, want ErrNetmapRollback", err)
	}
	conflict := base
	conflict.Self.Name = "attacker"
	if err := d.applyNetmap(conflict); !errors.Is(err, ErrNetmapEquivocation) {
		t.Fatalf("equivocation error = %v, want ErrNetmapEquivocation", err)
	}
	if d.lastNetmap.Version != 9 || d.lastNetmap.Self.Name != "client" {
		t.Fatalf("rejected map changed live state: %+v", d.lastNetmap)
	}
}

func TestRestartRestoresLastKnownGoodBeforeCoordinatorReconnect(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	firstEngine := wgengine.NewStub(log)
	first, err := New(Config{
		CoordURL: "http://127.0.0.1:1", StateDir: dir, Hostname: "client",
		DisableDisco: true, Engine: firstEngine, Logger: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	peerPriv, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	nm := types.Netmap{
		Version: 12,
		Self: types.Node{
			ID: "node-client", Name: "client", Key: first.PublicKey(), Role: types.RolePlain,
			MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")},
		},
		Peers: []types.Node{{
			ID: "node-peer", Name: "peer", Key: peerPriv.Public(), Role: types.RolePlain,
			MeshIPs:    []netip.Addr{netip.MustParseAddr("100.64.0.11")},
			AllowedIPs: []string{"100.64.0.11/32"},
		}},
	}
	if err := first.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, netmapFile)); err != nil {
		t.Fatalf("last-known-good snapshot not persisted: %v", err)
	}

	restartedEngine := wgengine.NewStub(log)
	restarted, err := New(Config{
		CoordURL: "http://127.0.0.1:1", StateDir: dir, Hostname: "client",
		DisableDisco: true, Engine: restartedEngine, Logger: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.bootstrapNetmap.Version != nm.Version {
		t.Fatalf("bootstrap version = %d, want %d", restarted.bootstrapNetmap.Version, nm.Version)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- restarted.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for restarted.Status().Version != nm.Version && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if restarted.Status().Version != nm.Version {
		cancel()
		<-done
		t.Fatalf("offline restart status version = %d, want %d", restarted.Status().Version, nm.Version)
	}
	got := restartedEngine.LastConfig()
	if len(got.Peers) != 1 || got.Peers[0].PublicKey != peerPriv.Public() {
		t.Fatalf("offline restart config peers = %+v", got.Peers)
	}
	if restarted.Status().State != StateRunning {
		t.Fatalf("offline restart state = %s, want Running", restarted.Status().State)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context canceled", err)
	}
}

func TestFailedExitDisableKeepsPriorKillSwitchPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action func(*Daemon) error
	}{
		{name: "clear exit", action: func(d *Daemon) error { return d.ClearExit() }},
		{name: "enable internet fallback", action: func(d *Daemon) error { return d.SetInternetFallback(true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guard := netguard.NewStubEnforcer(nil)
			d, err := New(Config{
				CoordURL: "https://203.0.113.10", StateDir: t.TempDir(), Hostname: "client",
				KillSwitch: true, Engine: &failingReconfigureEngine{}, Enforcer: guard,
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			exitPrivate, err := types.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			oldPolicy := netguard.Policy{
				Enabled: true, TunnelInterface: "utun4",
				TunnelEndpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.8:51820")},
			}
			if err := guard.Apply(oldPolicy); err != nil {
				t.Fatal(err)
			}
			d.lastNetmap = types.Netmap{Version: 7, Peers: []types.Node{{
				Name: "tokyo", Role: types.RoleExit, Key: exitPrivate.Public(),
				Endpoints: []string{"198.51.100.8:51820"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"},
			}}}
			d.preferredExit = "tokyo"
			d.exitPeerKey = exitPrivate.Public()
			d.exitRouted = true
			d.status = Status{Version: 7, ActiveExit: "tokyo", KillSwitch: true}

			if err := tc.action(d); err == nil {
				t.Fatal("data-plane failure unexpectedly succeeded")
			}
			if got := guard.Current(); !reflect.DeepEqual(got, oldPolicy) {
				t.Fatalf("failed transition changed kill switch: got=%+v want=%+v", got, oldPolicy)
			}
			if !d.Status().KillSwitch || d.preferredExit != "tokyo" || d.internetFallback {
				t.Fatalf("failed transition committed state: status=%+v preferred=%q fallback=%v", d.Status(), d.preferredExit, d.internetFallback)
			}
		})
	}
}
