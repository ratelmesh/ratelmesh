package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/netguard"
	"github.com/ratelmesh/ratelmesh/internal/remoteaccess"
	"github.com/ratelmesh/ratelmesh/internal/types"
	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

type lifecycleEventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *lifecycleEventLog) add(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *lifecycleEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type lifecycleApplyResult struct {
	policy netguard.Policy
	err    error
}

type lifecycleEnforcer struct {
	mu sync.Mutex

	current   netguard.Policy
	failNext  bool
	blockNext <-chan struct{}
	entered   chan struct{}
	applied   chan lifecycleApplyResult
	cleared   chan struct{}
	events    *lifecycleEventLog
	clearErr  error
}

func newLifecycleEnforcer(events *lifecycleEventLog) *lifecycleEnforcer {
	return &lifecycleEnforcer{
		entered: make(chan struct{}, 4),
		applied: make(chan lifecycleApplyResult, 16),
		cleared: make(chan struct{}, 4),
		events:  events,
	}
}

func (e *lifecycleEnforcer) Apply(policy netguard.Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	fail := e.failNext
	e.failNext = false
	block := e.blockNext
	e.blockNext = nil
	e.mu.Unlock()

	if block != nil {
		e.entered <- struct{}{}
		<-block
	}
	if fail {
		err := errors.New("injected firewall apply failure")
		e.applied <- lifecycleApplyResult{policy: cloneRemoteFirewallTestPolicy(policy), err: err}
		return err
	}

	e.mu.Lock()
	e.current = cloneRemoteFirewallTestPolicy(policy)
	e.mu.Unlock()
	if e.events != nil {
		e.events.add("apply")
	}
	e.applied <- lifecycleApplyResult{policy: cloneRemoteFirewallTestPolicy(policy)}
	return nil
}

func (e *lifecycleEnforcer) Clear() error {
	if e.clearErr != nil {
		return e.clearErr
	}
	e.mu.Lock()
	e.current = netguard.Policy{}
	e.mu.Unlock()
	if e.events != nil {
		e.events.add("clear")
	}
	e.cleared <- struct{}{}
	return nil
}

func (e *lifecycleEnforcer) Current() netguard.Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return cloneRemoteFirewallTestPolicy(e.current)
}

func (*lifecycleEnforcer) Capability() netguard.Capability {
	return netguard.Capability{HostFirewall: true, RemoteAccess: true}
}

func (e *lifecycleEnforcer) seed(policy netguard.Policy) {
	e.mu.Lock()
	e.current = cloneRemoteFirewallTestPolicy(policy)
	e.mu.Unlock()
}

func (e *lifecycleEnforcer) failNextApply() {
	e.mu.Lock()
	e.failNext = true
	e.mu.Unlock()
}

func (e *lifecycleEnforcer) blockNextApply(release <-chan struct{}) {
	e.mu.Lock()
	e.blockNext = release
	e.mu.Unlock()
}

type lifecycleEngine struct {
	*wgengine.StubEngine

	mu                   sync.Mutex
	name                 string
	up                   chan struct{}
	events               *lifecycleEventLog
	upOnce               sync.Once
	downErr              error
	requireCleanupIntent string
}

func newLifecycleEngine(name string, events *lifecycleEventLog) *lifecycleEngine {
	return &lifecycleEngine{
		StubEngine: wgengine.NewStub(slog.New(slog.NewTextHandler(io.Discard, nil))),
		name:       name,
		up:         make(chan struct{}),
		events:     events,
	}
}

func (e *lifecycleEngine) Up() error {
	if e.requireCleanupIntent != "" {
		if _, err := os.Stat(e.requireCleanupIntent); err != nil {
			return fmt.Errorf("cleanup intent missing before Up: %w", err)
		}
	}
	if err := e.StubEngine.Up(); err != nil {
		return err
	}
	e.upOnce.Do(func() { close(e.up) })
	return nil
}

func TestRunPersistsCleanupIntentBeforeEngineUp(t *testing.T) {
	fixture := liveRemoteTargetFixture(t, time.Now().Add(time.Minute))
	engine := newLifecycleEngine("ratelmesh-test0", nil)
	d := newLifecycleDaemon(t, fixture, "http://127.0.0.1:1", engine, newLifecycleEnforcer(nil))
	engine.requireCleanupIntent = filepath.Join(d.cfg.StateDir, cleanupFile)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = d.Run(ctx)
	// Up itself verifies the ordering. A shutdown then clears the marker.
}

func (e *lifecycleEngine) Down() error {
	if e.events != nil {
		e.events.add("down")
	}
	if err := e.StubEngine.Down(); err != nil {
		return err
	}
	return e.downErr
}

func (e *lifecycleEngine) InterfaceName() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.name
}

func (e *lifecycleEngine) setInterfaceName(name string) {
	e.mu.Lock()
	e.name = name
	e.mu.Unlock()
}

func liveRemoteTargetFixture(t *testing.T, expiresAt time.Time) remoteTargetFixture {
	t.Helper()
	fixture := newRemoteTargetFixture(t)
	now := time.Now().UTC()
	issuedAt := now.Add(-2 * time.Minute)
	tenantID := remoteAccessTenantID(fixture.netmap.Self.User)
	policy, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: tenantID,
		Version:  7,
		Enabled:  true,
		IssuedAt: issuedAt,
	}, fixture.signer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.netmap.RemoteAccessPolicyState = policy
	fixture.netmap.RemoteAccessTargetState = signRemoteTargetState(
		t, fixture.signer, policy, tenantID, fixture.netmap.Self.ID, 7, true, issuedAt,
	)
	grant := fixture.netmap.RemoteAccessGrants[0].Grant
	grant.IssuedAt = issuedAt
	grant.NotBefore = issuedAt
	grant.ExpiresAt = expiresAt
	fixture.netmap.RemoteAccessGrants = []remoteaccess.SignedGrant{
		signRemoteTargetGrant(t, fixture.signer, grant),
	}
	fixture.netmap.Version = 1
	fixture.now = now
	return fixture
}

func newLifecycleDaemon(
	t *testing.T,
	fixture remoteTargetFixture,
	coordURL string,
	engine wgengine.Engine,
	guard netguard.Enforcer,
) *Daemon {
	t.Helper()
	d, err := New(Config{
		CoordURL:                coordURL,
		StateDir:                t.TempDir(),
		Hostname:                "lifecycle-target",
		DisableDisco:            true,
		VerifyKey:               fixture.daemon.cfg.VerifyKey,
		RemoteAccessCandidates:  fixture.daemon.cfg.RemoteAccessCandidates,
		RemoteAccessPolicyStore: remoteaccess.NewMemoryPolicyFloorStore(),
		Engine:                  engine,
		Enforcer:                guard,
		Logger:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	d.remotePlatform = remoteaccess.PlatformLinux
	return d
}

func openLifecyclePolicy(fixture remoteTargetFixture, iface string, exit bool) netguard.Policy {
	policy := netguard.Policy{
		Enabled:           exit,
		TunnelInterface:   iface,
		RemoteEnforcement: true,
		ManagedServices: []netguard.ManagedService{{
			TargetMeshIP: fixture.netmap.Self.MeshIPs[0],
			TCPPort:      fixture.netmap.Self.RemoteServices[0].Port,
		}},
		RemoteAccessRules: []netguard.RemoteAccessRule{{
			SourceMeshIP: fixture.netmap.Peers[0].MeshIPs[0],
			TargetMeshIP: fixture.netmap.Self.MeshIPs[0],
			TCPPort:      fixture.netmap.Self.RemoteServices[0].Port,
		}},
		RemoteMeshPrefixes: []netip.Prefix{remoteMeshIPv4, remoteMeshIPv6},
	}
	if exit {
		policy.TunnelEndpoints = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:51820")}
		policy.RelayEndpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.8:443")}
		policy.ControlEndpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:443")}
		policy.AllowCIDRs = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	}
	return policy
}

func receiveLifecycle[T any](t *testing.T, ch <-chan T, timeout time.Duration, description string) T {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case value := <-ch:
		return value
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", description)
		var zero T
		return zero
	}
}

func waitLifecycle(t *testing.T, timeout time.Duration, description string, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", description)
		}
	}
}

func TestRemoteTargetExpiryLoopWakesAtExactExpiryAndRetries(t *testing.T) {
	expiresAt := time.Now().UTC().Add(150 * time.Millisecond)
	fixture := liveRemoteTargetFixture(t, expiresAt)
	guard := newLifecycleEnforcer(nil)
	engine := newLifecycleEngine("ratelmesh-test0", nil)
	d := newLifecycleDaemon(t, fixture, "https://203.0.113.9", engine, guard)
	guard.seed(openLifecyclePolicy(fixture, engine.InterfaceName(), false))
	guard.failNextApply()
	d.lastNetmap = fixture.netmap

	// Make the worker block on a distant timer, then replace the deadline without
	// signaling it. The unbuffered send below can complete only when the worker is
	// selecting on that old timer, and forces it to re-read the exact grant expiry.
	d.remoteExpiryWake = make(chan struct{})
	d.remoteExpiry = time.Now().Add(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.remoteTargetExpiryLoop(ctx)
	}()
	d.mu.Lock()
	d.remoteExpiry = expiresAt
	d.mu.Unlock()
	receiveLifecycle(t, func() <-chan struct{} {
		accepted := make(chan struct{})
		go func() {
			d.remoteExpiryWake <- struct{}{}
			close(accepted)
		}()
		return accepted
	}(), time.Second, "expiry wake acceptance")

	first := receiveLifecycle(t, guard.applied, 2*time.Second, "exact-expiry firewall attempt")
	if first.err == nil {
		t.Fatal("injected exact-expiry apply unexpectedly succeeded")
	}
	waitLifecycle(t, time.Second, "expiry retry scheduling", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return time.Until(d.remoteExpiry) > 500*time.Millisecond
	})
	d.mu.Lock()
	retryAt := d.remoteExpiry
	d.mu.Unlock()
	if remaining := time.Until(retryAt); remaining < 500*time.Millisecond || remaining > 1500*time.Millisecond {
		t.Fatalf("retry scheduled in %v, want approximately one second", remaining)
	}

	second := receiveLifecycle(t, guard.applied, 3*time.Second, "expiry retry")
	if second.err != nil {
		t.Fatalf("expiry retry failed: %v", second.err)
	}
	if !second.policy.RemoteEnforcement || len(second.policy.RemoteAccessRules) != 0 {
		t.Fatalf("retry did not install closed boundary: %#v", second.policy)
	}

	cancel()
	receiveLifecycle(t, done, time.Second, "expiry worker shutdown")
}

func TestRunJoinsRemoteExpiryWorkerBeforeEngineDownAndFirewallClear(t *testing.T) {
	fixture := liveRemoteTargetFixture(t, time.Now().Add(-time.Millisecond))
	events := &lifecycleEventLog{}
	guard := newLifecycleEnforcer(events)
	engine := newLifecycleEngine("ratelmesh-test0", events)
	guard.seed(openLifecyclePolicy(fixture, engine.InterfaceName(), false))
	releaseApply := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseApply) }) }
	guard.blockNextApply(releaseApply)

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	d := newLifecycleDaemon(t, fixture, server.URL, engine, guard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer release()
	runDone := make(chan error, 1)
	go func() { runDone <- d.Run(ctx) }()
	receiveLifecycle(t, engine.up, time.Second, "daemon engine startup")

	d.mu.Lock()
	d.lastNetmap = fixture.netmap
	d.mu.Unlock()
	d.setRemoteTargetExpiry(time.Now())
	receiveLifecycle(t, guard.entered, 2*time.Second, "blocked expiry apply")
	cancel()

	select {
	case <-guard.cleared:
		t.Fatal("firewall cleared while expiry worker was still applying")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case err := <-runDone:
		t.Fatalf("Run returned before expiry worker was released: %v", err)
	default:
	}

	release()
	if err := receiveLifecycle(t, runDone, 2*time.Second, "daemon shutdown"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context canceled", err)
	}
	if got, want := events.snapshot(), []string{"apply", "down", "clear"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("shutdown order = %v, want %v", got, want)
	}
}

func TestRunReportsIncompleteEngineCleanup(t *testing.T) {
	fixture := liveRemoteTargetFixture(t, time.Now().Add(time.Minute))
	cleanupErr := errors.New("route cleanup failed")
	events := &lifecycleEventLog{}
	engine := newLifecycleEngine("ratelmesh-test0", events)
	engine.downErr = cleanupErr
	guard := newLifecycleEnforcer(events)

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	d := newLifecycleDaemon(t, fixture, server.URL, engine, guard)
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- d.Run(ctx) }()
	receiveLifecycle(t, engine.up, time.Second, "daemon engine startup")
	cancel()

	err := receiveLifecycle(t, runDone, 2*time.Second, "daemon shutdown")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, cleanupErr) {
		t.Fatalf("Run error = %v, want context cancellation joined with cleanup failure", err)
	}
	if !d.Status().CleanupPending {
		t.Fatal("cleanup failure was not exposed in daemon status")
	}
	if got, want := events.snapshot(), []string{"down"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("shutdown events = %v, want %v (firewall must remain fail-closed)", got, want)
	}
}

func TestRunReportsIncompleteFirewallCleanup(t *testing.T) {
	fixture := liveRemoteTargetFixture(t, time.Now().Add(time.Minute))
	cleanupErr := errors.New("firewall cleanup failed")
	engine := newLifecycleEngine("ratelmesh-test0", nil)
	guard := newLifecycleEnforcer(nil)
	guard.clearErr = cleanupErr

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	d := newLifecycleDaemon(t, fixture, server.URL, engine, guard)
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- d.Run(ctx) }()
	receiveLifecycle(t, engine.up, time.Second, "daemon engine startup")
	cancel()

	err := receiveLifecycle(t, runDone, 2*time.Second, "daemon shutdown")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, cleanupErr) {
		t.Fatalf("Run error = %v, want context cancellation joined with firewall cleanup failure", err)
	}
	if !d.Status().CleanupPending {
		t.Fatal("firewall cleanup failure was not exposed in daemon status")
	}
}

func TestApplyNetmapComposeErrorRemovesOldRemoteAllow(t *testing.T) {
	fixture := liveRemoteTargetFixture(t, time.Now().Add(time.Minute))
	guard := newLifecycleEnforcer(nil)
	engine := newLifecycleEngine("", nil)
	d := newLifecycleDaemon(t, fixture, "https://203.0.113.9", engine, guard)
	prior := openLifecyclePolicy(fixture, "utun-old", true)
	guard.seed(prior)

	if _, err := d.applyNetmapLocked(fixture.netmap); err == nil {
		t.Fatal("missing tunnel interface did not reject candidate policy")
	}
	got := guard.Current()
	if !got.Enabled || !got.RemoteEnforcement || len(got.RemoteAccessRules) != 0 {
		t.Fatalf("compose error did not preserve EXIT and close remote allows: %#v", got)
	}
	if !reflect.DeepEqual(got.TunnelEndpoints, prior.TunnelEndpoints) ||
		!reflect.DeepEqual(got.RelayEndpoints, prior.RelayEndpoints) ||
		!reflect.DeepEqual(got.ControlEndpoints, prior.ControlEndpoints) ||
		!reflect.DeepEqual(got.AllowCIDRs, prior.AllowCIDRs) {
		t.Fatalf("compose error changed predecessor EXIT policy: %#v", got)
	}
	d.mu.Lock()
	retryAt := d.remoteExpiry
	d.mu.Unlock()
	if retryAt.IsZero() || !retryAt.After(time.Now()) {
		t.Fatalf("compose error did not schedule retry: %v", retryAt)
	}
}

func TestExpiryComposeErrorRemovesOldRemoteAllow(t *testing.T) {
	fixture := liveRemoteTargetFixture(t, time.Now().Add(time.Minute))
	guard := newLifecycleEnforcer(nil)
	engine := newLifecycleEngine("", nil)
	d := newLifecycleDaemon(t, fixture, "https://203.0.113.9", engine, guard)
	prior := openLifecyclePolicy(fixture, "utun-old", true)
	guard.seed(prior)
	d.lastNetmap = fixture.netmap
	d.lastNetmap.Self.MeshIPs = []netip.Addr{netip.MustParseAddr("192.0.2.3")}

	d.reconcileRemoteTargetExpiry(fixture.now)
	got := guard.Current()
	if !got.Enabled || !got.RemoteEnforcement || len(got.RemoteAccessRules) != 0 {
		t.Fatalf("expiry compose error did not preserve EXIT and close remote allows: %#v", got)
	}
	if !reflect.DeepEqual(got.TunnelEndpoints, prior.TunnelEndpoints) ||
		!reflect.DeepEqual(got.RelayEndpoints, prior.RelayEndpoints) ||
		!reflect.DeepEqual(got.ControlEndpoints, prior.ControlEndpoints) ||
		!reflect.DeepEqual(got.AllowCIDRs, prior.AllowCIDRs) {
		t.Fatalf("expiry compose error changed predecessor EXIT policy: %#v", got)
	}
	d.mu.Lock()
	retryAt := d.remoteExpiry
	d.mu.Unlock()
	if retryAt.IsZero() || !retryAt.After(time.Now()) {
		t.Fatalf("expiry compose error did not schedule retry: %v", retryAt)
	}
}

func TestCombinedExitAndRemotePolicyPreserveEachOtherAndRebindInterface(t *testing.T) {
	fixture := liveRemoteTargetFixture(t, time.Now().Add(time.Minute))
	guard := newLifecycleEnforcer(nil)
	engine := newLifecycleEngine("utun4", nil)
	d := newLifecycleDaemon(t, fixture, "https://203.0.113.9", engine, guard)
	d.cfg.KillSwitch = true

	base := openLifecyclePolicy(fixture, "utun4", true)
	target, err := d.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	composed, err := d.composeRemoteTargetPolicy(base, target, fixture.netmap.Self)
	if err != nil {
		t.Fatal(err)
	}
	if !composed.Enabled ||
		!reflect.DeepEqual(composed.TunnelEndpoints, base.TunnelEndpoints) ||
		!reflect.DeepEqual(composed.RelayEndpoints, base.RelayEndpoints) ||
		!reflect.DeepEqual(composed.ControlEndpoints, base.ControlEndpoints) ||
		!reflect.DeepEqual(composed.AllowCIDRs, base.AllowCIDRs) {
		t.Fatalf("remote composition erased EXIT policy: %#v", composed)
	}
	guard.seed(composed)
	remoteBefore := cloneRemoteFirewallTestPolicy(composed)
	d.mu.Lock()
	d.preferredExit = "exit"
	d.lastNetmap.Peers = append(d.lastNetmap.Peers, types.Node{
		Name:      "exit",
		Role:      types.RoleExit,
		Endpoints: []string{"198.51.100.10:51820"},
	})
	d.mu.Unlock()

	engine.setInterfaceName("utun9")
	if !d.refreshKillSwitch() {
		t.Fatal("active EXIT was not armed")
	}
	got := guard.Current()
	if !got.RemoteEnforcement ||
		!reflect.DeepEqual(got.ManagedServices, remoteBefore.ManagedServices) ||
		!reflect.DeepEqual(got.RemoteAccessRules, remoteBefore.RemoteAccessRules) ||
		!reflect.DeepEqual(got.RemoteMeshPrefixes, remoteBefore.RemoteMeshPrefixes) {
		t.Fatalf("EXIT refresh erased remote policy: %#v", got)
	}
	if got.TunnelInterface != "utun9" {
		t.Fatalf("combined policy remained pinned to stale interface %q", got.TunnelInterface)
	}
}

func TestKillSwitchRefreshSerializesWithRemoteRevocation(t *testing.T) {
	fixture := liveRemoteTargetFixture(t, time.Now().Add(time.Minute))
	guard := newLifecycleEnforcer(nil)
	engine := newLifecycleEngine("utun4", nil)
	d := newLifecycleDaemon(t, fixture, "https://203.0.113.9", engine, guard)
	d.cfg.KillSwitch = true
	guard.seed(openLifecyclePolicy(fixture, "utun4", true))
	d.mu.Lock()
	d.preferredExit = "exit"
	d.lastNetmap.Peers = append(d.lastNetmap.Peers, types.Node{
		Name:      "exit",
		Role:      types.RoleExit,
		Endpoints: []string{"198.51.100.10:51820"},
	})
	d.mu.Unlock()

	// Model the revocation transaction owning applyMu. A concurrent recovery
	// refresh must not reach guard.Current/Apply until that transaction has
	// installed its closed remote half and released the lock.
	d.applyMu.Lock()
	started := make(chan struct{})
	done := make(chan bool, 1)
	go func() {
		close(started)
		done <- d.refreshKillSwitch()
	}()
	<-started
	select {
	case <-done:
		d.applyMu.Unlock()
		t.Fatal("kill-switch refresh bypassed the remote-policy transaction lock")
	case <-time.After(100 * time.Millisecond):
	}

	closed := guard.Current()
	closed.RemoteAccessRules = nil
	guard.seed(closed)
	d.applyMu.Unlock()

	select {
	case armed := <-done:
		if !armed {
			t.Fatal("serialized EXIT refresh unexpectedly disarmed the kill switch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serialized kill-switch refresh did not complete")
	}
	if got := guard.Current(); len(got.RemoteAccessRules) != 0 {
		t.Fatalf("kill-switch refresh re-armed revoked remote rules: %#v", got.RemoteAccessRules)
	}
}

func TestKillSwitchRefreshUsesLatestExitIntentInsideTransaction(t *testing.T) {
	exitPeer := types.Node{
		Name:      "exit",
		Role:      types.RoleExit,
		Endpoints: []string{"198.51.100.10:51820"},
	}
	for _, test := range []struct {
		name            string
		initialSelected bool
		committed       bool
	}{
		{name: "new selection cannot be disarmed by stale direct state", committed: true},
		{name: "cleared selection cannot be rearmed by stale exit state", initialSelected: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := liveRemoteTargetFixture(t, time.Now().Add(time.Minute))
			guard := newLifecycleEnforcer(nil)
			engine := newLifecycleEngine("utun4", nil)
			d := newLifecycleDaemon(t, fixture, "https://203.0.113.9", engine, guard)
			d.cfg.KillSwitch = true
			if test.initialSelected {
				d.preferredExit = exitPeer.Name
				d.lastNetmap.Peers = append(d.lastNetmap.Peers, exitPeer)
				guard.seed(openLifecyclePolicy(fixture, "utun4", true))
			}

			d.applyMu.Lock()
			started := make(chan struct{})
			done := make(chan bool, 1)
			go func() {
				close(started)
				done <- d.refreshKillSwitch()
			}()
			<-started
			select {
			case <-done:
				d.applyMu.Unlock()
				t.Fatal("EXIT refresh bypassed the netmap transaction lock")
			case <-time.After(100 * time.Millisecond):
			}

			d.mu.Lock()
			if test.committed {
				d.preferredExit = exitPeer.Name
				d.lastNetmap.Peers = append(d.lastNetmap.Peers, exitPeer)
			} else {
				d.preferredExit = ""
				d.lastNetmap.Peers = nil
			}
			d.mu.Unlock()
			if test.committed {
				guard.seed(openLifecyclePolicy(fixture, "utun4", true))
			} else {
				guard.seed(openLifecyclePolicy(fixture, "utun4", false))
			}
			d.applyMu.Unlock()

			select {
			case armed := <-done:
				if armed != test.committed {
					t.Fatalf("refresh armed=%v, want latest committed intent %v", armed, test.committed)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("EXIT refresh did not complete")
			}
			if got := guard.Current(); got.Enabled != test.committed {
				t.Fatalf("firewall enabled=%v, want latest committed intent %v", got.Enabled, test.committed)
			}
			if got := d.Status().KillSwitch; got != test.committed {
				t.Fatalf("status killSwitch=%v, want latest committed intent %v", got, test.committed)
			}
		})
	}
}

func TestOldCoordinatorAndRejectedTargetStatesReachSafeFirewallResults(t *testing.T) {
	t.Run("old coordinator remains compatible", func(t *testing.T) {
		fixture := liveRemoteTargetFixture(t, time.Now().Add(time.Minute))
		guard := newLifecycleEnforcer(nil)
		engine := newLifecycleEngine("ratelmesh-test0", nil)
		d := newLifecycleDaemon(t, fixture, "https://203.0.113.9", engine, guard)
		oldNetmap := types.Netmap{
			Version: 1,
			Self: types.Node{
				ID:       fixture.netmap.Self.ID,
				User:     fixture.netmap.Self.User,
				Platform: "linux",
				MeshIPs:  append([]netip.Addr(nil), fixture.netmap.Self.MeshIPs...),
			},
		}
		if _, err := d.applyNetmapLocked(oldNetmap); err != nil {
			t.Fatalf("old coordinator netmap rejected: %v", err)
		}
		if got := guard.Current(); got.RemoteEnforcement || len(got.RemoteAccessRules) != 0 {
			t.Fatalf("old coordinator enabled remote firewall state: %#v", got)
		}
		if d.Status().Self.RemoteAccessAllowed {
			t.Fatal("old coordinator caused remote target capability to be reported")
		}
	})

	tests := map[string]func(*types.Netmap){
		"missing": func(netmap *types.Netmap) {
			netmap.RemoteAccessTargetState = remoteaccess.SignedTargetState{}
		},
		"tampered": func(netmap *types.Netmap) {
			netmap.RemoteAccessTargetState.Signature = append(
				[]byte(nil), netmap.RemoteAccessTargetState.Signature...,
			)
			netmap.RemoteAccessTargetState.Signature[0] ^= 0xff
		},
	}
	for name, mutate := range tests {
		t.Run(name+" target state fails closed", func(t *testing.T) {
			fixture := liveRemoteTargetFixture(t, time.Now().Add(time.Minute))
			mutate(&fixture.netmap)
			guard := newLifecycleEnforcer(nil)
			engine := newLifecycleEngine("ratelmesh-test0", nil)
			d := newLifecycleDaemon(t, fixture, "https://203.0.113.9", engine, guard)
			guard.seed(openLifecyclePolicy(fixture, engine.InterfaceName(), false))

			if _, err := d.applyNetmapLocked(fixture.netmap); err != nil {
				t.Fatalf("closed target netmap failed to apply: %v", err)
			}
			got := guard.Current()
			if !got.RemoteEnforcement || len(got.ManagedServices) == 0 || len(got.RemoteAccessRules) != 0 {
				t.Fatalf("rejected target did not reach closed firewall: %#v", got)
			}
			if d.Status().Self.RemoteAccessAllowed {
				t.Fatal("rejected target state was advertised as remotely accessible")
			}
		})
	}
}
