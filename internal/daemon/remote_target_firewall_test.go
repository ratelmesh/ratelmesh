package daemon

import (
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/shan25519/ratelmesh/internal/netguard"
	"github.com/shan25519/ratelmesh/internal/remoteaccess"
	"github.com/shan25519/ratelmesh/internal/wgengine"
)

type capableRemoteEnforcer struct {
	mu      sync.Mutex
	current netguard.Policy
	applies int
}

func (e *capableRemoteEnforcer) Apply(policy netguard.Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.current = cloneRemoteFirewallTestPolicy(policy)
	e.applies++
	return nil
}

func (e *capableRemoteEnforcer) Clear() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.current = netguard.Policy{}
	return nil
}

func (e *capableRemoteEnforcer) Current() netguard.Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return cloneRemoteFirewallTestPolicy(e.current)
}

func (e *capableRemoteEnforcer) Capability() netguard.Capability {
	return netguard.Capability{HostFirewall: true, RemoteAccess: true}
}

func cloneRemoteFirewallTestPolicy(policy netguard.Policy) netguard.Policy {
	policy.TunnelEndpoints = append([]netip.AddrPort(nil), policy.TunnelEndpoints...)
	policy.RelayEndpoints = append([]netip.AddrPort(nil), policy.RelayEndpoints...)
	policy.ControlEndpoints = append([]netip.AddrPort(nil), policy.ControlEndpoints...)
	policy.AllowCIDRs = append([]netip.Prefix(nil), policy.AllowCIDRs...)
	policy.ManagedServices = append([]netguard.ManagedService(nil), policy.ManagedServices...)
	policy.RemoteAccessRules = append([]netguard.RemoteAccessRule(nil), policy.RemoteAccessRules...)
	policy.RemoteMeshPrefixes = append([]netip.Prefix(nil), policy.RemoteMeshPrefixes...)
	return policy
}

type namedRemoteEngine struct {
	*wgengine.StubEngine
	name string
}

func (e *namedRemoteEngine) InterfaceName() string { return e.name }

type namedFailingRemoteEngine struct {
	failingReconfigureEngine
	name string
}

func (e *namedFailingRemoteEngine) InterfaceName() string { return e.name }

func TestApplyNetmapEnforcesAndExpiresRemoteTargetGrant(t *testing.T) {
	fixture := newRemoteTargetFixture(t)
	liveNow := time.Now().UTC()
	policy, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: remoteAccessTenantID(fixture.netmap.Self.User),
		Version:  7,
		Enabled:  true,
		IssuedAt: liveNow,
	}, fixture.signer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.netmap.RemoteAccessPolicyState = policy
	fixture.netmap.RemoteAccessTargetState = signRemoteTargetState(
		t, fixture.signer, policy, remoteAccessTenantID(fixture.netmap.Self.User),
		fixture.netmap.Self.ID, 7, true, liveNow,
	)
	grant := fixture.netmap.RemoteAccessGrants[0].Grant
	grant.IssuedAt = liveNow.Add(-time.Minute)
	grant.NotBefore = liveNow.Add(-time.Minute)
	grant.ExpiresAt = liveNow.Add(time.Hour)
	fixture.netmap.RemoteAccessGrants = []remoteaccess.SignedGrant{signRemoteTargetGrant(t, fixture.signer, grant)}
	fixture.netmap.Version = 1
	engine := &namedRemoteEngine{StubEngine: wgengine.NewStub(nil), name: "ratelmesh-test0"}
	guard := &capableRemoteEnforcer{}
	d, err := New(Config{
		CoordURL:               "https://coord.example",
		StateDir:               t.TempDir(),
		Hostname:               "target",
		VerifyKey:              fixture.daemon.cfg.VerifyKey,
		RemoteAccessCandidates: fixture.daemon.cfg.RemoteAccessCandidates,
		Engine:                 engine,
		Enforcer:               guard,
		Logger:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture models a Linux target while this test may execute on macOS.
	// Production derives this field from runtime.GOOS in New.
	d.remotePlatform = remoteaccess.PlatformLinux
	d.remotePolicyStore = remoteaccess.NewMemoryPolicyFloorStore()

	if _, err := d.applyNetmapLocked(fixture.netmap); err != nil {
		t.Fatal(err)
	}
	applied := guard.Current()
	if !applied.RemoteEnforcement || applied.Enabled || applied.TunnelInterface != "ratelmesh-test0" {
		t.Fatalf("applied remote policy = %#v", applied)
	}
	if len(applied.RemoteAccessRules) != 1 {
		t.Fatalf("remote rules = %#v", applied.RemoteAccessRules)
	}
	if want := []netguard.ManagedService{
		{TargetMeshIP: fixture.netmap.Self.MeshIPs[0], TCPPort: 22},
		{TargetMeshIP: fixture.netmap.Self.MeshIPs[0], TCPPort: 2200},
		{TargetMeshIP: fixture.netmap.Self.MeshIPs[0], TCPPort: 2222},
	}; !reflect.DeepEqual(applied.ManagedServices, want) {
		t.Fatalf("managed services = %#v, want %#v", applied.ManagedServices, want)
	}
	if d.refreshKillSwitch() {
		t.Fatal("inactive EXIT unexpectedly armed kill switch")
	}
	if got := guard.Current(); len(got.RemoteAccessRules) != 1 || !got.RemoteEnforcement {
		t.Fatalf("kill-switch refresh erased remote policy: %#v", got)
	}

	d.reconcileRemoteTargetExpiry(fixture.netmap.RemoteAccessGrants[0].Grant.ExpiresAt)
	expired := guard.Current()
	if !expired.RemoteEnforcement || len(expired.RemoteAccessRules) != 0 {
		t.Fatalf("expired grant remained in firewall: %#v", expired)
	}
	if !reflect.DeepEqual(expired.ManagedServices, applied.ManagedServices) {
		t.Fatalf("expiry removed deny boundary: %#v", expired.ManagedServices)
	}
}

func TestRemoteTargetCapabilityControlsOnlyLocalAdvertisement(t *testing.T) {
	fixture := newRemoteTargetFixture(t)
	fixture.netmap.RemoteAccessTargetState = signRemoteTargetState(
		t,
		fixture.signer,
		fixture.netmap.RemoteAccessPolicyState,
		remoteAccessTenantID(fixture.netmap.Self.User),
		fixture.netmap.Self.ID,
		7,
		true,
		fixture.now,
	)
	fixture.daemon.guard = netguard.NewStubEnforcer(nil)
	fixture.daemon.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	view := fixture.daemon.authenticateRemoteAccessNetmap(fixture.netmap, fixture.now)
	if view.selfAllowed {
		t.Fatal("rootless enforcer advertised this device as a secure target")
	}
}

func TestRemoteGrantRevocationSurvivesEngineFailure(t *testing.T) {
	fixture := newRemoteTargetFixture(t)
	liveNow := time.Now().UTC()
	policy7, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: remoteAccessTenantID(fixture.netmap.Self.User),
		Version:  7, Enabled: true, IssuedAt: liveNow,
	}, fixture.signer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.netmap.RemoteAccessPolicyState = policy7
	fixture.netmap.RemoteAccessTargetState = signRemoteTargetState(
		t, fixture.signer, policy7, remoteAccessTenantID(fixture.netmap.Self.User),
		fixture.netmap.Self.ID, 7, true, liveNow,
	)
	grant := fixture.netmap.RemoteAccessGrants[0].Grant
	grant.IssuedAt = liveNow.Add(-time.Minute)
	grant.NotBefore = liveNow.Add(-time.Minute)
	grant.ExpiresAt = liveNow.Add(time.Hour)
	fixture.netmap.RemoteAccessGrants = []remoteaccess.SignedGrant{signRemoteTargetGrant(t, fixture.signer, grant)}
	fixture.netmap.Version = 1

	guard := &capableRemoteEnforcer{}
	d, err := New(Config{
		CoordURL:               "https://coord.example",
		StateDir:               t.TempDir(),
		Hostname:               "target",
		VerifyKey:              fixture.daemon.cfg.VerifyKey,
		RemoteAccessCandidates: fixture.daemon.cfg.RemoteAccessCandidates,
		Engine:                 &namedRemoteEngine{StubEngine: wgengine.NewStub(nil), name: "ratelmesh-test0"},
		Enforcer:               guard,
		Logger:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	d.remotePlatform = remoteaccess.PlatformLinux
	d.remotePolicyStore = remoteaccess.NewMemoryPolicyFloorStore()
	if _, err := d.applyNetmapLocked(fixture.netmap); err != nil {
		t.Fatal(err)
	}
	if len(guard.Current().RemoteAccessRules) != 1 {
		t.Fatal("initial grant was not installed")
	}

	revoked := fixture.netmap
	revoked.Version = 2
	policy8, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: remoteAccessTenantID(revoked.Self.User),
		Version:  8, Enabled: true, IssuedAt: liveNow.Add(time.Second),
	}, fixture.signer)
	if err != nil {
		t.Fatal(err)
	}
	revoked.RemoteAccessPolicyVersion = 8
	revoked.RemoteAccessPolicyState = policy8
	revoked.RemoteAccessTargetState = signRemoteTargetState(
		t, fixture.signer, policy8, remoteAccessTenantID(revoked.Self.User),
		revoked.Self.ID, 8, true, liveNow.Add(time.Second),
	)
	revoked.RemoteAccessGrants = []remoteaccess.SignedGrant{}
	d.engine = &namedFailingRemoteEngine{name: "ratelmesh-test0"}
	if _, err := d.applyNetmapLocked(revoked); err == nil {
		t.Fatal("data-plane failure was not returned")
	}
	after := guard.Current()
	if !after.RemoteEnforcement || len(after.RemoteAccessRules) != 0 {
		t.Fatalf("engine rollback restored revoked grant: %#v", after)
	}
}
