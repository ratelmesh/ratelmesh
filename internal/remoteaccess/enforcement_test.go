package remoteaccess

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type enforcementFixture struct {
	now      time.Time
	signer   Ed25519Signer
	verifier Ed25519Verifier
	source   NodeIdentity
	target   NodeIdentity
	service  ServiceAdvertisement
	grant    Grant
	signed   SignedGrant
	policy   SignedPolicyState
}

func newEnforcementFixture(t *testing.T) enforcementFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	f := enforcementFixture{
		now:      now,
		signer:   Ed25519Signer{PrivateKey: priv},
		verifier: Ed25519Verifier{PublicKey: pub},
		source:   NodeIdentity{TenantID: "tenant-1", NodeID: "source-1", MeshIP: "100.64.0.2", Platform: PlatformMacOS},
		target:   NodeIdentity{TenantID: "tenant-1", NodeID: "target-1", MeshIP: "100.64.0.3", Platform: PlatformLinux},
	}
	f.service = ServiceAdvertisement{
		Kind: KindSSH, Port: 2222, Platform: f.target.Platform, Label: "SSH",
		TargetNodeID: f.target.NodeID, TargetMeshIP: f.target.MeshIP,
	}
	f.grant = Grant{
		ID: "grant-1", TenantID: f.source.TenantID, GrantorID: "admin",
		GranteeID: f.source.NodeID, GranteeMeshIP: f.source.MeshIP,
		PolicyVersion: 7, Service: f.service,
		IssuedAt: now.Add(-time.Minute), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	f.signed = signFixtureGrant(t, f.signer, f.grant)
	f.policy, err = SignPolicyState(PolicyState{
		TenantID: f.target.TenantID, Version: 7, Enabled: true, IssuedAt: now,
	}, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func signFixtureGrant(t *testing.T, signer Signer, grant Grant) SignedGrant {
	t.Helper()
	payload, signature, err := SignGrant(&grant, signer)
	if err != nil {
		t.Fatal(err)
	}
	return SignedGrant{Grant: grant, Payload: payload, Signature: signature}
}

func privateTestRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func validSourceAuthorizationRequest(f enforcementFixture, store PolicyFloorStore) SourceAuthorizationRequest {
	return SourceAuthorizationRequest{
		Self: f.source, Target: f.target, Verifier: f.verifier,
		PolicyStore: store, SignedPolicy: f.policy, Now: f.now,
		ExpectedKind: KindSSH, ExpectedPort: 2222, SignedGrant: f.signed,
	}
}

func TestAuthorizeSourceUsesSignedPayloadOnly(t *testing.T) {
	f := newEnforcementFixture(t)
	request := validSourceAuthorizationRequest(f, NewMemoryPolicyFloorStore())
	got, err := AuthorizeSource(request)
	if err != nil {
		t.Fatal(err)
	}
	if got.Grant != f.grant || got.Launcher.URI != "ssh://100.64.0.3:2222" {
		t.Fatalf("unexpected authorization: %#v", got)
	}

	tampered := f.signed
	tampered.Grant.Service.Port = 22
	request.SignedGrant = tampered
	_, err = AuthorizeSource(request)
	assertEnforcementCode(t, err, CodeCacheMismatch)
}

func TestAuthorizeSourceRejectsEveryBindingMismatch(t *testing.T) {
	f := newEnforcementFixture(t)
	tests := map[string]func(*SourceAuthorizationRequest){
		"tenant":           func(r *SourceAuthorizationRequest) { r.Self.TenantID = "other" },
		"grantee":          func(r *SourceAuthorizationRequest) { r.Self.NodeID = "other" },
		"grantee mesh ip":  func(r *SourceAuthorizationRequest) { r.Self.MeshIP = "100.64.0.9" },
		"target":           func(r *SourceAuthorizationRequest) { r.Target.NodeID = "other" },
		"mesh ip":          func(r *SourceAuthorizationRequest) { r.Target.MeshIP = "100.64.0.9" },
		"kind":             func(r *SourceAuthorizationRequest) { r.ExpectedKind = KindVNC },
		"port":             func(r *SourceAuthorizationRequest) { r.ExpectedPort = 22 },
		"platform":         func(r *SourceAuthorizationRequest) { r.Target.Platform = PlatformMacOS },
		"not before":       func(r *SourceAuthorizationRequest) { r.Now = f.grant.NotBefore.Add(-time.Nanosecond) },
		"expiry exclusive": func(r *SourceAuthorizationRequest) { r.Now = f.grant.ExpiresAt },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := validSourceAuthorizationRequest(f, NewMemoryPolicyFloorStore())
			mutate(&req)
			if _, err := AuthorizeSource(req); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestAuthorizeSourceRejectsKeySubstitution(t *testing.T) {
	f := newEnforcementFixture(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = AuthorizeSource(SourceAuthorizationRequest{
		Self: f.source, Target: f.target, Verifier: Ed25519Verifier{PublicKey: pub},
		PolicyStore: NewMemoryPolicyFloorStore(), SignedPolicy: f.policy,
		Now: f.now, ExpectedKind: KindSSH, ExpectedPort: 2222, SignedGrant: f.signed,
	})
	assertEnforcementCode(t, err, CodeSignatureInvalid)
}

func TestAuthorizeSourceSupportsMobileButRejectsMobileTarget(t *testing.T) {
	for _, platform := range []Platform{PlatformAndroid, PlatformIOS} {
		t.Run(string(platform), func(t *testing.T) {
			f := newEnforcementFixture(t)
			f.source.Platform = platform
			request := validSourceAuthorizationRequest(f, NewMemoryPolicyFloorStore())
			if _, err := AuthorizeSource(request); err != nil {
				t.Fatalf("mobile source rejected: %v", err)
			}

			request.Target.Platform = platform
			if _, err := AuthorizeSource(request); err == nil {
				t.Fatal("mobile remote-service target accepted")
			}
		})
	}
}

func TestAuthorizeSourceRequiresCurrentSignedEnabledPolicy(t *testing.T) {
	t.Run("unsigned", func(t *testing.T) {
		f := newEnforcementFixture(t)
		request := validSourceAuthorizationRequest(f, NewMemoryPolicyFloorStore())
		request.SignedPolicy.Signature = make([]byte, ed25519.SignatureSize)
		_, err := AuthorizeSource(request)
		assertEnforcementCode(t, err, CodeSignatureInvalid)
	})

	t.Run("stale", func(t *testing.T) {
		f := newEnforcementFixture(t)
		store := NewMemoryPolicyFloorStore()
		newerSigned, err := SignPolicyState(PolicyState{
			TenantID: f.source.TenantID, Version: 8, Enabled: true, IssuedAt: f.now,
		}, f.signer)
		if err != nil {
			t.Fatal(err)
		}
		newer, err := VerifyPolicyState(newerSigned, f.verifier, f.source.TenantID, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Advance(newer); err != nil {
			t.Fatal(err)
		}
		_, err = AuthorizeSource(validSourceAuthorizationRequest(f, store))
		assertEnforcementCode(t, err, CodePolicyStale)
	})

	t.Run("disabled", func(t *testing.T) {
		f := newEnforcementFixture(t)
		disabled, err := SignPolicyState(PolicyState{
			TenantID: f.source.TenantID, Version: 8, Enabled: false, IssuedAt: f.now,
		}, f.signer)
		if err != nil {
			t.Fatal(err)
		}
		request := validSourceAuthorizationRequest(f, NewMemoryPolicyFloorStore())
		request.SignedPolicy = disabled
		_, err = AuthorizeSource(request)
		assertEnforcementCode(t, err, CodePolicyDisabled)
	})

	t.Run("equal version conflict", func(t *testing.T) {
		f := newEnforcementFixture(t)
		store := NewMemoryPolicyFloorStore()
		verified, err := VerifyPolicyState(f.policy, f.verifier, f.source.TenantID, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Advance(verified); err != nil {
			t.Fatal(err)
		}
		conflicting, err := SignPolicyState(PolicyState{
			TenantID: f.source.TenantID, Version: 7, Enabled: false, IssuedAt: f.now,
		}, f.signer)
		if err != nil {
			t.Fatal(err)
		}
		request := validSourceAuthorizationRequest(f, store)
		request.SignedPolicy = conflicting
		_, err = AuthorizeSource(request)
		assertEnforcementCode(t, err, CodePolicyConflict)
	})

	t.Run("future grant under current policy", func(t *testing.T) {
		f := newEnforcementFixture(t)
		futureGrant := f.grant
		futureGrant.PolicyVersion = 8
		request := validSourceAuthorizationRequest(f, NewMemoryPolicyFloorStore())
		request.SignedGrant = signFixtureGrant(t, f.signer, futureGrant)
		_, err := AuthorizeSource(request)
		assertEnforcementCode(t, err, CodePolicyStale)
	})
}

func validReconcileRequest(f enforcementFixture) TargetReconcileRequest {
	return TargetReconcileRequest{
		Self: f.target, Services: []ServiceAdvertisement{f.service},
		Peers: map[string]string{f.source.NodeID: f.source.MeshIP},
		CanReach: func(source, target string) (bool, error) {
			return source == f.source.NodeID && target == f.target.NodeID, nil
		},
		Verifier: f.verifier, PolicyStore: NewMemoryPolicyFloorStore(),
		SignedPolicy: f.policy, Now: f.now, Grants: []SignedGrant{f.signed},
	}
}

func TestReconcileTargetBuildsDeterministicRule(t *testing.T) {
	f := newEnforcementFixture(t)
	req := validReconcileRequest(f)
	got, err := ReconcileTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	want := []DesiredRule{{
		SourceMeshIP: f.source.MeshIP, TargetMeshIP: f.target.MeshIP, Protocol: "tcp",
		Port: 2222, GrantID: f.grant.ID, ExpiresAt: f.grant.ExpiresAt,
	}}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Fatalf("rules %#v, want %#v", got.Rules, want)
	}

	req.Grants = []SignedGrant{f.signed, f.signed}
	got, err = ReconcileTarget(req)
	if err != nil || !reflect.DeepEqual(got.Rules, want) {
		t.Fatalf("duplicate changed rules: %#v, %v", got, err)
	}
}

func TestReconcileTargetRejectsReverseOnlyReachability(t *testing.T) {
	f := newEnforcementFixture(t)
	req := validReconcileRequest(f)
	req.CanReach = func(source, target string) (bool, error) {
		return source == f.target.NodeID && target == f.source.NodeID, nil
	}
	got, err := ReconcileTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 0 || len(got.Rejected) != 1 || got.Rejected[0].Code != CodeDirectionDenied {
		t.Fatalf("reverse direction authorized: %#v", got)
	}
}

func TestReconcileTargetRejectsPeerAndServiceMismatch(t *testing.T) {
	f := newEnforcementFixture(t)
	for name, mutate := range map[string]func(*TargetReconcileRequest){
		"missing peer":    func(r *TargetReconcileRequest) { r.Peers = map[string]string{} },
		"missing service": func(r *TargetReconcileRequest) { r.Services = []ServiceAdvertisement{} },
	} {
		t.Run(name, func(t *testing.T) {
			req := validReconcileRequest(f)
			mutate(&req)
			got, err := ReconcileTarget(req)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Rules) != 0 || len(got.Rejected) != 1 {
				t.Fatalf("expected fail closed, got %#v", got)
			}
		})
	}

	req := validReconcileRequest(f)
	req.Peers = map[string]string{f.source.NodeID: "192.0.2.1"}
	if _, err := ReconcileTarget(req); err == nil {
		t.Fatal("non-Mesh peer binding accepted")
	}

	req = validReconcileRequest(f)
	req.Peers = map[string]string{f.source.NodeID: "100.64.0.99"}
	got, err := ReconcileTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 0 || len(got.Rejected) != 1 || got.Rejected[0].Code != CodePeerBinding {
		t.Fatalf("reassigned peer IP retained stale grant: %#v", got)
	}
}

type countingPolicyStore struct {
	inner    *MemoryPolicyFloorStore
	advances int
}

func (s *countingPolicyStore) Load(tenantID string) (VerifiedPolicyState, bool, error) {
	return s.inner.Load(tenantID)
}

func (s *countingPolicyStore) Advance(state VerifiedPolicyState) error {
	s.advances++
	return s.inner.Advance(state)
}

func TestReconcileTargetDoesNotAdvanceFloorForMalformedObservations(t *testing.T) {
	f := newEnforcementFixture(t)
	for name, mutate := range map[string]func(*TargetReconcileRequest){
		"service": func(r *TargetReconcileRequest) {
			r.Services[0].TargetMeshIP = "100.64.0.99"
		},
		"peer": func(r *TargetReconcileRequest) {
			r.Peers[f.source.NodeID] = "192.0.2.10"
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := validReconcileRequest(f)
			store := &countingPolicyStore{inner: NewMemoryPolicyFloorStore()}
			req.PolicyStore = store
			mutate(&req)
			if _, err := ReconcileTarget(req); err == nil {
				t.Fatal("malformed observation accepted")
			}
			if store.advances != 0 {
				t.Fatalf("floor advanced %d times", store.advances)
			}
		})
	}
}

func TestReconcileTargetFailClosedDependenciesAndLimits(t *testing.T) {
	f := newEnforcementFixture(t)
	for name, mutate := range map[string]func(*TargetReconcileRequest){
		"verifier": func(r *TargetReconcileRequest) { r.Verifier = nil },
		"store":    func(r *TargetReconcileRequest) { r.PolicyStore = nil },
		"reach":    func(r *TargetReconcileRequest) { r.CanReach = nil },
		"services": func(r *TargetReconcileRequest) { r.Services = nil },
		"peers":    func(r *TargetReconcileRequest) { r.Peers = nil },
		"grants":   func(r *TargetReconcileRequest) { r.Grants = nil },
	} {
		t.Run(name, func(t *testing.T) {
			req := validReconcileRequest(f)
			mutate(&req)
			_, err := ReconcileTarget(req)
			assertEnforcementCode(t, err, CodeDependencyMissing)
		})
	}
	req := validReconcileRequest(f)
	req.Grants = make([]SignedGrant, MaxReconcileGrants+1)
	_, err := ReconcileTarget(req)
	assertEnforcementCode(t, err, CodeLimitExceeded)

	req = validReconcileRequest(f)
	req.Services = make([]ServiceAdvertisement, MaxReconcileServices+1)
	_, err = ReconcileTarget(req)
	assertEnforcementCode(t, err, CodeLimitExceeded)

	req = validReconcileRequest(f)
	req.Peers = make(map[string]string, MaxReconcilePeers+1)
	for i := 0; i <= MaxReconcilePeers; i++ {
		req.Peers[string(rune(i+1))] = "100.64.0.2"
	}
	_, err = ReconcileTarget(req)
	assertEnforcementCode(t, err, CodeLimitExceeded)
}

func TestReconcileTargetPolicyOffAndExpiryRemoveRules(t *testing.T) {
	f := newEnforcementFixture(t)
	req := validReconcileRequest(f)
	disabled, err := SignPolicyState(PolicyState{
		TenantID: f.target.TenantID, Version: 8, Enabled: false, IssuedAt: f.now.Add(time.Minute),
	}, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	req.SignedPolicy = disabled
	req.Now = f.now.Add(time.Minute)
	got, err := ReconcileTarget(req)
	if err != nil || got.PolicyEnabled || len(got.Rules) != 0 {
		t.Fatalf("policy off did not close rules: %#v %v", got, err)
	}

	req = validReconcileRequest(f)
	req.Now = f.grant.ExpiresAt
	got, err = ReconcileTarget(req)
	if err != nil || len(got.Rules) != 0 || got.Rejected[0].Code != CodeGrantTime {
		t.Fatalf("expiry did not close rule: %#v %v", got, err)
	}
}

func TestReconcileTargetConflictingGrantIDRejectsAll(t *testing.T) {
	f := newEnforcementFixture(t)
	second := f.grant
	second.Service.Port = 2223
	second.Service.Label = "Alternate SSH"
	signedSecond := signFixtureGrant(t, f.signer, second)
	req := validReconcileRequest(f)
	req.Services = append(req.Services, second.Service)
	req.Grants = append(req.Grants, signedSecond)
	got, err := ReconcileTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 0 || len(got.Rejected) != 2 {
		t.Fatalf("conflicting ID not fully rejected: %#v", got)
	}
}

func TestReconcileTargetRejectsSignedWrongTenantAndFuturePolicy(t *testing.T) {
	f := newEnforcementFixture(t)
	for name, mutate := range map[string]func(*Grant){
		"tenant": func(g *Grant) { g.TenantID = "other-tenant" },
		"future policy": func(g *Grant) {
			g.PolicyVersion = 8
		},
	} {
		t.Run(name, func(t *testing.T) {
			grant := f.grant
			mutate(&grant)
			req := validReconcileRequest(f)
			req.Grants = []SignedGrant{signFixtureGrant(t, f.signer, grant)}
			got, err := ReconcileTarget(req)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Rules) != 0 || len(got.Rejected) != 1 {
				t.Fatalf("grant escaped exact policy binding: %#v", got)
			}
		})
	}
}

func TestReconcileTargetIPv6AndNonstandardPort(t *testing.T) {
	f := newEnforcementFixture(t)
	f.source.MeshIP = "fd00::2"
	f.target.MeshIP = "fd00::3"
	f.service.TargetMeshIP = f.target.MeshIP
	f.service.Port = 6022
	f.grant.Service = f.service
	f.grant.GranteeMeshIP = f.source.MeshIP
	f.signed = signFixtureGrant(t, f.signer, f.grant)
	req := validReconcileRequest(f)
	got, err := ReconcileTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || got.Rules[0].SourceMeshIP != "fd00::2" || got.Rules[0].Port != 6022 {
		t.Fatalf("unexpected IPv6 rule: %#v", got)
	}
}

func TestReconcileTargetIgnoresMutableServiceLabel(t *testing.T) {
	f := newEnforcementFixture(t)
	req := validReconcileRequest(f)
	req.Services[0].Label = "Renamed by target"
	got, err := ReconcileTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("label-only change invalidated service: %#v", got)
	}
}

func TestReconcileTargetRuleOrderIndependentOfGrantOrder(t *testing.T) {
	f := newEnforcementFixture(t)
	second := f.grant
	second.ID = "grant-2"
	second.Service.Port = 2200
	second.Service.Label = "SSH alternate"
	signedSecond := signFixtureGrant(t, f.signer, second)
	req := validReconcileRequest(f)
	req.Services = append(req.Services, second.Service)
	req.Grants = []SignedGrant{f.signed, signedSecond}
	first, err := ReconcileTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Grants = []SignedGrant{signedSecond, f.signed}
	secondResult, err := ReconcileTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Rules, secondResult.Rules) {
		t.Fatalf("order changed desired state: %#v vs %#v", first.Rules, secondResult.Rules)
	}
}

func TestPolicyStateSignatureAndRollbackProtection(t *testing.T) {
	f := newEnforcementFixture(t)
	verified, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryPolicyFloorStore()
	if err := store.Advance(verified); err != nil {
		t.Fatal(err)
	}

	stale, err := SignPolicyState(PolicyState{
		TenantID: f.target.TenantID, Version: 6, Enabled: true, IssuedAt: f.now,
	}, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	staleVerified, err := VerifyPolicyState(stale, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(staleVerified); !errors.Is(err, ErrPolicyRollback) {
		t.Fatalf("got %v, want rollback", err)
	}

	unsigned := f.policy
	unsigned.Signature = make([]byte, ed25519.SignatureSize)
	if _, err := VerifyPolicyState(unsigned, f.verifier, f.target.TenantID, f.now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("unsigned floor accepted: %v", err)
	}

	conflictSigned, err := SignPolicyState(PolicyState{
		TenantID: f.target.TenantID, Version: 7, Enabled: false, IssuedAt: f.now,
	}, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	conflict, err := VerifyPolicyState(conflictSigned, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(conflict); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("equal-version conflict accepted: %v", err)
	}
}

func TestNewPolicyVersionRecoversFromFutureClockObservation(t *testing.T) {
	f := newEnforcementFixture(t)
	store := NewMemoryPolicyFloorStore()
	future := f.now.Add(20 * 365 * 24 * time.Hour)

	current, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, future)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(current); err != nil {
		t.Fatal(err)
	}

	nextSigned, err := SignPolicyState(PolicyState{
		TenantID: f.target.TenantID,
		Version:  current.Version + 1,
		Enabled:  true,
		IssuedAt: f.now.Add(time.Minute),
	}, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	next, err := VerifyPolicyState(nextSigned, f.verifier, f.target.TenantID, f.now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	next, err = ObservePolicyAt(next, current, true, f.now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(next); err != nil {
		t.Fatalf("new signed policy did not recover future observation: %v", err)
	}
	got, ok, err := store.Load(f.target.TenantID)
	if err != nil || !ok {
		t.Fatalf("load recovered policy: %#v, %v, %v", got, ok, err)
	}
	if got.Version != next.Version || !got.ObservedAt.Equal(next.ObservedAt) {
		t.Fatalf("recovered policy = %#v, want %#v", got, next)
	}
}

func TestAuthorizeSourceNewPolicyRecoversPersistedFutureObservation(t *testing.T) {
	f := newEnforcementFixture(t)
	store := NewMemoryPolicyFloorStore()
	future := f.now.Add(20 * 365 * 24 * time.Hour)
	current, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, future)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(current); err != nil {
		t.Fatal(err)
	}

	nextState := PolicyState{
		TenantID: f.target.TenantID,
		Version:  current.Version + 1,
		Enabled:  true,
		IssuedAt: f.now.Add(time.Minute),
	}
	nextPolicy, err := SignPolicyState(nextState, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	nextGrant := f.grant
	nextGrant.PolicyVersion = nextState.Version
	nextGrant.IssuedAt = f.now.Add(time.Minute)
	nextGrant.NotBefore = f.now.Add(time.Minute)
	nextGrant.ExpiresAt = f.now.Add(time.Hour)
	req := validSourceAuthorizationRequest(f, store)
	req.Now = f.now.Add(2 * time.Minute)
	req.SignedPolicy = nextPolicy
	req.SignedGrant = signFixtureGrant(t, f.signer, nextGrant)
	if _, err := AuthorizeSource(req); err != nil {
		t.Fatalf("new signed policy did not recover future clock observation: %v", err)
	}
	got, ok, err := store.Load(f.target.TenantID)
	if err != nil || !ok {
		t.Fatalf("load recovered floor: %#v, %v, %v", got, ok, err)
	}
	if !got.ObservedAt.Equal(req.Now.UTC()) {
		t.Fatalf("observation remained pinned in future: %v", got.ObservedAt)
	}
}

func TestReconcileTargetNewPolicyRecoversPersistedFutureObservation(t *testing.T) {
	f := newEnforcementFixture(t)
	store := NewMemoryPolicyFloorStore()
	future := f.now.Add(20 * 365 * 24 * time.Hour)
	current, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, future)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(current); err != nil {
		t.Fatal(err)
	}

	nextState := PolicyState{
		TenantID: f.target.TenantID,
		Version:  current.Version + 1,
		Enabled:  true,
		IssuedAt: f.now.Add(time.Minute),
	}
	nextPolicy, err := SignPolicyState(nextState, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	nextGrant := f.grant
	nextGrant.PolicyVersion = nextState.Version
	nextGrant.IssuedAt = f.now.Add(time.Minute)
	nextGrant.NotBefore = f.now.Add(time.Minute)
	nextGrant.ExpiresAt = f.now.Add(time.Hour)
	req := validReconcileRequest(f)
	req.PolicyStore = store
	req.Now = f.now.Add(2 * time.Minute)
	req.SignedPolicy = nextPolicy
	req.Grants = []SignedGrant{signFixtureGrant(t, f.signer, nextGrant)}
	result, err := ReconcileTarget(req)
	if err != nil {
		t.Fatalf("new signed policy did not recover future clock observation: %v", err)
	}
	if len(result.Rules) != 1 || len(result.Rejected) != 0 {
		t.Fatalf("reconcile result = %#v", result)
	}
	got, ok, err := store.Load(f.target.TenantID)
	if err != nil || !ok {
		t.Fatalf("load recovered floor: %#v, %v, %v", got, ok, err)
	}
	if !got.ObservedAt.Equal(req.Now.UTC()) {
		t.Fatalf("observation remained pinned in future: %v", got.ObservedAt)
	}
}

func TestSamePolicyVersionCannotRecoverByRollingObservationBack(t *testing.T) {
	f := newEnforcementFixture(t)
	store := NewMemoryPolicyFloorStore()
	future := f.now.Add(20 * 365 * 24 * time.Hour)

	current, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, future)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(current); err != nil {
		t.Fatal(err)
	}
	replayed, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(replayed); !errors.Is(err, ErrPolicyRollback) {
		t.Fatalf("same-version observation rollback accepted: %v", err)
	}
}

func TestFilePolicyFloorStoreRestartPermissionsAndRollback(t *testing.T) {
	f := newEnforcementFixture(t)
	verified, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "remote-policy.json")
	store, err := NewFilePolicyFloorStore(root, "remote-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Advance(verified); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 600", info.Mode().Perm())
	}

	restarted, err := NewFilePolicyFloorStore(root, "remote-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	got, ok, err := restarted.Load(f.target.TenantID)
	if err != nil || !ok || got != verified {
		t.Fatalf("restart load: %#v %v %v", got, ok, err)
	}
	older := verified
	older.Version--
	if err := restarted.Advance(older); !errors.Is(err, ErrPolicyRollback) {
		t.Fatalf("rollback accepted: %v", err)
	}
}

func TestPolicyFloorStoresSkipExactEqualWritesInsideAtomicAdvance(t *testing.T) {
	f := newEnforcementFixture(t)
	verified, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}

	memory := NewMemoryPolicyFloorStore()
	if err := memory.Advance(verified); err != nil {
		t.Fatal(err)
	}
	if err := memory.Advance(verified); err != nil {
		t.Fatalf("memory exact-equal advance: %v", err)
	}

	root := privateTestRoot(t)
	file, err := NewFilePolicyFloorStore(root, "floor.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writes := 0
	file.beforeWriteForTest = func() { writes++ }
	if err := file.Advance(verified); err != nil {
		t.Fatal(err)
	}
	if err := file.Advance(verified); err != nil {
		t.Fatalf("file exact-equal advance: %v", err)
	}
	if writes != 1 {
		t.Fatalf("file writes = %d, want 1", writes)
	}
}

func TestFilePolicyFloorStoreSerializesStaleWritersAcrossInstances(t *testing.T) {
	f := newEnforcementFixture(t)
	root := privateTestRoot(t)
	first, err := NewFilePolicyFloorStore(root, "floor.json")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewFilePolicyFloorStore(root, "floor.json")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	version7, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Advance(version7); err != nil {
		t.Fatal(err)
	}
	makeVersion := func(version uint64) VerifiedPolicyState {
		signed, err := SignPolicyState(PolicyState{
			TenantID: f.target.TenantID, Version: version, Enabled: true, IssuedAt: f.now,
		}, f.signer)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := VerifyPolicyState(signed, f.verifier, f.target.TenantID, f.now)
		if err != nil {
			t.Fatal(err)
		}
		return verified
	}
	version8, version9 := makeVersion(8), makeVersion(9)

	firstRead := make(chan struct{})
	releaseFirst := make(chan struct{})
	first.afterReadForTest = func() {
		close(firstRead)
		<-releaseFirst
	}
	secondRead := make(chan struct{})
	second.afterReadForTest = func() { close(secondRead) }

	firstDone := make(chan error, 1)
	go func() { firstDone <- first.Advance(version8) }()
	<-firstRead
	secondDone := make(chan error, 1)
	go func() { secondDone <- second.Advance(version9) }()
	select {
	case <-secondRead:
		t.Fatal("second instance read stale floor while first held transaction lock")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	final, ok, err := second.Load(f.target.TenantID)
	if err != nil || !ok || final.Version != 9 {
		t.Fatalf("final floor rolled back: %#v, %v, %v", final, ok, err)
	}
}

func TestAuthorizeSourceFileFloorSurvivesRestartAndRejectsRollback(t *testing.T) {
	f := newEnforcementFixture(t)
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFilePolicyFloorStore(root, "floor.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeSource(validSourceAuthorizationRequest(f, store)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewFilePolicyFloorStore(root, "floor.json")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	stalePolicy, err := SignPolicyState(PolicyState{
		TenantID: f.source.TenantID, Version: 6, Enabled: true, IssuedAt: f.now,
	}, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	staleGrant := f.grant
	staleGrant.PolicyVersion = 6
	request := validSourceAuthorizationRequest(f, restarted)
	request.SignedPolicy = stalePolicy
	request.SignedGrant = signFixtureGrant(t, f.signer, staleGrant)
	_, err = AuthorizeSource(request)
	assertEnforcementCode(t, err, CodePolicyStale)
}

func TestAuthorizeSourceTrustedTimePreventsExpiredGrantRevivalAfterRestart(t *testing.T) {
	f := newEnforcementFixture(t)
	root := privateTestRoot(t)
	store, err := NewFilePolicyFloorStore(root, "floor.json")
	if err != nil {
		t.Fatal(err)
	}
	expiredRequest := validSourceAuthorizationRequest(f, store)
	expiredRequest.Now = f.grant.ExpiresAt.Add(time.Minute)
	_, err = AuthorizeSource(expiredRequest)
	assertEnforcementCode(t, err, CodeGrantTime)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewFilePolicyFloorStore(root, "floor.json")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	rolledBack := validSourceAuthorizationRequest(f, restarted)
	rolledBack.Now = f.now
	_, err = AuthorizeSource(rolledBack)
	assertEnforcementCode(t, err, CodeGrantTime)
}

func TestMemoryPolicyFloorStoreRace(t *testing.T) {
	f := newEnforcementFixture(t)
	verified, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryPolicyFloorStore()
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = store.Advance(verified)
			_, _, _ = store.Load(verified.TenantID)
		}()
	}
	wg.Wait()
}

func TestPolicyStoreRejectsOversizedAndBroadMode(t *testing.T) {
	root := privateTestRoot(t)
	path := filepath.Join(root, "policy.json")
	if err := os.WriteFile(path, make([]byte, MaxPolicyStoreSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFilePolicyFloorStore(root, "policy.json")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.Load("t"); !errors.Is(err, ErrPolicyStoreCorrupt) {
		t.Fatalf("oversized store accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"records":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load("t"); !errors.Is(err, ErrPolicyStoreMode) {
		t.Fatalf("broad mode accepted: %v", err)
	}
}

func TestPolicyStoreRejectsNonCanonicalDigest(t *testing.T) {
	f := newEnforcementFixture(t)
	verified, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryPolicyFloorStore()
	upper := verified
	upper.Digest = strings.ToUpper(upper.Digest)
	if err := store.Advance(upper); !errors.Is(err, ErrInvalidPolicyState) {
		t.Fatalf("uppercase digest accepted: %v", err)
	}
	nonHex := verified
	nonHex.Digest = strings.Repeat("z", 64)
	if err := store.Advance(nonHex); !errors.Is(err, ErrInvalidPolicyState) {
		t.Fatalf("non-hex digest accepted: %v", err)
	}
}

func TestFilePolicyFloorStoreConfinesRootAndRejectsSymlinks(t *testing.T) {
	root := privateTestRoot(t)
	for _, name := range []string{"../escape", "nested/state", "/absolute", `nested\state`} {
		if _, err := NewFilePolicyFloorStore(root, name); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("name %q accepted: %v", name, err)
		}
	}

	realRoot := t.TempDir()
	linkRoot := filepath.Join(t.TempDir(), "linked-root")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFilePolicyFloorStore(linkRoot, "state.json"); !errors.Is(err, ErrPolicyStoreMode) {
		t.Fatalf("symlink root accepted: %v", err)
	}

	broadRoot := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(broadRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(broadRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFilePolicyFloorStore(broadRoot, "state.json"); !errors.Is(err, ErrPolicyStoreMode) {
		t.Fatalf("broad root accepted: %v", err)
	}
	info, err := os.Stat(broadRoot)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("constructor mutated external directory mode to %o", info.Mode().Perm())
	}

	external := filepath.Join(t.TempDir(), "external.json")
	if err := os.WriteFile(external, []byte(`{"records":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "state.json")); err != nil {
		t.Fatal(err)
	}
	store, err := NewFilePolicyFloorStore(root, "state.json")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.Load("tenant"); !errors.Is(err, ErrPolicyStoreCorrupt) {
		t.Fatalf("symlink state accepted: %v", err)
	}
}

func TestFilePolicyFloorStoreRejectsRootReplacementDuringOpen(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "private")
	moved := filepath.Join(parent, "original")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := newFilePolicyFloorStore(root, "state.json", func() {
		if err := os.Rename(root, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
	})
	if !errors.Is(err, ErrPolicyStoreMode) {
		t.Fatalf("replacement root accepted: %v", err)
	}
}

func TestFilePolicyFloorStoreCloseSerializesWithOperations(t *testing.T) {
	f := newEnforcementFixture(t)
	root := privateTestRoot(t)
	store, err := NewFilePolicyFloorStore(root, "state.json")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(verified); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = store.Load(f.target.TenantID)
		}()
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func assertEnforcementCode(t *testing.T, err error, want EnforcementErrorCode) {
	t.Helper()
	var typed *EnforcementError
	if !errors.As(err, &typed) || typed.Code != want {
		t.Fatalf("error %v has code %v, want %v", err, typed, want)
	}
}

func FuzzVerifySignedGrantCache(f *testing.F) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	now := time.Unix(1000, 0).UTC()
	grant := Grant{
		ID: "g", TenantID: "t", GrantorID: "admin", GranteeID: "source",
		GranteeMeshIP: "100.64.0.2", PolicyVersion: 1,
		Service: ServiceAdvertisement{
			Kind: KindSSH, Port: 22, Platform: PlatformLinux, Label: "SSH",
			TargetNodeID: "target", TargetMeshIP: "100.64.0.3",
		},
		IssuedAt: now.Add(-time.Second), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Hour),
	}
	payload, signature, err := SignGrant(&grant, Ed25519Signer{PrivateKey: privateKey})
	if err != nil {
		f.Fatal(err)
	}
	cache, err := json.Marshal(grant)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(cache)
	f.Add([]byte(`{"id":"other"}`))
	ctx := VerificationContext{
		Now: now, TenantID: "t", GranteeID: "source",
		ExpectedGranteeMeshIP: "100.64.0.2", MinPolicyVersion: 1,
		TargetNodeID: "target", ExpectedKind: KindSSH, ExpectedPort: 22,
		ExpectedPlatform: PlatformLinux, ExpectedMeshIP: "100.64.0.3",
	}
	f.Fuzz(func(t *testing.T, outer []byte) {
		if len(outer) > MaxSignedPayloadSize+1024 {
			t.Skip()
		}
		var cached Grant
		if err := json.Unmarshal(outer, &cached); err != nil {
			return
		}
		signed := SignedGrant{Grant: cached, Payload: payload, Signature: signature}
		verified, err := VerifySignedGrant(signed, Ed25519Verifier{PublicKey: publicKey}, ctx)
		if err == nil && *verified != grant {
			t.Fatalf("successful verification returned non-authoritative cache: %#v", verified)
		}
	})
}

func FuzzPolicyStoreDocument(f *testing.F) {
	f.Add([]byte(`{"records":{}}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > MaxPolicyStoreSize+1024 {
			t.Skip()
		}
		root := privateTestRoot(t)
		path := filepath.Join(root, "policy.json")
		if err := os.WriteFile(path, input, 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := NewFilePolicyFloorStore(root, "policy.json")
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		_, _, _ = store.Load("tenant")
	})
}

func TestPolicyDocumentHasNoCredentialFields(t *testing.T) {
	f := newEnforcementFixture(t)
	verified, err := VerifyPolicyState(f.policy, f.verifier, f.target.TenantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(verified)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"password", "credential", "privateKey"} {
		if json.Valid(payload) && containsBytesFold(payload, []byte(forbidden)) {
			t.Fatalf("policy state contains forbidden field %q", forbidden)
		}
	}
}

func containsBytesFold(haystack, needle []byte) bool {
	return strings.Contains(strings.ToLower(string(haystack)), strings.ToLower(string(needle)))
}
