package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/shan25519/ratelmesh/internal/remoteaccess"
	"github.com/shan25519/ratelmesh/internal/types"
)

type remoteTargetFixture struct {
	now    time.Time
	signer remoteaccess.Ed25519Signer
	daemon *Daemon
	netmap types.Netmap
}

func newRemoteTargetFixture(t *testing.T) remoteTargetFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 24, 18, 0, 0, 0, time.UTC)
	signer := remoteaccess.Ed25519Signer{PrivateKey: privateKey}
	self := types.Node{
		ID:                  "target-1",
		User:                "Owner@Example.com",
		Platform:            "linux",
		MeshIPs:             []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		RemoteAccessAllowed: true,
	}
	service := remoteaccess.ServiceAdvertisement{
		Kind:         remoteaccess.KindSSH,
		Port:         2222,
		Platform:     remoteaccess.PlatformLinux,
		Label:        "SSH alternate",
		TargetNodeID: self.ID,
		TargetMeshIP: self.MeshIPs[0].String(),
	}
	self.RemoteServices = []remoteaccess.ServiceAdvertisement{service}
	tenantID := remoteAccessTenantID(self.User)
	policy, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: tenantID,
		Version:  7,
		Enabled:  true,
		IssuedAt: now,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	targetState := signRemoteTargetState(t, signer, policy, tenantID, self.ID, 7, true, now)
	grant := remoteaccess.Grant{
		ID:            "grant-1",
		TenantID:      tenantID,
		GrantorID:     "admin",
		GranteeID:     "source-1",
		GranteeMeshIP: "100.64.0.2",
		PolicyVersion: 7,
		Service:       service,
		IssuedAt:      now.Add(-time.Minute),
		NotBefore:     now.Add(-time.Minute),
		ExpiresAt:     now.Add(time.Hour),
	}
	signedGrant := signRemoteTargetGrant(t, signer, grant)
	return remoteTargetFixture{
		now:    now,
		signer: signer,
		daemon: &Daemon{
			cfg: Config{
				VerifyKey: publicKey,
				RemoteAccessCandidates: []remoteaccess.Candidate{
					{Kind: remoteaccess.KindSSH, Port: 2200},
					{Kind: remoteaccess.KindSSH, Port: 22},
					{Kind: remoteaccess.KindSSH, Port: 2200},
				},
			},
			remotePolicyStore: remoteaccess.NewMemoryPolicyFloorStore(),
			remotePlatform:    remoteaccess.PlatformLinux,
		},
		netmap: types.Netmap{
			Self:                      self,
			Peers:                     []types.Node{{ID: "source-1", MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}}},
			RemoteAccessPolicyVersion: 7,
			RemoteAccessPolicyState:   policy,
			RemoteAccessTargetState:   targetState,
			RemoteAccessGrants:        []remoteaccess.SignedGrant{signedGrant},
		},
	}
}

func signRemoteTargetState(
	t *testing.T,
	signer remoteaccess.Signer,
	policy remoteaccess.SignedPolicyState,
	tenantID, targetNodeID string,
	version uint64,
	enabled bool,
	issuedAt time.Time,
) remoteaccess.SignedTargetState {
	t.Helper()
	digest, err := remoteaccess.PolicyPayloadDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := remoteaccess.SignTargetState(remoteaccess.TargetState{
		TenantID:      tenantID,
		PolicyVersion: version,
		PolicyDigest:  digest,
		TargetNodeID:  targetNodeID,
		Enabled:       enabled,
		IssuedAt:      issuedAt,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func signRemoteTargetGrant(t *testing.T, signer remoteaccess.Signer, grant remoteaccess.Grant) remoteaccess.SignedGrant {
	t.Helper()
	payload, signature, err := remoteaccess.SignGrant(&grant, signer)
	if err != nil {
		t.Fatal(err)
	}
	return remoteaccess.SignedGrant{Grant: grant, Payload: payload, Signature: signature}
}

func TestDeriveRemoteTargetPolicyValidExactAndDeterministic(t *testing.T) {
	fixture := newRemoteTargetFixture(t)
	first, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("non-deterministic policies:\n%#v\n%#v", first, second)
	}
	if !first.Required || !first.Enabled || first.PolicyVersion != 7 {
		t.Fatalf("unexpected policy state: %#v", first)
	}
	if want := []uint16{22, 2200, 2222}; !reflect.DeepEqual(first.ManagedTCPPorts, want) {
		t.Fatalf("managed ports %v, want %v", first.ManagedTCPPorts, want)
	}
	if len(first.Rules) != 1 {
		t.Fatalf("rules = %#v", first.Rules)
	}
	rule := first.Rules[0]
	if rule.SourceMeshIP != "100.64.0.2" || rule.TargetMeshIP != "100.64.0.3" ||
		rule.Port != 2222 || rule.Protocol != "tcp" || rule.GrantID != "grant-1" {
		t.Fatalf("wrong exact rule: %#v", rule)
	}
	if !first.NearestExpiry.Equal(fixture.now.Add(time.Hour)) {
		t.Fatalf("nearest expiry = %v", first.NearestExpiry)
	}
}

func TestDeriveRemoteTargetPolicyInvalidSignatureFailsClosed(t *testing.T) {
	fixture := newRemoteTargetFixture(t)
	fixture.netmap.RemoteAccessPolicyState.Signature[0] ^= 0xff
	got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
	if err == nil || !got.Required || !got.Enabled || len(got.Rules) != 0 {
		t.Fatalf("signature failure not closed: %#v, %v", got, err)
	}
	if want := []uint16{22, 2200}; !reflect.DeepEqual(got.ManagedTCPPorts, want) {
		t.Fatalf("signature failure managed ports = %v, want %v", got.ManagedTCPPorts, want)
	}
	var typed *remoteTargetPolicyError
	if !errors.As(err, &typed) || typed.Code != remoteTargetPolicySignature {
		t.Fatalf("wrong typed error: %T %v", err, err)
	}
}

func TestDeriveRemoteTargetPolicyOffAndUnsignedSelectionCannotClear(t *testing.T) {
	t.Run("unsigned false remains required and advances floor", func(t *testing.T) {
		fixture := newRemoteTargetFixture(t)
		fixture.netmap.Self.RemoteAccessAllowed = false
		got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
		if err != nil || !got.Required || !got.Enabled || len(got.Rules) != 1 {
			t.Fatalf("unsigned selection cleared policy: %#v, %v", got, err)
		}
		stored, ok, err := fixture.daemon.remotePolicyStore.Load(remoteAccessTenantID(fixture.netmap.Self.User))
		if err != nil || !ok || stored.Version != 7 {
			t.Fatalf("policy floor not advanced: %#v, %v, %v", stored, ok, err)
		}
	})
	t.Run("authority signed off", func(t *testing.T) {
		fixture := newRemoteTargetFixture(t)
		var err error
		fixture.netmap.RemoteAccessPolicyState, err = remoteaccess.SignPolicyState(remoteaccess.PolicyState{
			TenantID: remoteAccessTenantID(fixture.netmap.Self.User),
			Version:  8,
			Enabled:  false,
			IssuedAt: fixture.now,
		}, fixture.signer)
		if err != nil {
			t.Fatal(err)
		}
		fixture.netmap.RemoteAccessPolicyVersion = 8
		got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
		if err != nil || got.Required || got.Enabled || got.PolicyVersion != 8 {
			t.Fatalf("off policy = %#v, %v", got, err)
		}
	})
	t.Run("authority signed target off", func(t *testing.T) {
		fixture := newRemoteTargetFixture(t)
		fixture.netmap.RemoteAccessTargetState = signRemoteTargetState(
			t,
			fixture.signer,
			fixture.netmap.RemoteAccessPolicyState,
			remoteAccessTenantID(fixture.netmap.Self.User),
			fixture.netmap.Self.ID,
			7,
			false,
			fixture.now,
		)
		fixture.netmap.Self.RemoteAccessAllowed = true
		got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
		if err != nil || got.Required || got.Enabled || got.PolicyVersion != 7 {
			t.Fatalf("signed target off policy = %#v, %v", got, err)
		}
	})
	t.Run("tampered target state stays closed", func(t *testing.T) {
		fixture := newRemoteTargetFixture(t)
		fixture.netmap.RemoteAccessTargetState.Signature[0] ^= 0xff
		got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
		if err == nil || !got.Required || !got.Enabled || len(got.Rules) != 0 {
			t.Fatalf("tampered target state not closed: %#v, %v", got, err)
		}
		if want := []uint16{22, 2200}; !reflect.DeepEqual(got.ManagedTCPPorts, want) {
			t.Fatalf("tampered target managed ports = %v, want %v", got.ManagedTCPPorts, want)
		}
	})
}

func TestDeriveRemoteTargetPolicyAdvancesNewVersionBeforeMalformedObservations(t *testing.T) {
	fixture := newRemoteTargetFixture(t)
	policy, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: remoteAccessTenantID(fixture.netmap.Self.User),
		Version:  8,
		Enabled:  true,
		IssuedAt: fixture.now,
	}, fixture.signer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.netmap.RemoteAccessPolicyVersion = 8
	fixture.netmap.RemoteAccessPolicyState = policy
	fixture.netmap.RemoteAccessTargetState = signRemoteTargetState(
		t, fixture.signer, policy, remoteAccessTenantID(fixture.netmap.Self.User),
		fixture.netmap.Self.ID, 8, true, fixture.now,
	)
	fixture.netmap.Self.RemoteServices[0].TargetMeshIP = "192.0.2.1"

	got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
	if err == nil || !got.Required || !got.Enabled || got.PolicyVersion != 8 || len(got.Rules) != 0 {
		t.Fatalf("malformed observation not closed at authenticated version: %#v, %v", got, err)
	}
	if want := []uint16{22, 2200}; !reflect.DeepEqual(got.ManagedTCPPorts, want) {
		t.Fatalf("malformed observation managed ports = %v, want %v", got.ManagedTCPPorts, want)
	}
	stored, ok, loadErr := fixture.daemon.remotePolicyStore.Load(remoteAccessTenantID(fixture.netmap.Self.User))
	if loadErr != nil || !ok || stored.Version != 8 {
		t.Fatalf("new revocation floor not retained: %#v, %v, %v", stored, ok, loadErr)
	}
}

func TestDeriveRemoteTargetPolicyVersionBumpInvalidatesOldDirectionalGrant(t *testing.T) {
	fixture := newRemoteTargetFixture(t)
	policy, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: remoteAccessTenantID(fixture.netmap.Self.User),
		Version:  8,
		Enabled:  true,
		IssuedAt: fixture.now,
	}, fixture.signer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.netmap.RemoteAccessPolicyVersion = 8
	fixture.netmap.RemoteAccessPolicyState = policy
	fixture.netmap.RemoteAccessTargetState = signRemoteTargetState(
		t, fixture.signer, policy, remoteAccessTenantID(fixture.netmap.Self.User),
		fixture.netmap.Self.ID, 8, true, fixture.now,
	)
	// The old source remains visible, modelling a reverse-only peer after an
	// ACL update. Its version-7 grant must not survive the version-8 floor.
	got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Required || got.PolicyVersion != 8 || len(got.Rules) != 0 {
		t.Fatalf("old directional grant survived policy bump: %#v", got)
	}
}

func TestDeriveRemoteTargetPolicyWrongPeerServiceExpiryAndRevoke(t *testing.T) {
	tests := map[string]func(*remoteTargetFixture){
		"wrong peer": func(f *remoteTargetFixture) {
			f.netmap.Peers[0].MeshIPs[0] = netip.MustParseAddr("100.64.0.9")
		},
		"missing service": func(f *remoteTargetFixture) {
			f.netmap.Self.RemoteServices = []remoteaccess.ServiceAdvertisement{}
		},
		"expired": func(f *remoteTargetFixture) {
			f.now = f.netmap.RemoteAccessGrants[0].Grant.ExpiresAt
		},
		"revoked by policy floor": func(f *remoteTargetFixture) {
			policy, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
				TenantID: remoteAccessTenantID(f.netmap.Self.User),
				Version:  8,
				Enabled:  true,
				IssuedAt: f.now,
			}, f.signer)
			if err != nil {
				t.Fatal(err)
			}
			f.netmap.RemoteAccessPolicyVersion = 8
			f.netmap.RemoteAccessPolicyState = policy
			f.netmap.RemoteAccessTargetState = signRemoteTargetState(
				t, f.signer, policy, remoteAccessTenantID(f.netmap.Self.User),
				f.netmap.Self.ID, 8, true, f.now,
			)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newRemoteTargetFixture(t)
			mutate(&fixture)
			got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Required || !got.Enabled || len(got.Rules) != 0 {
				t.Fatalf("rejected grant opened access: %#v", got)
			}
		})
	}
}

func TestDeriveRemoteTargetPolicyRejectsDuplicateAndInvalidPeers(t *testing.T) {
	tests := map[string]func(*remoteTargetFixture){
		"duplicate node": func(f *remoteTargetFixture) {
			f.netmap.Peers = append(f.netmap.Peers, types.Node{
				ID: "source-1", MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.4")},
			})
		},
		"duplicate mesh IP": func(f *remoteTargetFixture) {
			f.netmap.Peers = append(f.netmap.Peers, types.Node{
				ID: "source-2", MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
			})
		},
		"invalid first IP": func(f *remoteTargetFixture) {
			f.netmap.Peers[0].MeshIPs[0] = netip.Addr{}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newRemoteTargetFixture(t)
			mutate(&fixture)
			got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
			if err == nil || !got.Required || len(got.Rules) != 0 {
				t.Fatalf("ambiguous peers not closed: %#v, %v", got, err)
			}
		})
	}
}

func TestDeriveRemoteTargetPolicyUsesTrustedLocalPlatformForClosedPorts(t *testing.T) {
	fixture := newRemoteTargetFixture(t)
	fixture.netmap.Self.Platform = "windows"
	got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
	if err == nil || !got.Required || !got.Enabled || len(got.Rules) != 0 {
		t.Fatalf("platform mismatch not closed: %#v, %v", got, err)
	}
	if want := []uint16{22, 2200}; !reflect.DeepEqual(got.ManagedTCPPorts, want) {
		t.Fatalf("platform mismatch managed ports = %v, want %v", got.ManagedTCPPorts, want)
	}
}

func TestDeriveRemoteTargetPolicyRequiresExactPolicyVersion(t *testing.T) {
	fixture := newRemoteTargetFixture(t)
	fixture.netmap.RemoteAccessPolicyVersion++
	got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now)
	if err == nil || !errors.Is(err, errRemoteTargetVersion) ||
		!got.Required || len(got.Rules) != 0 {
		t.Fatalf("version mismatch not closed: %#v, %v", got, err)
	}
}

func TestDeriveRemoteTargetPolicyAdvancesFloorBeforeUnsignedVersionEcho(t *testing.T) {
	fixture := newRemoteTargetFixture(t)
	oldNetmap := fixture.netmap
	if _, err := fixture.daemon.deriveRemoteTargetPolicy(oldNetmap, fixture.now); err != nil {
		t.Fatal(err)
	}
	policy, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: remoteAccessTenantID(fixture.netmap.Self.User),
		Version:  8,
		Enabled:  true,
		IssuedAt: fixture.now.Add(time.Second),
	}, fixture.signer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.netmap.RemoteAccessPolicyState = policy
	fixture.netmap.RemoteAccessPolicyVersion = 7 // untrusted stale echo
	fixture.netmap.RemoteAccessTargetState = signRemoteTargetState(
		t, fixture.signer, policy, remoteAccessTenantID(fixture.netmap.Self.User),
		fixture.netmap.Self.ID, 8, true, fixture.now.Add(time.Second),
	)
	got, err := fixture.daemon.deriveRemoteTargetPolicy(fixture.netmap, fixture.now.Add(time.Second))
	if err == nil || !errors.Is(err, errRemoteTargetVersion) || got.PolicyVersion != 8 {
		t.Fatalf("version echo mismatch = %#v, %v", got, err)
	}
	stored, ok, err := fixture.daemon.remotePolicyStore.Load(remoteAccessTenantID(fixture.netmap.Self.User))
	if err != nil || !ok || stored.Version != 8 {
		t.Fatalf("new signed floor not retained: %#v, %v, %v", stored, ok, err)
	}
	if _, err := fixture.daemon.deriveRemoteTargetPolicy(oldNetmap, fixture.now.Add(2*time.Second)); !errors.Is(err, remoteaccess.ErrPolicyRollback) {
		t.Fatalf("old policy replay error = %v, want rollback", err)
	}
}
