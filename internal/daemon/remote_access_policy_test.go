package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/remoteaccess"
	"github.com/ratelmesh/ratelmesh/internal/types"
)

func TestAuthenticateRemoteAccessNetmapRequiresExactSignedGrant(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	user := "alice@example.com"
	tenantID := remoteAccessTenantID(user)
	signer := remoteaccess.Ed25519Signer{PrivateKey: privateKey}
	policy, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: tenantID,
		Version:  7,
		Enabled:  true,
		IssuedAt: now,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := remoteaccess.PolicyPayloadDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	targetState, err := remoteaccess.SignTargetState(remoteaccess.TargetState{
		TenantID:      tenantID,
		PolicyVersion: 7,
		PolicyDigest:  policyDigest,
		TargetNodeID:  "source",
		Enabled:       false,
		IssuedAt:      now,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	service := remoteaccess.ServiceAdvertisement{
		Kind:         remoteaccess.KindSSH,
		Port:         22,
		Platform:     remoteaccess.PlatformLinux,
		Label:        "SSH",
		TargetNodeID: "target",
		TargetMeshIP: "100.64.0.2",
	}
	grant := remoteaccess.Grant{
		ID:            "grant-1",
		TenantID:      tenantID,
		GrantorID:     tenantID,
		GranteeID:     "source",
		GranteeMeshIP: "100.64.0.1",
		PolicyVersion: 7,
		Service:       service,
		IssuedAt:      now,
		NotBefore:     now,
		ExpiresAt:     now.Add(5 * time.Minute),
	}
	payload, signature, err := remoteaccess.SignGrant(&grant, signer)
	if err != nil {
		t.Fatal(err)
	}
	nm := types.Netmap{
		RemoteAccessPolicyVersion: 7,
		RemoteAccessPolicyState:   policy,
		RemoteAccessTargetState:   targetState,
		RemoteAccessGrants: []remoteaccess.SignedGrant{{
			Grant: grant, Payload: payload, Signature: signature,
		}},
		Self: types.Node{
			ID: "source", User: user, Platform: "macos",
			MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		},
		Peers: []types.Node{{
			ID: "target", User: user, Platform: "linux",
			MeshIPs:             []netip.Addr{netip.MustParseAddr("100.64.0.2")},
			RemoteAccessAllowed: true,
			RemoteServices:      []remoteaccess.ServiceAdvertisement{service},
		}},
	}
	d := &Daemon{
		cfg:               Config{VerifyKey: publicKey},
		log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		remotePolicyStore: remoteaccess.NewMemoryPolicyFloorStore(),
	}
	view := d.authenticateRemoteAccessNetmap(nm, now)
	services := view.servicesFor(nm.Peers[0], now)
	if len(services) != 1 || services[0] != service {
		t.Fatalf("authorized services = %+v", services)
	}
	if got := view.servicesFor(nm.Peers[0], grant.ExpiresAt); len(got) != 0 {
		t.Fatalf("expired authorization remained: %+v", got)
	}
	unsignedFlip := nm
	unsignedFlip.Self.RemoteAccessAllowed = true
	if got := d.authenticateRemoteAccessNetmap(unsignedFlip, now); got.selfAllowed {
		t.Fatal("unsigned self flag overrode signed target disable")
	}

	tamperedTarget := nm
	tamperedTarget.RemoteAccessTargetState.Signature = append([]byte(nil), nm.RemoteAccessTargetState.Signature...)
	tamperedTarget.RemoteAccessTargetState.Signature[0] ^= 0xff
	tamperedTarget.Self.RemoteAccessAllowed = true
	tamperedTargetView := d.authenticateRemoteAccessNetmap(tamperedTarget, now)
	if tamperedTargetView.selfAllowed || len(tamperedTargetView.servicesFor(nm.Peers[0], now)) != 0 {
		t.Fatal("tampered target activation retained remote access")
	}

	tampered := nm
	tampered.RemoteAccessGrants = append([]remoteaccess.SignedGrant(nil), nm.RemoteAccessGrants...)
	tampered.RemoteAccessGrants[0].Grant.Service.Port = 3389
	tamperedView := d.authenticateRemoteAccessNetmap(tampered, now)
	if len(tamperedView.servicesFor(tampered.Peers[0], now)) != 0 {
		t.Fatal("signed payload cache tamper retained launcher")
	}

	badSignature := nm
	badSignature.RemoteAccessGrants = append([]remoteaccess.SignedGrant(nil), nm.RemoteAccessGrants...)
	badSignature.RemoteAccessGrants[0].Signature = append([]byte(nil), nm.RemoteAccessGrants[0].Signature...)
	badSignature.RemoteAccessGrants[0].Signature[0] ^= 0xff
	badView := d.authenticateRemoteAccessNetmap(badSignature, now)
	if len(badView.servicesFor(badSignature.Peers[0], now)) != 0 {
		t.Fatalf("bad signature retained launcher: %+v", badView)
	}

	redirected := nm
	redirected.Peers = append([]types.Node(nil), nm.Peers...)
	redirected.Peers = append(redirected.Peers, types.Node{
		ID: "target", User: user, Platform: "linux",
		MeshIPs: []netip.Addr{netip.MustParseAddr("192.168.1.50")},
	})
	redirectView := d.authenticateRemoteAccessNetmap(redirected, now)
	if len(redirectView.servicesFor(redirected.Peers[1], now)) != 0 {
		t.Fatal("authorization was transferred to an unsigned target address")
	}
	if got := redirectView.servicesFor(redirected.Peers[0], now); len(got) != 1 {
		t.Fatalf("exact signed target lost authorization: %+v", got)
	}
}

func TestAuthenticateRemoteAccessNetmapRejectsPolicyRollback(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := remoteaccess.Ed25519Signer{PrivateKey: privateKey}
	now := time.Now().UTC()
	tenantID := remoteAccessTenantID("alice@example.com")
	store := remoteaccess.NewMemoryPolicyFloorStore()
	newer, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: tenantID, Version: 9, Enabled: true, IssuedAt: now,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := remoteaccess.VerifyPolicyState(newer, remoteaccess.Ed25519Verifier{PublicKey: publicKey}, tenantID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Advance(verified); err != nil {
		t.Fatal(err)
	}
	older, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: tenantID, Version: 8, Enabled: true, IssuedAt: now.Add(-time.Minute),
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	nm := types.Netmap{
		RemoteAccessPolicyVersion: 8,
		RemoteAccessPolicyState:   older,
		Self: types.Node{
			ID: "source", User: "alice@example.com", Platform: "macos",
			MeshIPs:             []netip.Addr{netip.MustParseAddr("100.64.0.1")},
			RemoteAccessAllowed: true,
		},
		Peers: []types.Node{{
			ID: "target", Platform: "linux",
			MeshIPs:             []netip.Addr{netip.MustParseAddr("100.64.0.2")},
			RemoteAccessAllowed: true,
		}},
	}
	d := &Daemon{
		cfg:               Config{VerifyKey: publicKey},
		log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		remotePolicyStore: store,
	}
	view := d.authenticateRemoteAccessNetmap(nm, now)
	if view.selfAllowed || len(view.servicesFor(nm.Peers[0], now)) != 0 {
		t.Fatal("rolled-back policy retained remote access")
	}
}

type countingPolicyStore struct {
	inner    *remoteaccess.MemoryPolicyFloorStore
	advances int
}

func (s *countingPolicyStore) Load(tenantID string) (remoteaccess.VerifiedPolicyState, bool, error) {
	return s.inner.Load(tenantID)
}

func (s *countingPolicyStore) Advance(state remoteaccess.VerifiedPolicyState) error {
	s.advances++
	return s.inner.Advance(state)
}

func TestRemoteAccessPolicyUsesOneAtomicAdvancePerNetmap(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tenantID := remoteAccessTenantID("alice@example.com")
	signed, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: tenantID, Version: 3, Enabled: true, IssuedAt: now,
	}, remoteaccess.Ed25519Signer{PrivateKey: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	store := &countingPolicyStore{inner: remoteaccess.NewMemoryPolicyFloorStore()}
	d := &Daemon{
		cfg: Config{VerifyKey: publicKey}, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		remotePolicyStore: store,
	}
	nm := types.Netmap{
		RemoteAccessPolicyVersion: 3, RemoteAccessPolicyState: signed,
		Self: types.Node{ID: "source", User: "alice@example.com"},
	}
	before := nm
	d.authenticateRemoteAccessNetmap(nm, now)
	d.authenticateRemoteAccessNetmap(nm, now.Add(time.Second))
	if store.advances != 2 {
		t.Fatalf("atomic policy advances = %d, want one per netmap", store.advances)
	}
	if !reflect.DeepEqual(nm, before) {
		t.Fatal("authorization derivation mutated the raw netmap")
	}
}

func TestRemoteAccessRevocationSurvivesDataPlaneApplyFailure(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	user := "alice@example.com"
	policy, err := remoteaccess.SignPolicyState(remoteaccess.PolicyState{
		TenantID: remoteAccessTenantID(user),
		Version:  8,
		Enabled:  false,
		IssuedAt: now,
	}, remoteaccess.Ed25519Signer{PrivateKey: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Config{
		CoordURL:  "http://127.0.0.1:8080",
		StateDir:  t.TempDir(),
		Hostname:  "source",
		VerifyKey: publicKey,
		Engine:    &failingReconfigureEngine{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	service := remoteaccess.ServiceAdvertisement{
		Kind: remoteaccess.KindSSH, Port: 22, Platform: remoteaccess.PlatformLinux,
		TargetNodeID: "target", TargetMeshIP: "100.64.0.2",
	}
	peer := types.Node{
		ID: "target", Platform: "linux",
		MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
	}
	d.lastNetmap = types.Netmap{
		Version: 4,
		Self: types.Node{
			ID: "source", User: user,
			MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		},
		Peers: []types.Node{peer},
	}
	d.remoteAccess = remoteAccessView{
		selfAllowed: true,
		services: map[remoteTargetKey][]remoteAuthorizedService{
			{nodeID: peer.ID, meshIP: "100.64.0.2", platform: peer.Platform}: {{
				service: service, expiresAt: now.Add(time.Hour),
			}},
		},
	}
	d.status = Status{
		Version: 4,
		Self: PeerStatus{
			RemoteAccessAllowed: true,
			RemoteServices:      []remoteaccess.ServiceAdvertisement{service},
		},
		Peers: []PeerStatus{{
			MeshIP:              "100.64.0.2",
			RemoteAccessAllowed: true,
			RemoteServices:      []remoteaccess.ServiceAdvertisement{service},
		}},
	}

	err = d.applyNetmap(types.Netmap{
		Version: 5,
		Self: types.Node{
			ID: "source", User: user,
			MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		},
		RemoteAccessPolicyVersion: 8,
		RemoteAccessPolicyState:   policy,
	})
	if err == nil {
		t.Fatal("data-plane apply unexpectedly succeeded")
	}
	status := d.Status()
	if status.Self.RemoteAccessAllowed || len(status.Self.RemoteServices) != 0 {
		t.Fatalf("revoked local presentation survived: %+v", status.Self)
	}
	if len(status.Peers) != 1 || status.Peers[0].RemoteAccessAllowed || len(status.Peers[0].RemoteServices) != 0 {
		t.Fatalf("revoked peer launcher survived: %+v", status.Peers)
	}
	if d.lastNetmap.Version != 4 {
		t.Fatalf("failed data-plane apply committed netmap version %d", d.lastNetmap.Version)
	}
}
