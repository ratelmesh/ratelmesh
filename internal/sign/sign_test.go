package sign

import (
	"net/netip"
	"testing"

	"github.com/shan25519/ratelmesh/internal/types"
)

func testNode(t *testing.T) types.Node {
	t.Helper()
	k, _ := types.GenerateKey()
	return types.Node{
		ID: "n-1", User: "alice", Name: "laptop", Key: k.Public(),
		Role: types.RolePlain, Tags: []string{"tag:dev"},
		MeshIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	a, err := GenerateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	n := testNode(t)
	sig := a.Sign(n)
	if !Verify(a.PublicKey(), n, sig) {
		t.Fatal("valid signature failed to verify")
	}
}

func TestTamperedKeyFailsVerification(t *testing.T) {
	a, _ := GenerateAuthority()
	n := testNode(t)
	sig := a.Sign(n)

	// A compromised coord swaps the peer's WireGuard key (the MITM attack §5
	// prevents). The old signature must no longer verify.
	attacker, _ := types.GenerateKey()
	n.Key = attacker.Public()
	if Verify(a.PublicKey(), n, sig) {
		t.Fatal("signature verified after the WireGuard key was swapped")
	}
}

func TestTamperedTagsFailVerification(t *testing.T) {
	a, _ := GenerateAuthority()
	n := testNode(t)
	sig := a.Sign(n)
	n.Tags = append(n.Tags, "tag:admin") // privilege escalation attempt
	if Verify(a.PublicKey(), n, sig) {
		t.Fatal("signature verified after tags were changed")
	}
}

func TestRouteSignatureRejectsTamperedAllowedIPs(t *testing.T) {
	a, _ := GenerateAuthority()
	n := testNode(t)
	n.AllowedIPs = []string{"100.64.0.1/32"}
	sig := a.SignRoutes(n)
	if !VerifyRoutes(a.PublicKey(), n, sig) {
		t.Fatal("valid route signature failed to verify")
	}
	n.AllowedIPs = append(n.AllowedIPs, "0.0.0.0/0")
	if VerifyRoutes(a.PublicKey(), n, sig) {
		t.Fatal("route signature verified after AllowedIPs were changed")
	}
}

func TestRouteSignatureIgnoresVolatileFields(t *testing.T) {
	a, _ := GenerateAuthority()
	n := testNode(t)
	n.AllowedIPs = []string{"100.64.0.1/32"}
	sig := a.SignRoutes(n)
	n.Endpoints = []string{"203.0.113.9:51820"}
	n.DiscoEndpoints = []string{"203.0.113.9:51821"}
	n.Online = true
	if !VerifyRoutes(a.PublicKey(), n, sig) {
		t.Fatal("route signature broke on a volatile-field change")
	}
}

func TestVolatileFieldsDoNotAffectSignature(t *testing.T) {
	a, _ := GenerateAuthority()
	n := testNode(t)
	sig := a.Sign(n)
	// Endpoints/online/lastSeen change as a node roams; the signature must hold.
	n.Endpoints = []string{"203.0.113.9:51820"}
	n.Online = true
	if !Verify(a.PublicKey(), n, sig) {
		t.Fatal("signature broke on a volatile-field change")
	}
}

func TestWrongAuthorityRejected(t *testing.T) {
	a, _ := GenerateAuthority()
	other, _ := GenerateAuthority()
	n := testNode(t)
	sig := a.Sign(n)
	if Verify(other.PublicKey(), n, sig) {
		t.Fatal("signature verified under a different authority key")
	}
}

func TestPublicKeyStringRoundTrip(t *testing.T) {
	a, _ := GenerateAuthority()
	pub, err := ParsePublicKey(a.PublicKeyString())
	if err != nil {
		t.Fatal(err)
	}
	n := testNode(t)
	if !Verify(pub, n, a.Sign(n)) {
		t.Fatal("verify failed with a round-tripped public key")
	}
}

func TestHybridMLDSAAuthoritySignatures(t *testing.T) {
	a, err := GenerateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	n := testNode(t)
	n.PQKEMPublicKey = []byte("kem-public-key")
	n.PQSigningPublicKey = []byte("mldsa-device-key")
	identitySig := a.SignPQ(n)
	routeSig := a.SignRoutesPQ(n)
	if !VerifyPQ(a.PQPublicKey(), n, identitySig) || !VerifyRoutesPQ(a.PQPublicKey(), n, routeSig) {
		t.Fatal("valid ML-DSA authority signatures rejected")
	}
	n.PQKEMPublicKey[0] ^= 1
	if VerifyPQ(a.PQPublicKey(), n, identitySig) || VerifyRoutesPQ(a.PQPublicKey(), n, routeSig) {
		t.Fatal("ML-DSA signature accepted a substituted ML-KEM key")
	}
}
