package remoteaccess

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestCrypto_SignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer := Ed25519Signer{PrivateKey: priv}
	verifier := Ed25519Verifier{PublicKey: pub}
	wrongVerifier := Ed25519Verifier{PublicKey: pub2}

	now := time.Now()
	grant := &Grant{
		ID:            "g1",
		TenantID:      "t1",
		GrantorID:     "u1",
		GranteeID:     "u2",
		GranteeMeshIP: "100.64.0.2",
		PolicyVersion: 5,
		Service: ServiceAdvertisement{
			Kind:         KindSSH,
			Port:         22,
			Platform:     PlatformLinux,
			Label:        "Linux SSH",
			TargetNodeID: "node1",
			TargetMeshIP: "100.64.0.1",
		},
		IssuedAt:  now,
		NotBefore: now,
		ExpiresAt: now.Add(time.Hour),
	}

	ctx := VerificationContext{
		Now:                   now.Add(time.Minute),
		TenantID:              "t1",
		GranteeID:             "u2",
		ExpectedGranteeMeshIP: "100.64.0.2",
		MinPolicyVersion:      5,
		TargetNodeID:          "node1",
		ExpectedKind:          KindSSH,
		ExpectedPort:          22,
		ExpectedPlatform:      PlatformLinux,
		ExpectedMeshIP:        "100.64.0.1",
	}

	data, sig, err := SignGrant(grant, signer)
	if err != nil {
		t.Fatalf("SignGrant failed: %v", err)
	}
	if ed25519.Verify(pub, data, sig) {
		t.Fatal("grant signature verified without the remote-access domain separator")
	}

	// 1. Valid verification
	verified, err := VerifyGrant(data, sig, verifier, ctx)
	if err != nil {
		t.Errorf("VerifyGrant failed: %v", err)
	}
	if verified != nil && verified.ID != grant.ID {
		t.Errorf("got id %q, want %q", verified.ID, grant.ID)
	}

	// 2. Binding mismatch tests
	badCtx := ctx
	badCtx.GranteeID = "u3"
	_, err = VerifyGrant(data, sig, verifier, badCtx)
	if err != ErrBindingMismatch {
		t.Errorf("expected ErrBindingMismatch for bad grantee, got: %v", err)
	}

	badCtx = ctx
	badCtx.ExpectedPlatform = PlatformMacOS
	_, err = VerifyGrant(data, sig, verifier, badCtx)
	if err != ErrBindingMismatch {
		t.Errorf("expected ErrBindingMismatch for bad platform, got: %v", err)
	}

	badCtx = ctx
	badCtx.ExpectedMeshIP = "100.64.0.2"
	_, err = VerifyGrant(data, sig, verifier, badCtx)
	if err != ErrBindingMismatch {
		t.Errorf("expected ErrBindingMismatch for bad mesh IP, got: %v", err)
	}

	badCtx = ctx
	badCtx.ExpectedGranteeMeshIP = "100.64.0.9"
	_, err = VerifyGrant(data, sig, verifier, badCtx)
	if err != ErrBindingMismatch {
		t.Errorf("expected ErrBindingMismatch for bad grantee mesh IP, got: %v", err)
	}

	// 3. Stale grant (PolicyVersion too low)
	staleCtx := ctx
	staleCtx.MinPolicyVersion = 6
	_, err = VerifyGrant(data, sig, verifier, staleCtx)
	if err != ErrStaleGrant {
		t.Errorf("expected ErrStaleGrant for low policy version, got: %v", err)
	}

	// 4. Chronology invalidation (exclusive expiry)
	expiredCtx := ctx
	expiredCtx.Now = grant.ExpiresAt // exactly at expiration must be expired
	_, err = VerifyGrant(data, sig, verifier, expiredCtx)
	if err != ErrGrantExpired {
		t.Errorf("expected ErrGrantExpired exactly at ExpiresAt, got: %v", err)
	}

	// 5. Tampered data
	tamperedData := append([]byte(nil), data...)
	tamperedData[10] ^= 0xFF
	_, err = VerifyGrant(tamperedData, sig, verifier, ctx)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for tampered data, got: %v", err)
	}

	tamperedSig := append([]byte(nil), sig...)
	tamperedSig[10] ^= 0xFF
	_, err = VerifyGrant(data, tamperedSig, verifier, ctx)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for tampered signature, got: %v", err)
	}

	// 5.5 Wrong verifier (cross-authority)
	_, err = VerifyGrant(data, sig, wrongVerifier, ctx)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for wrong verifier, got: %v", err)
	}

	// 6. Large payload bounds
	hugeData := make([]byte, MaxSignedPayloadSize+1)
	_, err = VerifyGrant(hugeData, sig, verifier, ctx)
	if err != ErrPayloadTooLarge {
		t.Errorf("expected ErrPayloadTooLarge for huge data, got: %v", err)
	}

	// 7. Test deterministic serialization across goroutines (race safety)
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			d, _, e := SignGrant(grant, signer)
			if e != nil {
				t.Errorf("concurrent sign failed: %v", e)
			}
			if !bytes.Equal(d, data) {
				t.Errorf("non-deterministic JSON marshaling detected")
			}
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	// 8. SignGrant must reject structurally invalid grants
	badGrant := *grant
	badGrant.Service.Port = 0 // Invalid port
	_, _, err = SignGrant(&badGrant, signer)
	if err != ErrInvalidPort {
		t.Errorf("expected ErrInvalidPort when signing structurally invalid grant, got: %v", err)
	}
}
