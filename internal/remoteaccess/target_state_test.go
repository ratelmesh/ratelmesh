package remoteaccess

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestTargetStateBindsPolicyDigestAndTarget(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	signer := Ed25519Signer{PrivateKey: privateKey}
	verifier := Ed25519Verifier{PublicKey: publicKey}
	signedPolicy, err := SignPolicyState(PolicyState{
		TenantID: "tenant-a",
		Version:  7,
		Enabled:  true,
		IssuedAt: now,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := VerifyPolicyState(signedPolicy, verifier, "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignTargetState(TargetState{
		TenantID:      policy.TenantID,
		PolicyVersion: policy.Version,
		PolicyDigest:  policy.Digest,
		TargetNodeID:  "n-0123456789abcdef",
		Enabled:       true,
		IssuedAt:      policy.IssuedAt,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyTargetState(signed, verifier, policy, "n-0123456789abcdef", now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.PolicyVersion != 7 {
		t.Fatalf("verified target state = %+v", got)
	}

	otherPolicy := policy
	otherPolicy.Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := VerifyTargetState(signed, verifier, otherPolicy, got.TargetNodeID, now); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("digest mismatch error = %v, want binding mismatch", err)
	}
	if _, err := VerifyTargetState(signed, verifier, policy, "n-fedcba9876543210", now); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("target mismatch error = %v, want binding mismatch", err)
	}
}

func TestTargetStateRejectsTamperingAndNonCanonicalPayload(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	signer := Ed25519Signer{PrivateKey: privateKey}
	verifier := Ed25519Verifier{PublicKey: publicKey}
	signedPolicy, err := SignPolicyState(PolicyState{
		TenantID: "tenant-a", Version: 2, Enabled: true, IssuedAt: now,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := VerifyPolicyState(signedPolicy, verifier, "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignTargetState(TargetState{
		TenantID: policy.TenantID, PolicyVersion: policy.Version,
		PolicyDigest: policy.Digest, TargetNodeID: "n-0123456789abcdef",
		IssuedAt: policy.IssuedAt,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	tampered := signed
	tampered.Payload = append([]byte(nil), signed.Payload...)
	tampered.Payload[len(tampered.Payload)-2] ^= 1
	if _, err := VerifyTargetState(tampered, verifier, policy, "n-0123456789abcdef", now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tamper error = %v, want invalid signature", err)
	}

	payload := append(append([]byte(nil), signed.Payload...), []byte(`{}`)...)
	signature, err := signer.Sign(targetStateSigningMessage(payload))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTargetState(
		SignedTargetState{Payload: payload, Signature: signature},
		verifier,
		policy,
		"n-0123456789abcdef",
		now,
	); !errors.Is(err, ErrInvalidPolicyState) {
		t.Fatalf("trailing payload error = %v, want invalid policy state", err)
	}
}
