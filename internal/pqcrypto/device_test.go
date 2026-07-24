package pqcrypto

import (
	"bytes"
	"testing"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

func TestMLKEMSessionProducesSameWireGuardPSK(t *testing.T) {
	recipient, err := LoadOrCreateDeviceKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := LoadOrCreateDeviceKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sharedA, ciphertext, err := Encapsulate(recipient.KEMPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := initiator.SignSession("a", "b", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySession(initiator.MLDSAPublicKey(), "a", "b", ciphertext, sig) {
		t.Fatal("valid ML-DSA session signature rejected")
	}
	sharedB, err := recipient.Decapsulate(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sharedA, sharedB) {
		t.Fatal("ML-KEM shared secrets differ")
	}
	a, _ := types.GenerateKey()
	b, _ := types.GenerateKey()
	pskA := DeriveWireGuardPSK(sharedA, "a", "b", a.Public(), b.Public(), recipient.KEMPublicKey())
	pskB := DeriveWireGuardPSK(sharedB, "a", "b", a.Public(), b.Public(), recipient.KEMPublicKey())
	if pskA != pskB || pskA.IsZero() {
		t.Fatal("derived WireGuard PSKs differ or are zero")
	}
	ciphertext[0] ^= 1
	if VerifySession(initiator.MLDSAPublicKey(), "a", "b", ciphertext, sig) {
		t.Fatal("tampered ciphertext signature verified")
	}
}

func TestDeviceKeysPersist(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreateDeviceKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateDeviceKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.KEMPublicKey(), b.KEMPublicKey()) || !bytes.Equal(a.MLDSAPublicKey(), b.MLDSAPublicKey()) {
		t.Fatal("post-quantum identity changed after reload")
	}
}
