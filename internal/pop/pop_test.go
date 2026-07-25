package pop

import (
	"testing"
	"time"

	"github.com/shan25519/ratelmesh/internal/types"
)

func TestProveVerifyRoundTrip(t *testing.T) {
	coordPriv, coordPub, err := GenerateCoordKey()
	if err != nil {
		t.Fatal(err)
	}
	nodePriv, _ := types.GenerateKey()
	nodePub := nodePriv.Public()

	ctx := Context(time.Now().Unix(), nodePub, "plain", []string{"10.0.0.0/8"})
	proof, err := Prove(nodePriv, coordPub, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(coordPriv, nodePub, ctx, proof) {
		t.Fatal("valid proof failed to verify")
	}
}

func TestAttackerWithoutPrivateKeyCannotProve(t *testing.T) {
	coordPriv, coordPub, _ := GenerateCoordKey()
	victim, _ := types.GenerateKey()
	attacker, _ := types.GenerateKey()
	victimPub := victim.Public()

	ctx := Context(time.Now().Unix(), victimPub, "exit", nil)
	// Attacker knows victimPub but not victim's private key; its proof (computed
	// with its own key) must not verify for victimPub.
	forged, _ := Prove(attacker, coordPub, ctx)
	if Verify(coordPriv, victimPub, ctx, forged) {
		t.Fatal("proof for a key the attacker does not hold was accepted")
	}
}

func TestContextBindingDetectsTamper(t *testing.T) {
	coordPriv, coordPub, _ := GenerateCoordKey()
	nodePriv, _ := types.GenerateKey()
	nodePub := nodePriv.Public()
	now := time.Now().Unix()

	proof, _ := Prove(nodePriv, coordPub, Context(now, nodePub, "plain", []string{"10.0.0.0/8"}))

	// A verifier checking a DIFFERENT role/routes context must reject the proof.
	if Verify(coordPriv, nodePub, Context(now, nodePub, "exit", []string{"10.0.0.0/8"}), proof) {
		t.Error("role tamper not detected")
	}
	if Verify(coordPriv, nodePub, Context(now, nodePub, "plain", []string{"0.0.0.0/0"}), proof) {
		t.Error("route tamper not detected")
	}
	if Verify(coordPriv, nodePub, Context(now+3600, nodePub, "plain", []string{"10.0.0.0/8"}), proof) {
		t.Error("timestamp tamper not detected")
	}
}

func TestWrongCoordKeyRejected(t *testing.T) {
	_, coordPub, _ := GenerateCoordKey()
	otherPriv, _, _ := GenerateCoordKey()
	nodePriv, _ := types.GenerateKey()
	nodePub := nodePriv.Public()
	ctx := Context(time.Now().Unix(), nodePub, "plain", nil)
	proof, _ := Prove(nodePriv, coordPub, ctx)
	if Verify(otherPriv, nodePub, ctx, proof) {
		t.Fatal("proof verified under a different coord key")
	}
}

func TestPublicFromPrivateMatchesGenerate(t *testing.T) {
	priv, pub, _ := GenerateCoordKey()
	if PublicFromPrivate(priv) != pub {
		t.Fatal("derived public key mismatch")
	}
}
