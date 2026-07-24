package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

// Relay bind is protected by an X25519 proof-of-possession, so a client can only
// bind a public key it actually holds the private half of — an attacker cannot
// squat a victim's public key to hijack its relay path (security review §4).
//
// The relay sends an ephemeral X25519 public key + nonce. The client computes
// the Diffie-Hellman shared secret with its node private key and returns
// HMAC(shared, nonce). The relay recomputes the same shared secret from its
// ephemeral private key and the claimed public key; they match iff the client
// holds the private key for the claimed public key.

const nonceLen = 16

// DeriveClientSecret binds relay admission to one node key. A credential leaked
// by one member therefore cannot be reused to bind another member's key.
func DeriveClientSecret(master []byte, nodePub types.Key) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte("ratelmesh-relay-client-v1"))
	m.Write(nodePub[:])
	return []byte(base64.RawURLEncoding.EncodeToString(m.Sum(nil)))
}

// newChallenge returns an ephemeral X25519 keypair and a random nonce.
func newChallenge() (ephPriv, ephPub [32]byte, nonce [nonceLen]byte, err error) {
	if _, err = rand.Read(ephPriv[:]); err != nil {
		return
	}
	if _, err = rand.Read(nonce[:]); err != nil {
		return
	}
	curve25519.ScalarBaseMult(&ephPub, &ephPriv)
	return
}

// proofFor is the client side: HMAC(X25519(nodePriv, ephPub), nonce).
func proofFor(nodePriv types.Key, ephPub [32]byte, nonce []byte) ([]byte, error) {
	shared, err := curve25519.X25519(nodePriv[:], ephPub[:])
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, shared)
	m.Write(nonce)
	return m.Sum(nil), nil
}

// newNonce returns a random challenge nonce.
func newNonce() ([nonceLen]byte, error) {
	var n [nonceLen]byte
	_, err := rand.Read(n[:])
	return n, err
}

// siblingProof is the shared-secret proof for a relay-to-relay link: HMAC of the
// nonce keyed by the operator's sibling secret (security review §5).
func siblingProof(secret, nonce []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(nonce)
	return m.Sum(nil)
}

func siblingProofValid(secret, nonce, proof []byte) bool {
	return subtle.ConstantTimeCompare(siblingProof(secret, nonce), proof) == 1
}

// verifyProof is the relay side: recompute HMAC(X25519(ephPriv, nodePub), nonce)
// and constant-time compare against the client's proof.
func verifyProof(ephPriv [32]byte, nodePub types.Key, nonce, proof []byte) bool {
	priv := ephPriv // X25519 takes a slice; copy to avoid aliasing the array
	shared, err := curve25519.X25519(priv[:], nodePub[:])
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, shared)
	m.Write(nonce)
	return subtle.ConstantTimeCompare(m.Sum(nil), proof) == 1
}

func admissionProof(secret []byte, nodePub types.Key, nonce []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(nodePub[:])
	m.Write(nonce)
	return m.Sum(nil)
}

func admissionProofValid(secret []byte, nodePub types.Key, nonce, proof []byte) bool {
	return subtle.ConstantTimeCompare(admissionProof(secret, nodePub, nonce), proof) == 1
}
