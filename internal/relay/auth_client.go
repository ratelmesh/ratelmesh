package relay

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

const nonceLen = 16

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

// admissionProof authenticates fleet membership while binding the proof to the
// node public key and this handshake's nonce.
func admissionProof(secret []byte, nodePub types.Key, nonce []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(nodePub[:])
	m.Write(nonce)
	return m.Sum(nil)
}
