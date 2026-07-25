// Package pop implements an X25519 proof-of-possession: a device proves it holds
// the private key for the WireGuard public key it registers, so a party that
// merely knows the public key cannot register/poison/hijack that node (security
// review §1/§4). WireGuard keys are Curve25519, so the proof is a Diffie-Hellman
// exchange with the coord's static key rather than a signature.
//
// Flow (one round, no challenge trip):
//   - The coord publishes its X25519 public key (GET /v1/coordkey).
//   - The client computes shared = X25519(nodePriv, coordPub) and
//     proof = HMAC-SHA256(shared, context), where context binds a timestamp and
//     the security-relevant request fields.
//   - The coord recomputes shared = X25519(coordPriv, nodePub) and verifies the
//     HMAC and the timestamp window. They match iff the client holds nodePriv.
package pop

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"sort"

	"golang.org/x/crypto/curve25519"

	"github.com/shan25519/ratelmesh/internal/types"
)

// GenerateCoordKey returns a new X25519 keypair for the coord.
func GenerateCoordKey() (priv, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

// PublicFromPrivate derives the X25519 public key from a private key.
func PublicFromPrivate(priv [32]byte) [32]byte {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return pub
}

// Context builds the deterministic bytes bound by the proof: a timestamp (for
// freshness/replay bounding), the node public key, and the security-relevant
// mutable fields (role, advertised routes). Endpoints are intentionally excluded
// — they vary legitimately and are not security-critical.
func Context(proofTime int64, nodePub types.Key, role string, routes []string) []byte {
	var b []byte
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(proofTime))
	b = appendField(b, t[:])
	b = appendField(b, nodePub[:])
	b = appendField(b, []byte(role))
	sorted := append([]string(nil), routes...)
	sort.Strings(sorted)
	for _, r := range sorted {
		b = appendField(b, []byte(r))
	}
	return b
}

// ChallengeContext additionally binds a coordinator-issued one-shot challenge
// and every endpoint that registration can mutate. Replaying a captured proof
// therefore cannot poison reachability, even within the timestamp window.
func ChallengeContext(proofTime int64, nonce string, nodePub types.Key, role string, routes, endpoints, discoEndpoints []string, pqPublicKeys ...[]byte) []byte {
	b := Context(proofTime, nodePub, role, routes)
	b = appendField(b, []byte(nonce))
	for _, values := range [][]string{endpoints, discoEndpoints} {
		sorted := append([]string(nil), values...)
		sort.Strings(sorted)
		for _, value := range sorted {
			b = appendField(b, []byte(value))
		}
		// Preserve the boundary between endpoint classes.
		b = appendField(b, nil)
	}
	hasPQKey := false
	for _, key := range pqPublicKeys {
		hasPQKey = hasPQKey || len(key) > 0
	}
	if hasPQKey {
		for _, key := range pqPublicKeys {
			b = appendField(b, key)
		}
	}
	return b
}

// Prove is the client side: HMAC(X25519(nodePriv, coordPub), context).
func Prove(nodePriv types.Key, coordPub [32]byte, context []byte) ([]byte, error) {
	shared, err := curve25519.X25519(nodePriv[:], coordPub[:])
	if err != nil {
		return nil, err
	}
	return mac(shared, context), nil
}

// Verify is the coord side: recompute the shared secret from its own private key
// and the claimed node public key, then constant-time compare the HMAC.
func Verify(coordPriv [32]byte, nodePub types.Key, context, proof []byte) bool {
	priv := coordPriv
	shared, err := curve25519.X25519(priv[:], nodePub[:])
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(mac(shared, context), proof) == 1
}

func mac(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func appendField(b, field []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	b = append(b, l[:]...)
	return append(b, field...)
}
