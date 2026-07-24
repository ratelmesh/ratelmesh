// Package types holds the platform-independent data model shared by every HB
// Mesh component (coord, ratelmeshd, CLI). These structs are the public contract
// between the control plane and the clients; in a later milestone they graduate
// to protobuf messages (see DESIGN.md §4), but the JSON shape here is the M1
// long-poll wire format.
package types

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Key is a WireGuard Curve25519 key (public or private), 32 bytes.
// Its JSON representation is standard base64, matching `wg` tooling.
type Key [32]byte

// GenerateKey returns a new random Curve25519 private key with the clamping
// WireGuard expects.
func GenerateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, err
	}
	// Curve25519 clamping.
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}

// Public derives the public key from a private key.
func (priv Key) Public() Key {
	var pub Key
	p := (*[32]byte)(&pub)
	s := (*[32]byte)(&priv)
	curve25519.ScalarBaseMult(p, s)
	return pub
}

// IsZero reports whether the key is all zeros (unset).
func (k Key) IsZero() bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// String returns the base64 encoding, matching WireGuard's textual form.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// ShortString returns an abbreviated key for logs (first 8 base64 chars).
func (k Key) ShortString() string {
	s := k.String()
	if len(s) > 8 {
		return s[:8] + "…"
	}
	return s
}

// ParseKey decodes a base64-encoded key.
func ParseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("parse key: %w", err)
	}
	if len(b) != 32 {
		return Key{}, errors.New("parse key: want 32 bytes")
	}
	var k Key
	copy(k[:], b)
	return k, nil
}

func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *Key) UnmarshalText(text []byte) error {
	parsed, err := ParseKey(string(text))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}
