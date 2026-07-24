// Package sign implements node-credential signing (the "key authority" of
// DESIGN.md §5). An offline authority signs the binding between a device's
// identity and its WireGuard public key; clients verify that signature before
// trusting a peer. This defends against a compromised coord: even though the
// coord distributes the netmap, it cannot forge a peer with an attacker's key,
// because it lacks the authority's signing key (in a hardened deployment the
// authority key is kept offline and only used at enrollment).
package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net/netip"
	"os"
	"sort"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/ratelmesh/ratelmesh/internal/types"
)

// Authority holds the signing key. In production this lives offline; the coord
// only needs the public half to distribute and clients only need the public
// half to verify.
type Authority struct {
	priv   ed25519.PrivateKey
	pqPriv *mldsa65.PrivateKey
}

// GenerateAuthority creates a fresh Ed25519 authority key.
func GenerateAuthority() (*Authority, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, pqPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authority{priv: priv, pqPriv: pqPriv}, nil
}

// LoadOrCreate loads an authority key from path (base64 seed) or creates and
// persists one on first use.
func LoadOrCreate(path string) (*Authority, error) {
	if b, err := os.ReadFile(path); err == nil {
		seed, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(b)))
		if err == nil && len(seed) == ed25519.SeedSize {
			pqPriv, pqErr := loadOrCreateMLDSA(path + ".mldsa65")
			if pqErr != nil {
				return nil, pqErr
			}
			return &Authority{priv: ed25519.NewKeyFromSeed(seed), pqPriv: pqPriv}, nil
		}
	}
	a, err := GenerateAuthority()
	if err != nil {
		return nil, err
	}
	seed := a.priv.Seed()
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed)), 0o600); err != nil {
		return nil, err
	}
	if err := persistMLDSA(path+".mldsa65", a.pqPriv); err != nil {
		return nil, err
	}
	return a, nil
}

func loadOrCreateMLDSA(path string) (*mldsa65.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		seedBytes, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data)))
		if err != nil || len(seedBytes) != mldsa65.SeedSize {
			return nil, ErrBadKey
		}
		var seed [mldsa65.SeedSize]byte
		copy(seed[:], seedBytes)
		_, priv := mldsa65.NewKeyFromSeed(&seed)
		return priv, nil
	}
	_, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := persistMLDSA(path, priv); err != nil {
		return nil, err
	}
	return priv, nil
}

func persistMLDSA(path string, priv *mldsa65.PrivateKey) error {
	seed := priv.Seed()
	if len(seed) != mldsa65.SeedSize {
		return ErrBadKey
	}
	return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed)), 0o600)
}

// PublicKey returns the authority's public key (distributed to clients).
func (a *Authority) PublicKey() ed25519.PublicKey {
	return a.priv.Public().(ed25519.PublicKey)
}

// PublicKeyString returns the base64 public key for config/flags.
func (a *Authority) PublicKeyString() string {
	return base64.StdEncoding.EncodeToString(a.PublicKey())
}

func (a *Authority) PQPublicKey() *mldsa65.PublicKey {
	return a.pqPriv.Public().(*mldsa65.PublicKey)
}

func (a *Authority) PQPublicKeyString() string {
	return base64.StdEncoding.EncodeToString(a.PQPublicKey().Bytes())
}

// Sign returns a signature over the node's identity→key binding.
func (a *Authority) Sign(n types.Node) []byte {
	return ed25519.Sign(a.priv, canonical(n))
}

// SignRoutes signs the complete stable routing credential. It is separate from
// the legacy identity-only signature so old clients continue to verify Sig
// during a rolling upgrade.
func (a *Authority) SignRoutes(n types.Node) []byte {
	return ed25519.Sign(a.priv, routeCanonical(n))
}

func (a *Authority) SignPQ(n types.Node) []byte {
	sig := make([]byte, mldsa65.SignatureSize)
	_ = mldsa65.SignTo(a.pqPriv, pqCanonical(canonical(n), n), []byte("RatelMesh-Node-v1"), false, sig)
	return sig
}

func (a *Authority) SignRoutesPQ(n types.Node) []byte {
	sig := make([]byte, mldsa65.SignatureSize)
	_ = mldsa65.SignTo(a.pqPriv, pqCanonical(routeCanonical(n), n), []byte("RatelMesh-Routes-v1"), false, sig)
	return sig
}

// ParsePublicKey decodes a base64 authority public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, ErrBadKey
	}
	return ed25519.PublicKey(b), nil
}

func ParsePQPublicKey(s string) (*mldsa65.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != mldsa65.PublicKeySize {
		return nil, ErrBadKey
	}
	var key mldsa65.PublicKey
	if err := key.UnmarshalBinary(b); err != nil {
		return nil, ErrBadKey
	}
	return &key, nil
}

// Verify reports whether sig is a valid authority signature for n.
func Verify(pub ed25519.PublicKey, n types.Node, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) == 0 {
		return false
	}
	return ed25519.Verify(pub, canonical(n), sig)
}

// VerifyRoutes verifies the stable identity, key and authoritative routes.
func VerifyRoutes(pub ed25519.PublicKey, n types.Node, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) == 0 {
		return false
	}
	return ed25519.Verify(pub, routeCanonical(n), sig)
}

func VerifyPQ(pub *mldsa65.PublicKey, n types.Node, sig []byte) bool {
	return pub != nil && len(sig) == mldsa65.SignatureSize && mldsa65.Verify(pub, pqCanonical(canonical(n), n), []byte("RatelMesh-Node-v1"), sig)
}

func VerifyRoutesPQ(pub *mldsa65.PublicKey, n types.Node, sig []byte) bool {
	return pub != nil && len(sig) == mldsa65.SignatureSize && mldsa65.Verify(pub, pqCanonical(routeCanonical(n), n), []byte("RatelMesh-Routes-v1"), sig)
}

// routeCanonical uses length-prefixed fields so delimiter ambiguity cannot
// weaken the route credential. Volatile endpoint/liveness fields and both
// signatures are deliberately excluded.
func routeCanonical(n types.Node) []byte {
	var b bytes.Buffer
	writeBytes := func(v []byte) {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(v)))
		b.Write(v)
	}
	writeString := func(v string) { writeBytes([]byte(v)) }
	writeString(n.ID)
	writeString(n.User)
	writeString(n.Name)
	writeBytes(n.Key[:])
	writeString(string(n.Role))
	for _, values := range [][]string{
		sortedStrings(n.Tags),
		sortedAddrs(n.MeshIPs),
		sortedStrings(n.AllowedIPs),
	} {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(values)))
		for _, value := range values {
			writeString(value)
		}
	}
	return b.Bytes()
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func sortedAddrs(values []netip.Addr) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = value.String()
	}
	sort.Strings(out)
	return out
}

// canonical produces the deterministic bytes that are signed: the security-
// relevant binding of identity to WireGuard key. Volatile fields (endpoints,
// online, lastSeen, the signature itself) are excluded so signatures stay valid
// as a node roams.
func canonical(n types.Node) []byte {
	var b bytes.Buffer
	writeField := func(s string) { b.WriteString(s); b.WriteByte(0) }
	writeField(n.ID)
	writeField(n.User)
	writeField(n.Name)
	b.Write(n.Key[:])
	b.WriteByte(0)
	writeField(string(n.Role))
	tags := append([]string(nil), n.Tags...)
	sort.Strings(tags)
	for _, t := range tags {
		writeField(t)
	}
	b.WriteByte(0)
	ips := make([]string, len(n.MeshIPs))
	for i, ip := range n.MeshIPs {
		ips[i] = ip.String()
	}
	sort.Strings(ips)
	for _, ip := range ips {
		writeField(ip)
	}
	return b.Bytes()
}

func writeCanonicalBytes(b *bytes.Buffer, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	b.Write(size[:])
	b.Write(value)
}

// pqCanonical extends the legacy Ed25519 canonical form without changing it,
// so old clients keep verifying during rollout while ML-DSA binds both new
// post-quantum device keys.
func pqCanonical(legacy []byte, n types.Node) []byte {
	var b bytes.Buffer
	b.Write(legacy)
	writeCanonicalBytes(&b, n.PQKEMPublicKey)
	writeCanonicalBytes(&b, n.PQSigningPublicKey)
	return b.Bytes()
}

// ErrBadKey is returned for a malformed authority key.
var ErrBadKey = errBadKey{}

type errBadKey struct{}

func (errBadKey) Error() string { return "sign: bad authority public key length" }
