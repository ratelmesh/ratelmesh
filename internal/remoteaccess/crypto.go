package remoteaccess

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrInvalidSignature           = errors.New("invalid signature")
	ErrSignerFailed               = errors.New("signer failed")
	ErrBindingMismatch            = errors.New("grant binding mismatch")
	ErrPayloadTooLarge            = errors.New("signed payload too large")
	ErrInvalidVerificationContext = errors.New("invalid verification context")
	ErrSignedGrantCacheMismatch   = errors.New("signed grant cache does not match payload")
)

const MaxSignedPayloadSize = 16384 // 16KB bound

var grantSignatureDomain = []byte("RatelMesh-Remote-Access-Grant-v1\x00")

// Signer interface allows the Coordinator to inject its own authority key mechanism.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// Verifier interface allows clients and nodes to verify grants against trusted keys.
type Verifier interface {
	Verify(data, sig []byte) bool
}

// Ed25519Signer is a simple signer using an explicit Ed25519 private key.
type Ed25519Signer struct {
	PrivateKey ed25519.PrivateKey
}

func (s Ed25519Signer) Sign(data []byte) ([]byte, error) {
	if len(s.PrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrSignerFailed
	}
	return ed25519.Sign(s.PrivateKey, data), nil
}

// Ed25519Verifier is a simple verifier using an explicit Ed25519 public key.
type Ed25519Verifier struct {
	PublicKey ed25519.PublicKey
}

func (v Ed25519Verifier) Verify(data, sig []byte) bool {
	if len(v.PublicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(v.PublicKey, data, sig)
}

// deterministicMarshal JSON-marshals the Grant safely.
func deterministicMarshal(g *Grant) ([]byte, error) {
	if g == nil {
		return nil, ErrNilPointer
	}
	// json.Marshal is deterministic for structs.
	return json.Marshal(g)
}

func grantSigningMessage(data []byte) []byte {
	message := make([]byte, 0, len(grantSignatureDomain)+len(data))
	message = append(message, grantSignatureDomain...)
	return append(message, data...)
}

// SignedGrant carries the deterministic grant payload and its detached
// authority signature. Payload contains no password or reusable credential.
type SignedGrant struct {
	Grant     Grant  `json:"grant"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// SignGrant returns a signed JSON representation of the grant and the signature.
// It explicitly rejects structurally invalid grants prior to signing.
func SignGrant(grant *Grant, signer Signer) ([]byte, []byte, error) {
	if grant == nil || signer == nil {
		return nil, nil, ErrNilPointer
	}

	// Validating at NotBefore is acceptable to ensure structural correctness
	// without failing prematurely just because it hasn't started yet.
	if err := grant.Validate(grant.NotBefore); err != nil {
		return nil, nil, err
	}

	data, err := deterministicMarshal(grant)
	if err != nil {
		return nil, nil, err
	}

	sig, err := signer.Sign(grantSigningMessage(data))
	if err != nil {
		return nil, nil, err
	}

	return data, sig, nil
}

// VerificationContext provides explicit boundaries for grant validation.
type VerificationContext struct {
	Now                   time.Time
	TenantID              string
	GranteeID             string
	ExpectedGranteeMeshIP string
	MinPolicyVersion      uint64
	TargetNodeID          string
	ExpectedKind          ServiceKind
	ExpectedPort          uint16
	ExpectedPlatform      Platform
	ExpectedMeshIP        string
}

// VerifyGrant verifies that the signature matches the grant data using the provided verifier,
// validates the chronology, and ensures exact binding to the verification context.
func VerifyGrant(data, sig []byte, verifier Verifier, ctx VerificationContext) (*Grant, error) {
	if verifier == nil {
		return nil, ErrNilPointer
	}
	if ctx.MinPolicyVersion == 0 {
		return nil, ErrInvalidVerificationContext
	}
	if len(data) > MaxSignedPayloadSize {
		return nil, ErrPayloadTooLarge
	}
	if len(sig) == 0 || len(sig) > MaxSignatureSize {
		return nil, ErrInvalidSignature
	}
	if !verifier.Verify(grantSigningMessage(data), sig) {
		return nil, ErrInvalidSignature
	}

	var g Grant
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(dec); err != nil {
		return nil, err
	}

	if err := g.Validate(ctx.Now); err != nil {
		return nil, err
	}

	if g.PolicyVersion < ctx.MinPolicyVersion {
		return nil, ErrStaleGrant
	}

	if g.TenantID != ctx.TenantID ||
		g.GranteeID != ctx.GranteeID ||
		g.GranteeMeshIP != ctx.ExpectedGranteeMeshIP ||
		g.Service.TargetNodeID != ctx.TargetNodeID ||
		g.Service.Kind != ctx.ExpectedKind ||
		g.Service.Port != ctx.ExpectedPort ||
		g.Service.Platform != ctx.ExpectedPlatform ||
		g.Service.TargetMeshIP != ctx.ExpectedMeshIP {
		return nil, ErrBindingMismatch
	}

	return &g, nil
}

// VerifySignedGrant verifies the signed payload and treats it as the sole
// authority. The outer Grant is only a transport cache and must be an exact
// canonical match, so consumers cannot be tricked into displaying or launching
// a service different from the one covered by the signature.
func VerifySignedGrant(signed SignedGrant, verifier Verifier, ctx VerificationContext) (*Grant, error) {
	grant, err := VerifyGrant(signed.Payload, signed.Signature, verifier, ctx)
	if err != nil {
		return nil, err
	}
	cached, err := deterministicMarshal(&signed.Grant)
	if err != nil {
		return nil, err
	}
	canonical, err := deterministicMarshal(grant)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cached, canonical) {
		return nil, ErrSignedGrantCacheMismatch
	}
	return grant, nil
}
