package remoteaccess

import (
	"bytes"
	"encoding/json"
	"time"
)

var targetStateSignatureDomain = []byte("RatelMesh-Remote-Access-Target-State-v1\x00")

// TargetState is an authority-signed decision that binds one device's
// participation in remote access to one exact tenant policy snapshot. The
// ordinary Netmap Node fields remain presentation data and cannot enable or
// disable the target firewall boundary.
type TargetState struct {
	TenantID      string    `json:"tenantId"`
	PolicyVersion uint64    `json:"policyVersion"`
	PolicyDigest  string    `json:"policyDigest"`
	TargetNodeID  string    `json:"targetNodeId"`
	Enabled       bool      `json:"enabled"`
	IssuedAt      time.Time `json:"issuedAt"`
}

// SignedTargetState carries the canonical target decision and its detached
// authority signature.
type SignedTargetState struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func targetStateSigningMessage(payload []byte) []byte {
	out := make([]byte, 0, len(targetStateSignatureDomain)+len(payload))
	out = append(out, targetStateSignatureDomain...)
	return append(out, payload...)
}

func validateTargetState(state TargetState) error {
	if state.TenantID == "" || len(state.TenantID) > 256 || containsControlChars(state.TenantID) ||
		state.PolicyVersion == 0 || !isCanonicalPolicyDigest(state.PolicyDigest) ||
		state.TargetNodeID == "" || len(state.TargetNodeID) > 256 ||
		containsControlChars(state.TargetNodeID) || state.IssuedAt.IsZero() {
		return ErrInvalidPolicyState
	}
	return nil
}

// SignTargetState signs a per-target decision under a domain separated from
// grants and tenant policy state.
func SignTargetState(state TargetState, signer Signer) (SignedTargetState, error) {
	if signer == nil {
		return SignedTargetState{}, ErrNilPointer
	}
	if err := validateTargetState(state); err != nil {
		return SignedTargetState{}, err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return SignedTargetState{}, err
	}
	signature, err := signer.Sign(targetStateSigningMessage(payload))
	if err != nil {
		return SignedTargetState{}, err
	}
	return SignedTargetState{Payload: payload, Signature: signature}, nil
}

// VerifyTargetState authenticates an exact tenant, policy snapshot and target
// binding. A target decision from another policy digest is never transferable,
// even if a malformed coordinator repeats a version number.
func VerifyTargetState(
	signed SignedTargetState,
	verifier Verifier,
	policy VerifiedPolicyState,
	targetNodeID string,
	now time.Time,
) (TargetState, error) {
	if verifier == nil || targetNodeID == "" || now.IsZero() {
		return TargetState{}, ErrInvalidVerificationContext
	}
	if len(signed.Payload) == 0 || len(signed.Payload) > MaxPolicyPayloadSize {
		return TargetState{}, ErrPayloadTooLarge
	}
	if len(signed.Signature) == 0 || len(signed.Signature) > MaxSignatureSize ||
		!verifier.Verify(targetStateSigningMessage(signed.Payload), signed.Signature) {
		return TargetState{}, ErrInvalidSignature
	}
	var state TargetState
	dec := json.NewDecoder(bytes.NewReader(signed.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return TargetState{}, ErrInvalidPolicyState
	}
	if err := ensureJSONEOF(dec); err != nil {
		return TargetState{}, ErrInvalidPolicyState
	}
	if err := validateTargetState(state); err != nil {
		return TargetState{}, err
	}
	if state.TenantID != policy.TenantID ||
		state.PolicyVersion != policy.Version ||
		state.PolicyDigest != policy.Digest ||
		state.TargetNodeID != targetNodeID ||
		!state.IssuedAt.Equal(policy.IssuedAt) ||
		state.IssuedAt.After(now.Add(5*time.Minute)) {
		return TargetState{}, ErrBindingMismatch
	}
	return state, nil
}
