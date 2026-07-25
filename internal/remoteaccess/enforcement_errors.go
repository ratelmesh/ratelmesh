package remoteaccess

import (
	"errors"
	"fmt"
)

// EnforcementErrorCode is a stable machine-readable failure category.
type EnforcementErrorCode string

const (
	CodeInvalidInput      EnforcementErrorCode = "invalid_input"
	CodeDependencyMissing EnforcementErrorCode = "dependency_missing"
	CodeSignatureInvalid  EnforcementErrorCode = "signature_invalid"
	CodeCacheMismatch     EnforcementErrorCode = "cache_mismatch"
	CodeBindingMismatch   EnforcementErrorCode = "binding_mismatch"
	CodePolicyStale       EnforcementErrorCode = "policy_stale"
	CodePolicyDisabled    EnforcementErrorCode = "policy_disabled"
	CodePolicyConflict    EnforcementErrorCode = "policy_conflict"
	CodeGrantTime         EnforcementErrorCode = "grant_time"
	CodePeerBinding       EnforcementErrorCode = "peer_binding"
	CodeServiceMissing    EnforcementErrorCode = "service_missing"
	CodeDirectionDenied   EnforcementErrorCode = "direction_denied"
	CodeLimitExceeded     EnforcementErrorCode = "limit_exceeded"
	CodeStorage           EnforcementErrorCode = "storage"
	CodeGrantConflict     EnforcementErrorCode = "grant_conflict"
)

// EnforcementError preserves a stable code while retaining a cause for
// errors.Is/errors.As.
type EnforcementError struct {
	Code  EnforcementErrorCode
	Cause error
}

func (e *EnforcementError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Cause == nil {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Cause)
}

func (e *EnforcementError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func enforcementError(code EnforcementErrorCode, cause error) error {
	return &EnforcementError{Code: code, Cause: cause}
}

func classifyGrantError(err error) EnforcementErrorCode {
	switch {
	case errors.Is(err, ErrInvalidSignature):
		return CodeSignatureInvalid
	case errors.Is(err, ErrSignedGrantCacheMismatch):
		return CodeCacheMismatch
	case errors.Is(err, ErrBindingMismatch):
		return CodeBindingMismatch
	case errors.Is(err, ErrStaleGrant):
		return CodePolicyStale
	case errors.Is(err, ErrGrantExpired), errors.Is(err, ErrGrantNotYetValid):
		return CodeGrantTime
	default:
		return CodeInvalidInput
	}
}
