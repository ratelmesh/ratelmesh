package remoteaccess

import (
	"errors"
	"time"
)

// NodeIdentity is the minimum trusted local identity needed for authorization.
type NodeIdentity struct {
	TenantID string
	NodeID   string
	MeshIP   string
	Platform Platform
}

// SourceAuthorizationRequest contains only exact, structured connection
// expectations. It deliberately has no command, URL, username, or credential.
type SourceAuthorizationRequest struct {
	Self         NodeIdentity
	Verifier     Verifier
	PolicyStore  PolicyFloorStore
	SignedPolicy SignedPolicyState
	Now          time.Time
	Target       NodeIdentity
	ExpectedKind ServiceKind
	ExpectedPort uint16
	SignedGrant  SignedGrant
}

// AuthorizedLaunch is canonical launcher eligibility derived exclusively from
// a verified payload.
type AuthorizedLaunch struct {
	Grant    Grant
	Launcher LauncherMetadata
}

// AuthorizeSource validates every source and target binding before deriving a
// fixed protocol launcher URI.
func AuthorizeSource(req SourceAuthorizationRequest) (*AuthorizedLaunch, error) {
	if req.Verifier == nil || req.PolicyStore == nil || req.Now.IsZero() {
		return nil, enforcementError(CodeDependencyMissing, ErrInvalidVerificationContext)
	}
	if err := validateSourceNodeIdentity(req.Self); err != nil {
		return nil, enforcementError(CodeInvalidInput, err)
	}
	if err := validateTargetNodeIdentity(req.Target); err != nil {
		return nil, enforcementError(CodeInvalidInput, err)
	}
	if req.Self.TenantID != req.Target.TenantID {
		return nil, enforcementError(CodeInvalidInput, ErrBindingMismatch)
	}

	policy, err := VerifyPolicyState(req.SignedPolicy, req.Verifier, req.Self.TenantID, req.Now)
	if err != nil {
		return nil, enforcementError(classifyGrantError(err), err)
	}
	current, exists, err := req.PolicyStore.Load(req.Self.TenantID)
	if err != nil {
		return nil, enforcementError(CodeStorage, err)
	}
	if err := checkPolicyAdvance(current, exists, policy); err != nil {
		code := CodePolicyStale
		if errors.Is(err, ErrPolicyConflict) {
			code = CodePolicyConflict
		}
		return nil, enforcementError(code, err)
	}
	if err := req.PolicyStore.Advance(policy); err != nil {
		return nil, enforcementError(CodeStorage, err)
	}
	if !policy.Enabled {
		return nil, enforcementError(CodePolicyDisabled, ErrPolicyDisabled)
	}

	ctx := VerificationContext{
		Now:                   req.Now,
		TenantID:              req.Self.TenantID,
		GranteeID:             req.Self.NodeID,
		ExpectedGranteeMeshIP: req.Self.MeshIP,
		MinPolicyVersion:      policy.Version,
		TargetNodeID:          req.Target.NodeID,
		ExpectedKind:          req.ExpectedKind,
		ExpectedPort:          req.ExpectedPort,
		ExpectedPlatform:      req.Target.Platform,
		ExpectedMeshIP:        req.Target.MeshIP,
	}
	grant, err := VerifySignedGrant(req.SignedGrant, req.Verifier, ctx)
	if err != nil {
		return nil, enforcementError(classifyGrantError(err), err)
	}
	if grant.PolicyVersion != policy.Version {
		return nil, enforcementError(CodePolicyStale, ErrStaleGrant)
	}
	launcher, err := GenerateLauncherMetadata(grant)
	if err != nil {
		return nil, enforcementError(CodeInvalidInput, err)
	}
	return &AuthorizedLaunch{Grant: *grant, Launcher: *launcher}, nil
}
