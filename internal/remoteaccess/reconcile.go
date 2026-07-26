package remoteaccess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"time"
)

const (
	MaxReconcileGrants   = 256
	MaxReconcileServices = 64
	MaxReconcilePeers    = 1024
	MaxSignatureSize     = 1024
)

var (
	ErrReconcileLimit      = errors.New("remote access reconcile input exceeds limit")
	ErrDependencyMissing   = errors.New("remote access enforcement dependency unavailable")
	ErrPeerBindingMismatch = errors.New("peer identity and Mesh IP binding mismatch")
	ErrServiceUnavailable  = errors.New("advertised service unavailable")
	ErrDirectionDenied     = errors.New("source cannot reach target")
	ErrGrantIDConflict     = errors.New("conflicting grants share an ID")
)

// DirectionalReachability must answer whether sourceNodeID may initiate a
// connection to targetNodeID. Reverse-only reachability is insufficient.
type DirectionalReachability func(sourceNodeID, targetNodeID string) (bool, error)

// DesiredRule is platform-neutral desired state. Implementations may enforce
// only new connections or may terminate established TCP flows on removal; that
// established-flow policy belongs to the platform enforcer, not this core.
type DesiredRule struct {
	SourceMeshIP string    `json:"sourceMeshIp"`
	TargetMeshIP string    `json:"targetMeshIp"`
	Protocol     string    `json:"protocol"`
	Port         uint16    `json:"port"`
	GrantID      string    `json:"grantId"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type GrantRejection struct {
	Index int                  `json:"index"`
	Code  EnforcementErrorCode `json:"code"`
}

type ReconcileResult struct {
	PolicyVersion uint64           `json:"policyVersion"`
	PolicyEnabled bool             `json:"policyEnabled"`
	Rules         []DesiredRule    `json:"rules"`
	Rejected      []GrantRejection `json:"rejected"`
}

type TargetReconcileRequest struct {
	Self         NodeIdentity
	Services     []ServiceAdvertisement
	Peers        map[string]string
	CanReach     DirectionalReachability
	Verifier     Verifier
	PolicyStore  PolicyFloorStore
	SignedPolicy SignedPolicyState
	Now          time.Time
	Grants       []SignedGrant
}

type verifiedCandidate struct {
	index       int
	grant       Grant
	fingerprint string
}

// ReconcileTarget authenticates policy and grants and produces deterministic,
// fail-closed desired state. It never invokes firewall commands.
func ReconcileTarget(req TargetReconcileRequest) (*ReconcileResult, error) {
	if req.Verifier == nil || req.PolicyStore == nil || req.CanReach == nil ||
		req.Services == nil || req.Peers == nil || req.Grants == nil || req.Now.IsZero() {
		return nil, enforcementError(CodeDependencyMissing, ErrDependencyMissing)
	}
	if len(req.Grants) > MaxReconcileGrants || len(req.Services) > MaxReconcileServices ||
		len(req.Peers) > MaxReconcilePeers {
		return nil, enforcementError(CodeLimitExceeded, ErrReconcileLimit)
	}
	if err := validateTargetNodeIdentity(req.Self); err != nil {
		return nil, enforcementError(CodeInvalidInput, err)
	}
	services, err := validatedLocalServices(req.Self, req.Services)
	if err != nil {
		return nil, enforcementError(CodeInvalidInput, err)
	}
	peers, err := validatedPeers(req.Self, req.Peers)
	if err != nil {
		return nil, enforcementError(CodePeerBinding, err)
	}

	trustedNow, err := PolicyTimeFloor(req.PolicyStore, req.Self.TenantID, req.Now)
	if err != nil {
		return nil, enforcementError(CodeStorage, err)
	}
	policy, err := VerifyPolicyState(req.SignedPolicy, req.Verifier, req.Self.TenantID, trustedNow)
	if err != nil {
		return nil, enforcementError(classifyGrantError(err), err)
	}
	current, exists, err := req.PolicyStore.Load(req.Self.TenantID)
	if err != nil {
		return nil, enforcementError(CodeStorage, err)
	}
	policy, err = ObservePolicyAt(policy, current, exists, req.Now)
	if err != nil {
		return nil, enforcementError(CodeStorage, err)
	}
	trustedNow = policy.ObservedAt
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

	result := &ReconcileResult{
		PolicyVersion: policy.Version,
		PolicyEnabled: policy.Enabled,
		Rules:         make([]DesiredRule, 0),
		Rejected:      make([]GrantRejection, 0),
	}
	if !policy.Enabled {
		return result, nil
	}

	candidates := make([]verifiedCandidate, 0, len(req.Grants))
	for index, signed := range req.Grants {
		grant, err := verifyGrantPayload(signed, req.Verifier, trustedNow, policy.Version)
		if err != nil {
			result.Rejected = append(result.Rejected, GrantRejection{Index: index, Code: classifyGrantError(err)})
			continue
		}
		sum := sha256.Sum256(signed.Payload)
		candidates = append(candidates, verifiedCandidate{
			index:       index,
			grant:       *grant,
			fingerprint: hex.EncodeToString(sum[:]),
		})
	}

	conflicts := conflictingGrantIDs(candidates)
	seenPayload := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		grant := candidate.grant
		if conflicts[grant.ID] {
			result.Rejected = append(result.Rejected, GrantRejection{Index: candidate.index, Code: CodeGrantConflict})
			continue
		}
		dedupKey := grant.ID + "\x00" + candidate.fingerprint
		if _, ok := seenPayload[dedupKey]; ok {
			continue
		}
		seenPayload[dedupKey] = struct{}{}

		if grant.TenantID != req.Self.TenantID {
			result.Rejected = append(result.Rejected, GrantRejection{Index: candidate.index, Code: CodeBindingMismatch})
			continue
		}
		// A grant for a newer policy snapshot must not become active under an
		// older LKG merely because its version is above the persisted floor.
		if grant.PolicyVersion != policy.Version {
			result.Rejected = append(result.Rejected, GrantRejection{Index: candidate.index, Code: CodePolicyStale})
			continue
		}
		serviceKey := advertisementKey(grant.Service)
		if _, ok := services[serviceKey]; !ok {
			result.Rejected = append(result.Rejected, GrantRejection{Index: candidate.index, Code: CodeServiceMissing})
			continue
		}
		sourceIP, ok := peers[grant.GranteeID]
		if !ok {
			result.Rejected = append(result.Rejected, GrantRejection{Index: candidate.index, Code: CodePeerBinding})
			continue
		}
		if grant.GranteeMeshIP != sourceIP {
			result.Rejected = append(result.Rejected, GrantRejection{Index: candidate.index, Code: CodePeerBinding})
			continue
		}
		allowed, err := req.CanReach(grant.GranteeID, req.Self.NodeID)
		if err != nil {
			return nil, enforcementError(CodeDependencyMissing, err)
		}
		if !allowed {
			result.Rejected = append(result.Rejected, GrantRejection{Index: candidate.index, Code: CodeDirectionDenied})
			continue
		}
		result.Rules = append(result.Rules, DesiredRule{
			SourceMeshIP: sourceIP,
			TargetMeshIP: req.Self.MeshIP,
			Protocol:     "tcp",
			Port:         grant.Service.Port,
			GrantID:      grant.ID,
			ExpiresAt:    grant.ExpiresAt,
		})
	}

	sort.Slice(result.Rules, func(i, j int) bool {
		a, b := result.Rules[i], result.Rules[j]
		if a.SourceMeshIP != b.SourceMeshIP {
			return a.SourceMeshIP < b.SourceMeshIP
		}
		if a.TargetMeshIP != b.TargetMeshIP {
			return a.TargetMeshIP < b.TargetMeshIP
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.GrantID < b.GrantID
	})
	sort.Slice(result.Rejected, func(i, j int) bool {
		if result.Rejected[i].Index != result.Rejected[j].Index {
			return result.Rejected[i].Index < result.Rejected[j].Index
		}
		return result.Rejected[i].Code < result.Rejected[j].Code
	})
	return result, nil
}

func verifyGrantPayload(signed SignedGrant, verifier Verifier, now time.Time, floor uint64) (*Grant, error) {
	if verifier == nil || floor == 0 || now.IsZero() {
		return nil, ErrInvalidVerificationContext
	}
	if len(signed.Payload) == 0 || len(signed.Payload) > MaxSignedPayloadSize ||
		len(signed.Signature) == 0 || len(signed.Signature) > MaxSignatureSize {
		return nil, ErrPayloadTooLarge
	}
	if !verifier.Verify(grantSigningMessage(signed.Payload), signed.Signature) {
		return nil, ErrInvalidSignature
	}
	var grant Grant
	dec := jsonDecoder(signed.Payload)
	if err := dec.Decode(&grant); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(dec); err != nil {
		return nil, err
	}
	if err := grant.Validate(now); err != nil {
		return nil, err
	}
	if grant.PolicyVersion < floor {
		return nil, ErrStaleGrant
	}
	cache, err := deterministicMarshal(&signed.Grant)
	if err != nil {
		return nil, err
	}
	canonical, err := deterministicMarshal(&grant)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cache, canonical) {
		return nil, ErrSignedGrantCacheMismatch
	}
	return &grant, nil
}

func jsonDecoder(payload []byte) *json.Decoder {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	return dec
}

func validateIdentityFields(identity NodeIdentity) error {
	if identity.TenantID == "" || identity.NodeID == "" ||
		len(identity.TenantID) > 256 || len(identity.NodeID) > 256 ||
		containsControlChars(identity.TenantID) || containsControlChars(identity.NodeID) {
		return ErrInvalidID
	}
	addr, err := netip.ParseAddr(identity.MeshIP)
	if err != nil || !isMeshAddr(addr) {
		return ErrInvalidMeshIP
	}
	return nil
}

func validateTargetNodeIdentity(identity NodeIdentity) error {
	if err := validateIdentityFields(identity); err != nil {
		return err
	}
	switch identity.Platform {
	case PlatformMacOS, PlatformWindows, PlatformLinux:
		return nil
	default:
		return ErrInvalidPlatform
	}
}

func validateSourceNodeIdentity(identity NodeIdentity) error {
	if err := validateIdentityFields(identity); err != nil {
		return err
	}
	switch identity.Platform {
	case PlatformAndroid, PlatformIOS, PlatformMacOS, PlatformWindows, PlatformLinux:
		return nil
	default:
		return ErrInvalidPlatform
	}
}

func advertisementKey(service ServiceAdvertisement) string {
	// Label is mutable display metadata, not a security coordinate.
	return string(service.Kind) + "\x00" + string(service.Platform) + "\x00" +
		service.TargetNodeID + "\x00" + service.TargetMeshIP + "\x00" +
		strconv.Itoa(int(service.Port))
}

func validatedLocalServices(self NodeIdentity, input []ServiceAdvertisement) (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(input))
	for i := range input {
		service := input[i]
		if err := service.Validate(); err != nil {
			return nil, err
		}
		if service.TargetNodeID != self.NodeID || service.TargetMeshIP != self.MeshIP ||
			service.Platform != self.Platform {
			return nil, ErrBindingMismatch
		}
		out[advertisementKey(service)] = struct{}{}
	}
	return out, nil
}

func validatedPeers(self NodeIdentity, input map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(input))
	seenIPs := make(map[netip.Addr]string, len(input))
	for nodeID, meshIP := range input {
		if nodeID == "" || len(nodeID) > 256 || containsControlChars(nodeID) || nodeID == self.NodeID {
			return nil, ErrPeerBindingMismatch
		}
		addr, err := netip.ParseAddr(meshIP)
		if err != nil || !isMeshAddr(addr) {
			return nil, ErrPeerBindingMismatch
		}
		if previous, exists := seenIPs[addr]; exists && previous != nodeID {
			return nil, ErrPeerBindingMismatch
		}
		seenIPs[addr] = nodeID
		out[nodeID] = addr.String()
	}
	return out, nil
}

func conflictingGrantIDs(candidates []verifiedCandidate) map[string]bool {
	first := make(map[string]string, len(candidates))
	conflicts := make(map[string]bool)
	for _, candidate := range candidates {
		if fingerprint, ok := first[candidate.grant.ID]; ok && fingerprint != candidate.fingerprint {
			conflicts[candidate.grant.ID] = true
		} else if !ok {
			first[candidate.grant.ID] = candidate.fingerprint
		}
	}
	return conflicts
}
