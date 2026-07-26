package daemon

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sort"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/remoteaccess"
	"github.com/ratelmesh/ratelmesh/internal/types"
)

type remoteTargetPolicyErrorCode string

const (
	remoteTargetPolicyDependency remoteTargetPolicyErrorCode = "dependency"
	remoteTargetPolicySignature  remoteTargetPolicyErrorCode = "signature"
	remoteTargetPolicyBinding    remoteTargetPolicyErrorCode = "binding"
	remoteTargetPolicyLimit      remoteTargetPolicyErrorCode = "limit"
	remoteTargetPolicyStorage    remoteTargetPolicyErrorCode = "storage"
	remoteTargetPolicyReconcile  remoteTargetPolicyErrorCode = "reconcile"
)

var (
	errRemoteTargetDependency = errors.New("remote target policy dependency unavailable")
	errRemoteTargetBinding    = errors.New("remote target policy binding invalid")
	errRemoteTargetVersion    = errors.New("remote target policy version mismatch")
	errRemoteTargetLimit      = errors.New("remote target policy input exceeds limit")
)

// remoteTargetPolicyError is intentionally typed so the integrator can expose
// a stable, credential-free diagnostic while retaining the underlying cause.
type remoteTargetPolicyError struct {
	Code  remoteTargetPolicyErrorCode
	Cause error
}

func (e *remoteTargetPolicyError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Cause)
}

func (e *remoteTargetPolicyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// remoteTargetPolicy is a pure desired-state derivation. Required means the
// platform firewall must install this policy even when Rules is empty. The
// integrator owns TunnelInterface discovery and all firewall side effects.
type remoteTargetPolicy struct {
	Required        bool
	Enabled         bool
	TunnelInterface string
	ManagedTCPPorts []uint16
	Rules           []remoteaccess.DesiredRule
	NearestExpiry   time.Time
	PolicyVersion   uint64
}

func closedRemoteTargetPolicy(required bool, managed []uint16, version uint64) remoteTargetPolicy {
	return remoteTargetPolicy{
		Required:        required,
		Enabled:         required,
		ManagedTCPPorts: append([]uint16(nil), managed...),
		Rules:           []remoteaccess.DesiredRule{},
		PolicyVersion:   version,
	}
}

// deriveRemoteTargetPolicy authenticates the coordinator's target selection,
// tenant policy and temporary grants before producing firewall-neutral desired
// state. It never executes a command or changes firewall state.
func (d *Daemon) deriveRemoteTargetPolicy(nm types.Netmap, now time.Time) (remoteTargetPolicy, error) {
	var configured []remoteaccess.Candidate
	var localPlatform remoteaccess.Platform
	if d != nil {
		configured = d.cfg.RemoteAccessCandidates
		localPlatform = d.remotePlatform
	}
	if localPlatform == "" {
		if platform, ok := remoteAccessPlatformForGOOS(runtime.GOOS); ok {
			localPlatform = platform
		}
	}
	candidatePorts, candidateErr := remoteTargetCandidatePorts(configured, localPlatform)
	closed := closedRemoteTargetPolicy(true, candidatePorts, 0)
	if candidateErr != nil {
		return closed, targetPolicyError(remoteTargetPolicyBinding, candidateErr)
	}
	if d == nil || len(d.cfg.VerifyKey) == 0 || d.remotePolicyStore == nil || now.IsZero() {
		return closed, targetPolicyError(remoteTargetPolicyDependency, errRemoteTargetDependency)
	}

	tenantID := remoteAccessTenantID(nm.Self.User)
	verifier := remoteaccess.Ed25519Verifier{PublicKey: d.cfg.VerifyKey}
	trustedNow, err := remoteaccess.PolicyTimeFloor(d.remotePolicyStore, tenantID, now)
	if err != nil {
		return closed, targetPolicyError(remoteTargetPolicyStorage, err)
	}
	verifiedPolicy, err := remoteaccess.VerifyPolicyState(
		nm.RemoteAccessPolicyState,
		verifier,
		tenantID,
		trustedNow,
	)
	if err != nil {
		return closed, targetPolicyError(remoteTargetPolicySignature, err)
	}
	currentPolicy, policyExists, err := d.remotePolicyStore.Load(tenantID)
	if err != nil {
		return closed, targetPolicyError(remoteTargetPolicyStorage, err)
	}
	verifiedPolicy, err = remoteaccess.ObservePolicyAt(verifiedPolicy, currentPolicy, policyExists, now)
	if err != nil {
		return closed, targetPolicyError(remoteTargetPolicyStorage, err)
	}
	trustedNow = verifiedPolicy.ObservedAt
	closed.PolicyVersion = verifiedPolicy.Version
	// Advance the authenticated revocation floor before inspecting any mutable
	// echo, target activation, service or peer observation. None of that mutable
	// data may prevent a newer signed version from revoking older grants.
	if err := d.remotePolicyStore.Advance(verifiedPolicy); err != nil {
		return closed, targetPolicyError(remoteTargetPolicyStorage, err)
	}
	if verifiedPolicy.Version != nm.RemoteAccessPolicyVersion {
		return closed, targetPolicyError(remoteTargetPolicyBinding, errRemoteTargetVersion)
	}
	if !verifiedPolicy.Enabled {
		// A signed global-off state is not an empty allowlist that needs a
		// target firewall; it explicitly turns the feature off.
		return closedRemoteTargetPolicy(false, nil, verifiedPolicy.Version), nil
	}
	targetState, err := remoteaccess.VerifyTargetState(
		nm.RemoteAccessTargetState,
		verifier,
		verifiedPolicy,
		nm.Self.ID,
		trustedNow,
	)
	if err != nil {
		return closed, targetPolicyError(remoteTargetPolicySignature, err)
	}
	if !targetState.Enabled {
		return closedRemoteTargetPolicy(false, nil, verifiedPolicy.Version), nil
	}
	if len(candidatePorts) == 0 {
		// An explicit empty local candidate list opts this device out of target
		// service management. No port is advertised or claimed as protected.
		return closedRemoteTargetPolicy(false, nil, verifiedPolicy.Version), nil
	}
	if len(nm.Peers) > remoteaccess.MaxReconcilePeers ||
		len(nm.Self.RemoteServices) > remoteaccess.MaxReconcileServices ||
		len(nm.RemoteAccessGrants) > remoteaccess.MaxReconcileGrants {
		return closed, targetPolicyError(remoteTargetPolicyLimit, errRemoteTargetLimit)
	}

	self, err := remoteTargetIdentity(nm.Self, tenantID, localPlatform)
	if err != nil {
		return closed, targetPolicyError(remoteTargetPolicyBinding, err)
	}
	managed, err := remoteTargetManagedPorts(candidatePorts, self, nm.Self.RemoteServices)
	if err != nil {
		return closed, targetPolicyError(remoteTargetPolicyBinding, err)
	}
	closed.ManagedTCPPorts = managed

	peers, err := remoteTargetPeers(nm.Self.ID, nm.Peers)
	if err != nil {
		return closed, targetPolicyError(remoteTargetPolicyBinding, err)
	}
	// This callback means only that the source identity is still present in the
	// target's current peer map. The coordinator authenticated direction when it
	// signed the grant; every ACL update must advance the policy floor and revoke
	// all grants issued under the previous version.
	canReach := func(sourceNodeID, targetNodeID string) (bool, error) {
		if targetNodeID != self.NodeID {
			return false, nil
		}
		_, visible := peers[sourceNodeID]
		return visible, nil
	}
	result, err := remoteaccess.ReconcileTarget(remoteaccess.TargetReconcileRequest{
		Self:         self,
		Services:     cloneRemoteTargetServices(nm.Self.RemoteServices),
		Peers:        peers,
		CanReach:     canReach,
		Verifier:     verifier,
		PolicyStore:  d.remotePolicyStore,
		SignedPolicy: nm.RemoteAccessPolicyState,
		Now:          trustedNow,
		Grants:       cloneRemoteTargetGrants(nm.RemoteAccessGrants),
	})
	if err != nil {
		return closed, targetPolicyError(remoteTargetPolicyReconcile, err)
	}
	if !result.PolicyEnabled || result.PolicyVersion != verifiedPolicy.Version {
		return closed, targetPolicyError(remoteTargetPolicyBinding, errRemoteTargetVersion)
	}

	policy := closed
	policy.Rules = append([]remoteaccess.DesiredRule(nil), result.Rules...)
	for _, rule := range policy.Rules {
		if policy.NearestExpiry.IsZero() || rule.ExpiresAt.Before(policy.NearestExpiry) {
			policy.NearestExpiry = rule.ExpiresAt
		}
	}
	return policy, nil
}

func cloneRemoteTargetServices(input []remoteaccess.ServiceAdvertisement) []remoteaccess.ServiceAdvertisement {
	out := make([]remoteaccess.ServiceAdvertisement, len(input))
	copy(out, input)
	return out
}

func cloneRemoteTargetGrants(input []remoteaccess.SignedGrant) []remoteaccess.SignedGrant {
	out := make([]remoteaccess.SignedGrant, len(input))
	copy(out, input)
	return out
}

func remoteTargetIdentity(self types.Node, tenantID string, expectedPlatform remoteaccess.Platform) (remoteaccess.NodeIdentity, error) {
	if tenantID == "" || self.ID == "" || len(self.MeshIPs) == 0 {
		return remoteaccess.NodeIdentity{}, errRemoteTargetBinding
	}
	meshIP := self.MeshIPs[0]
	if !meshIP.IsValid() {
		return remoteaccess.NodeIdentity{}, errRemoteTargetBinding
	}
	platform := remoteaccess.Platform(self.Platform)
	if platform != expectedPlatform {
		return remoteaccess.NodeIdentity{}, errRemoteTargetBinding
	}
	identity := remoteaccess.NodeIdentity{
		TenantID: tenantID,
		NodeID:   self.ID,
		MeshIP:   meshIP.String(),
		Platform: platform,
	}
	// Validate the complete identity through a bound service below. Platforms
	// without target support must fail closed instead of silently opting out.
	switch platform {
	case remoteaccess.PlatformMacOS, remoteaccess.PlatformWindows, remoteaccess.PlatformLinux:
	default:
		return remoteaccess.NodeIdentity{}, errRemoteTargetBinding
	}
	return identity, nil
}

func remoteTargetCandidatePorts(configured []remoteaccess.Candidate, platform remoteaccess.Platform) ([]uint16, error) {
	candidates := configured
	if candidates == nil {
		candidates = remoteaccess.DefaultCandidates(platform)
	}
	if len(candidates) > remoteaccess.MaxCandidates {
		return nil, errRemoteTargetLimit
	}
	ports := make(map[uint16]struct{}, len(candidates))
	for _, candidate := range candidates {
		probe := remoteaccess.ServiceAdvertisement{
			Kind:         candidate.Kind,
			Port:         candidate.Port,
			Platform:     platform,
			Label:        "managed",
			TargetNodeID: "candidate",
			TargetMeshIP: "100.64.0.1",
		}
		if err := probe.Validate(); err != nil {
			return nil, err
		}
		ports[candidate.Port] = struct{}{}
	}
	return sortedRemoteTargetPorts(ports), nil
}

func remoteTargetManagedPorts(candidatePorts []uint16, self remoteaccess.NodeIdentity, services []remoteaccess.ServiceAdvertisement) ([]uint16, error) {
	ports := make(map[uint16]struct{}, len(candidatePorts)+len(services))
	for _, port := range candidatePorts {
		if port == 0 {
			return nil, errRemoteTargetBinding
		}
		ports[port] = struct{}{}
	}
	for i := range services {
		service := services[i]
		if err := service.Validate(); err != nil ||
			service.TargetNodeID != self.NodeID ||
			service.TargetMeshIP != self.MeshIP ||
			service.Platform != self.Platform {
			if err != nil {
				return nil, err
			}
			return nil, errRemoteTargetBinding
		}
		ports[service.Port] = struct{}{}
	}
	return sortedRemoteTargetPorts(ports), nil
}

func sortedRemoteTargetPorts(ports map[uint16]struct{}) []uint16 {
	out := make([]uint16, 0, len(ports))
	for port := range ports {
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func remoteAccessPlatformForGOOS(goos string) (remoteaccess.Platform, bool) {
	switch goos {
	case "darwin":
		return remoteaccess.PlatformMacOS, true
	case "windows":
		return remoteaccess.PlatformWindows, true
	case "linux":
		return remoteaccess.PlatformLinux, true
	default:
		return "", false
	}
}

func remoteTargetPeers(selfNodeID string, nodes []types.Node) (map[string]string, error) {
	peers := make(map[string]string, len(nodes))
	seenIPs := make(map[netip.Addr]string, len(nodes))
	for _, node := range nodes {
		if node.ID == "" || node.ID == selfNodeID || len(node.MeshIPs) == 0 {
			return nil, errRemoteTargetBinding
		}
		if _, duplicate := peers[node.ID]; duplicate {
			return nil, errRemoteTargetBinding
		}
		meshIP := node.MeshIPs[0]
		if !meshIP.IsValid() {
			return nil, errRemoteTargetBinding
		}
		if other, duplicate := seenIPs[meshIP]; duplicate && other != node.ID {
			return nil, errRemoteTargetBinding
		}
		seenIPs[meshIP] = node.ID
		peers[node.ID] = meshIP.String()
	}
	return peers, nil
}

func targetPolicyError(code remoteTargetPolicyErrorCode, cause error) error {
	return &remoteTargetPolicyError{Code: code, Cause: cause}
}
