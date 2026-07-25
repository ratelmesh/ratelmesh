package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/shan25519/ratelmesh/internal/remoteaccess"
	"github.com/shan25519/ratelmesh/internal/types"
)

type remoteTargetKey struct {
	nodeID   string
	meshIP   string
	platform string
}

type remoteAuthorizedService struct {
	service   remoteaccess.ServiceAdvertisement
	expiresAt time.Time
}

// remoteAccessView is derived from signed policy/grants without rewriting the
// raw netmap. Keeping raw control-plane state separate from time-varying
// launcher eligibility preserves equal-version equivocation detection.
type remoteAccessView struct {
	selfAllowed bool
	services    map[remoteTargetKey][]remoteAuthorizedService
}

// authenticateRemoteAccessNetmap derives authority-signed, locally bound
// launcher state. A failure returns an empty view and never tears down the Mesh
// data plane.
func (d *Daemon) authenticateRemoteAccessNetmap(nm types.Netmap, now time.Time) remoteAccessView {
	view := remoteAccessView{services: make(map[remoteTargetKey][]remoteAuthorizedService)}
	if len(d.cfg.VerifyKey) == 0 || d.remotePolicyStore == nil {
		return view
	}

	tenantID := remoteAccessTenantID(nm.Self.User)
	verifier := remoteaccess.Ed25519Verifier{PublicKey: d.cfg.VerifyKey}
	policy, err := remoteaccess.VerifyPolicyState(nm.RemoteAccessPolicyState, verifier, tenantID, now)
	if err != nil {
		d.log.Warn("remote access disabled for netmap", "reason", "policy signature rejected", "err", err)
		return view
	}
	if policy.Version != nm.RemoteAccessPolicyVersion {
		d.log.Warn("remote access disabled for netmap", "reason", "policy version mismatch")
		return view
	}
	if err := d.remotePolicyStore.Advance(policy); err != nil {
		d.log.Warn("remote access disabled for netmap", "reason", "policy floor rejected", "err", err)
		return view
	}
	if !policy.Enabled {
		return view
	}
	targetState, err := remoteaccess.VerifyTargetState(
		nm.RemoteAccessTargetState,
		verifier,
		policy,
		nm.Self.ID,
		now,
	)
	if err != nil {
		d.log.Warn("remote access disabled for netmap", "reason", "target activation rejected", "err", err)
		return view
	}
	view.selfAllowed = targetState.Enabled && d.remoteFirewallCapable()
	if targetState.Enabled && !view.selfAllowed {
		d.log.Warn("remote access target disabled locally", "reason", "host firewall enforcement unavailable")
	}

	if len(nm.Self.MeshIPs) == 0 {
		return view
	}
	selfMeshIP := nm.Self.MeshIPs[0].String()
	for _, signed := range nm.RemoteAccessGrants {
		if signed.Grant.GranteeID != nm.Self.ID {
			continue
		}
		service := signed.Grant.Service
		target, ok := exactRemoteAccessPeer(nm.Peers, service.TargetNodeID, service.TargetMeshIP, string(service.Platform))
		if !ok {
			continue
		}
		grant, err := remoteaccess.VerifySignedGrant(signed, verifier, remoteaccess.VerificationContext{
			Now:                   now,
			TenantID:              tenantID,
			GranteeID:             nm.Self.ID,
			ExpectedGranteeMeshIP: selfMeshIP,
			MinPolicyVersion:      policy.Version,
			TargetNodeID:          target.ID,
			ExpectedKind:          service.Kind,
			ExpectedPort:          service.Port,
			ExpectedPlatform:      remoteaccess.Platform(target.Platform),
			ExpectedMeshIP:        service.TargetMeshIP,
		})
		if err != nil || grant.PolicyVersion != policy.Version {
			continue
		}
		if _, err := remoteaccess.GenerateLauncherMetadata(grant); err != nil {
			continue
		}
		key := remoteTargetKey{nodeID: target.ID, meshIP: service.TargetMeshIP, platform: target.Platform}
		view.services[key] = appendUniqueAuthorizedService(view.services[key], remoteAuthorizedService{
			service:   grant.Service,
			expiresAt: grant.ExpiresAt,
		})
	}
	return view
}

func (v remoteAccessView) servicesFor(peer types.Node, now time.Time) []remoteaccess.ServiceAdvertisement {
	if len(peer.MeshIPs) == 0 {
		return nil
	}
	key := remoteTargetKey{nodeID: peer.ID, meshIP: peer.MeshIPs[0].String(), platform: peer.Platform}
	authorized := v.services[key]
	out := make([]remoteaccess.ServiceAdvertisement, 0, len(authorized))
	for _, item := range authorized {
		if now.Before(item.expiresAt) {
			out = append(out, item.service)
		}
	}
	return out
}

func remoteAccessTenantID(user string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(user)))
	return "tenant-" + hex.EncodeToString(sum[:6])
}

func exactRemoteAccessPeer(peers []types.Node, nodeID, meshIP, platform string) (types.Node, bool) {
	var match types.Node
	found := false
	for _, peer := range peers {
		if peer.ID != nodeID || peer.Platform != platform || len(peer.MeshIPs) == 0 || peer.MeshIPs[0].String() != meshIP {
			continue
		}
		if found {
			// Duplicate identity rows are ambiguous even if their visible
			// coordinates match. Fail closed instead of fanning one grant out.
			return types.Node{}, false
		}
		match, found = peer, true
	}
	return match, found
}

func appendUniqueAuthorizedService(services []remoteAuthorizedService, candidate remoteAuthorizedService) []remoteAuthorizedService {
	for i, service := range services {
		if service.service.Kind == candidate.service.Kind &&
			service.service.Port == candidate.service.Port &&
			service.service.Platform == candidate.service.Platform &&
			service.service.TargetNodeID == candidate.service.TargetNodeID &&
			service.service.TargetMeshIP == candidate.service.TargetMeshIP {
			if candidate.expiresAt.After(service.expiresAt) {
				services[i].expiresAt = candidate.expiresAt
			}
			return services
		}
	}
	return append(services, candidate)
}
