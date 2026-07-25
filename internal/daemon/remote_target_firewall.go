package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	"github.com/shan25519/ratelmesh/internal/netguard"
	"github.com/shan25519/ratelmesh/internal/types"
	"github.com/shan25519/ratelmesh/internal/wgengine"
)

var (
	remoteMeshIPv4 = netip.MustParsePrefix("100.64.0.0/10")
	remoteMeshIPv6 = netip.MustParsePrefix("fd00::/8")
)

func (d *Daemon) remoteFirewallCapable() bool {
	reporter, ok := d.guard.(netguard.CapabilityReporter)
	return ok && reporter.Capability().RemoteAccess
}

func (d *Daemon) remoteTunnelInterface(base netguard.Policy) string {
	if base.TunnelInterface != "" {
		return base.TunnelInterface
	}
	if namer, ok := d.engine.(wgengine.InterfaceNamer); ok {
		return namer.InterfaceName()
	}
	return ""
}

// composeRemoteTargetPolicy replaces only the remote-ingress half of a
// combined netguard policy. EXIT leak protection remains byte-for-byte intact.
func (d *Daemon) composeRemoteTargetPolicy(
	base netguard.Policy,
	target remoteTargetPolicy,
	self types.Node,
) (netguard.Policy, error) {
	base.RemoteEnforcement = false
	base.ManagedServices = nil
	base.RemoteAccessRules = nil
	base.RemoteMeshPrefixes = nil
	if !target.Required {
		return base, nil
	}
	if !d.remoteFirewallCapable() {
		return base, errors.New("remote target firewall unavailable")
	}
	if len(target.ManagedTCPPorts) == 0 || len(self.MeshIPs) == 0 || !self.MeshIPs[0].IsValid() {
		return base, errors.New("remote target firewall has no trusted managed boundary")
	}
	targetIP := self.MeshIPs[0].Unmap()
	if !remoteMeshIPv4.Contains(targetIP) && !remoteMeshIPv6.Contains(targetIP) {
		return base, errors.New("remote target firewall has invalid target address")
	}
	base.TunnelInterface = d.remoteTunnelInterface(base)
	if base.TunnelInterface == "" {
		return base, errors.New("remote target firewall has no tunnel interface")
	}
	base.RemoteEnforcement = true
	base.RemoteMeshPrefixes = []netip.Prefix{remoteMeshIPv4, remoteMeshIPv6}
	for _, port := range target.ManagedTCPPorts {
		if port == 0 {
			return netguard.Policy{}, errors.New("remote target firewall has invalid managed port")
		}
		base.ManagedServices = append(base.ManagedServices, netguard.ManagedService{
			TargetMeshIP: targetIP,
			TCPPort:      port,
		})
	}
	for _, desired := range target.Rules {
		sourceIP, err := netip.ParseAddr(desired.SourceMeshIP)
		if err != nil {
			return netguard.Policy{}, fmt.Errorf("remote target firewall source: %w", err)
		}
		ruleTarget, err := netip.ParseAddr(desired.TargetMeshIP)
		if err != nil {
			return netguard.Policy{}, fmt.Errorf("remote target firewall target: %w", err)
		}
		sourceIP = sourceIP.Unmap()
		ruleTarget = ruleTarget.Unmap()
		if desired.Protocol != "tcp" || desired.Port == 0 || ruleTarget != targetIP {
			return netguard.Policy{}, errors.New("remote target firewall rule binding invalid")
		}
		base.RemoteAccessRules = append(base.RemoteAccessRules, netguard.RemoteAccessRule{
			SourceMeshIP: sourceIP,
			TargetMeshIP: ruleTarget,
			TCPPort:      desired.Port,
		})
	}
	if err := base.Validate(); err != nil {
		return netguard.Policy{}, fmt.Errorf("remote target firewall policy: %w", err)
	}
	return base, nil
}

func copyRemotePolicy(dst *netguard.Policy, src netguard.Policy) {
	dst.RemoteEnforcement = src.RemoteEnforcement
	dst.ManagedServices = append([]netguard.ManagedService(nil), src.ManagedServices...)
	dst.RemoteAccessRules = append([]netguard.RemoteAccessRule(nil), src.RemoteAccessRules...)
	dst.RemoteMeshPrefixes = append([]netip.Prefix(nil), src.RemoteMeshPrefixes...)
	if src.RemoteEnforcement && dst.TunnelInterface == "" {
		dst.TunnelInterface = src.TunnelInterface
	}
}

func copyExitPolicy(dst *netguard.Policy, src netguard.Policy) {
	dst.Enabled = src.Enabled
	dst.TunnelEndpoints = append([]netip.AddrPort(nil), src.TunnelEndpoints...)
	dst.RelayEndpoints = append([]netip.AddrPort(nil), src.RelayEndpoints...)
	dst.ControlEndpoints = append([]netip.AddrPort(nil), src.ControlEndpoints...)
	dst.AllowCIDRs = append([]netip.Prefix(nil), src.AllowCIDRs...)
	if src.Enabled || !dst.RemoteEnforcement {
		dst.TunnelInterface = src.TunnelInterface
	}
}

func (d *Daemon) setRemoteTargetExpiry(expiry time.Time) {
	d.mu.Lock()
	changed := !d.remoteExpiry.Equal(expiry)
	d.remoteExpiry = expiry
	wake := d.remoteExpiryWake
	d.mu.Unlock()
	if changed && wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (d *Daemon) remoteTargetExpiryLoop(ctx context.Context) {
	for {
		d.mu.Lock()
		expiry := d.remoteExpiry
		wake := d.remoteExpiryWake
		d.mu.Unlock()

		var timer *time.Timer
		var timerC <-chan time.Time
		if !expiry.IsZero() {
			delay := time.Until(expiry)
			if delay < 0 {
				delay = 0
			}
			timer = time.NewTimer(delay)
			timerC = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
			continue
		case now := <-timerC:
			d.reconcileRemoteTargetExpiry(now)
		}
	}
}

func (d *Daemon) reconcileRemoteTargetExpiry(now time.Time) {
	if !d.remoteFirewallCapable() {
		d.setRemoteTargetExpiry(time.Time{})
		return
	}
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	d.mu.Lock()
	nm := d.lastNetmap
	d.mu.Unlock()
	if nm.Version == 0 {
		d.setRemoteTargetExpiry(time.Time{})
		return
	}
	target, err := d.deriveRemoteTargetPolicy(nm, now)
	if err != nil {
		d.log.Warn("remote target expiry reconciled fail-closed", "err", err)
	}
	current := d.guard.Current()
	desired, composeErr := d.composeRemoteTargetPolicy(current, target, nm.Self)
	if composeErr != nil {
		// Never retain a temporary allow because a fresh snapshot cannot be
		// composed. Preserve the already-installed deny boundary, remove every
		// allow, and retry discovery without busy-spinning.
		closed := current
		closed.RemoteAccessRules = nil
		if !reflect.DeepEqual(current, closed) {
			if err := d.applyKillSwitchPolicy(closed); err != nil {
				d.log.Error("remote target expiry emergency close failed", "err", errors.Join(composeErr, err))
			}
		}
		d.log.Error("remote target expiry policy invalid; temporary allows removed", "err", composeErr)
		d.setRemoteTargetExpiry(time.Now().Add(time.Second))
		return
	}
	if !reflect.DeepEqual(current, desired) {
		if err := d.applyKillSwitchPolicy(desired); err != nil {
			d.log.Error("remote target expiry firewall apply failed", "err", err)
			// Retry soon without busy-spinning.
			d.setRemoteTargetExpiry(time.Now().Add(time.Second))
			return
		}
	}
	d.setRemoteTargetExpiry(target.NearestExpiry)
}
