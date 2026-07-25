package netguard

import (
	"errors"
	"log/slog"
	"net/netip"
	"sync"
)

// Capability describes whether an enforcer can provide real host protection.
// Callers must not mistake a rootless recorder or an unsupported OS for an
// enforced remote-access boundary.
type Capability struct {
	HostFirewall bool
	RemoteAccess bool
	Reason       string
}

// CapabilityReporter is optional to preserve compatibility with existing
// Enforcer implementations while allowing security-sensitive callers to fail
// closed before offering remote access.
type CapabilityReporter interface {
	Capability() Capability
}

// Enforcer applies a firewall Policy to the host. The default build uses a stub
// that records intent (so the daemon logic runs rootless); the real enforcer
// (pfctl/nft) plugs in behind the same interface on privileged builds.
type Enforcer interface {
	Apply(Policy) error
	Clear() error
	// Current returns the last applied policy (for status/tests).
	Current() Policy
}

// StubEnforcer records the desired policy without touching the host firewall.
type StubEnforcer struct {
	log *slog.Logger
	mu  sync.Mutex
	cur Policy
}

// NewStubEnforcer returns a rootless enforcer.
func NewStubEnforcer(log *slog.Logger) *StubEnforcer {
	if log == nil {
		log = slog.Default()
	}
	return &StubEnforcer{log: log}
}

func (e *StubEnforcer) Apply(p Policy) error {
	p = clonePolicy(p)
	if err := p.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cur = p
	e.log.Info("killswitch: policy applied (stub)",
		"enabled", p.Enabled, "allowCIDRs", len(p.AllowCIDRs), "tunnelEndpoints", len(p.TunnelEndpoints))
	return nil
}

func (e *StubEnforcer) Capability() Capability {
	return Capability{Reason: "rootless firewall recorder does not enforce host rules"}
}

func (e *StubEnforcer) Clear() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cur = Policy{}
	e.log.Info("killswitch: cleared (stub)")
	return nil
}

func (e *StubEnforcer) Current() Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return clonePolicy(e.cur)
}

// UnsupportedEnforcer explicitly rejects active protection on unsupported
// platforms. It is preferable to a stub which could report false success.
type UnsupportedEnforcer struct {
	reason string
}

func NewUnsupportedEnforcer(reason string) *UnsupportedEnforcer {
	return &UnsupportedEnforcer{reason: reason}
}

func (e *UnsupportedEnforcer) Apply(p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Active() {
		return errors.New("netguard: host firewall enforcement unsupported")
	}
	return nil
}

func (e *UnsupportedEnforcer) Clear() error    { return nil }
func (e *UnsupportedEnforcer) Current() Policy { return Policy{} }
func (e *UnsupportedEnforcer) Capability() Capability {
	return Capability{Reason: e.reason}
}

func clonePolicy(p Policy) Policy {
	p.TunnelEndpoints = append([]netip.AddrPort(nil), p.TunnelEndpoints...)
	p.RelayEndpoints = append([]netip.AddrPort(nil), p.RelayEndpoints...)
	p.ControlEndpoints = append([]netip.AddrPort(nil), p.ControlEndpoints...)
	p.AllowCIDRs = append([]netip.Prefix(nil), p.AllowCIDRs...)
	p.ManagedServices = append([]ManagedService(nil), p.ManagedServices...)
	p.RemoteAccessRules = append([]RemoteAccessRule(nil), p.RemoteAccessRules...)
	p.RemoteMeshPrefixes = append([]netip.Prefix(nil), p.RemoteMeshPrefixes...)
	return p
}
