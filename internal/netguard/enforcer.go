package netguard

import (
	"log/slog"
	"sync"
)

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
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cur = p
	e.log.Info("killswitch: policy applied (stub)",
		"enabled", p.Enabled, "allowCIDRs", len(p.AllowCIDRs), "tunnelEndpoints", len(p.TunnelEndpoints))
	return nil
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
	return e.cur
}
