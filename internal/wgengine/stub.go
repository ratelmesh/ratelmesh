package wgengine

import (
	"log/slog"
	"sync"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

// StubEngine is a rootless, no-network implementation of Engine. It records the
// desired configuration and logs transitions, so the control plane and daemon
// state machine can run and be tested anywhere without a TUN device or root.
// The real data plane is StubEngine's counterpart behind the `wgreal` tag.
type StubEngine struct {
	log *slog.Logger

	mu    sync.Mutex
	up    bool
	cfg   Config
	stats map[types.Key]PeerStat // synthetic per-peer stats (for tests)
}

// NewStub returns a stub engine.
func NewStub(log *slog.Logger) *StubEngine {
	if log == nil {
		log = slog.Default()
	}
	return &StubEngine{log: log}
}

func (e *StubEngine) Up() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.up = true
	e.log.Info("wg stub: interface up (no real TUN; build with -tags wgreal for the kernel/userspace data plane)")
	return nil
}

func (e *StubEngine) Reconfigure(cfg Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
	e.log.Info("wg stub: reconfigured",
		"addresses", cfg.Addresses, "listenPort", cfg.ListenPort, "peers", len(cfg.Peers),
		"directRoutes", len(cfg.DirectRoutes), "blockRoutes", len(cfg.BlockRoutes))
	for _, p := range cfg.Peers {
		e.log.Debug("wg stub: peer", "key", p.PublicKey.ShortString(),
			"allowedIPs", p.AllowedIPs, "endpoints", p.Endpoints)
	}
	return nil
}

// LastConfig returns the most recently applied configuration (for tests).
func (e *StubEngine) LastConfig() Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// SetPeerStat records a synthetic per-peer stat (test hook so the daemon's
// relay fallback/upgrade logic can be exercised without real WireGuard).
func (e *StubEngine) SetPeerStat(peer types.Key, s PeerStat) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stats == nil {
		e.stats = make(map[types.Key]PeerStat)
	}
	e.stats[peer] = s
}

// PeerStats implements PeerStatsReporter for the stub.
func (e *StubEngine) PeerStats() (map[types.Key]PeerStat, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[types.Key]PeerStat, len(e.stats))
	for k, v := range e.stats {
		out[k] = v
	}
	return out, nil
}

func (e *StubEngine) Peers() []types.Key {
	e.mu.Lock()
	defer e.mu.Unlock()
	keys := make([]types.Key, 0, len(e.cfg.Peers))
	for _, p := range e.cfg.Peers {
		keys = append(keys, p.PublicKey)
	}
	return keys
}

func (e *StubEngine) Down() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.up = false
	e.log.Info("wg stub: interface down")
	return nil
}

func (e *StubEngine) Close() error { return e.Down() }
