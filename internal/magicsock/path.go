package magicsock

import (
	"net/netip"
	"sort"
	"sync"

	"github.com/shan25519/ratelmesh/internal/types"
)

// PathType is how traffic to a peer currently flows.
type PathType string

const (
	// PathRelay routes through ratelmesh-relay (the initial, always-available path).
	PathRelay PathType = "relay"
	// PathDirect is a hole-punched peer-to-peer WireGuard connection.
	PathDirect PathType = "direct"
)

// PeerPath is the connection-path state machine for one peer (DESIGN.md §3.2).
// It starts on the relay and upgrades to direct when a candidate endpoint is
// confirmed reachable; if the direct path later fails it falls back to relay.
// The state machine is pure and concurrency-safe so it can be unit-tested
// without real sockets.
type PeerPath struct {
	peer types.Key

	mu         sync.Mutex
	candidates []netip.AddrPort
	direct     netip.AddrPort // confirmed direct endpoint (zero => none)
	haveDirect bool
}

// NewPeerPath creates a path tracker for a peer, starting on the relay.
func NewPeerPath(peer types.Key) *PeerPath {
	return &PeerPath{peer: peer}
}

// SetCandidates records the endpoint candidates advertised for this peer. If the
// currently-confirmed direct endpoint is no longer a candidate, the direct path
// is dropped (the peer likely moved networks).
func (p *PeerPath) SetCandidates(eps []netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.candidates = append(p.candidates[:0:0], eps...)
	sortAddrPorts(p.candidates)
	if p.haveDirect && !containsAddrPort(p.candidates, p.direct) {
		p.haveDirect = false
		p.direct = netip.AddrPort{}
	}
}

// Candidates returns a copy of the current candidate list.
func (p *PeerPath) Candidates() []netip.AddrPort {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.AddrPort(nil), p.candidates...)
}

// ConfirmDirect marks an endpoint as a working direct path, upgrading away from
// the relay. It is ignored if the endpoint is not among the known candidates
// (guards against confirming a stale/spoofed endpoint).
func (p *PeerPath) ConfirmDirect(ep netip.AddrPort) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !containsAddrPort(p.candidates, ep) {
		return false
	}
	p.direct = ep
	p.haveDirect = true
	return true
}

// LoseDirect drops the direct path, falling back to the relay.
func (p *PeerPath) LoseDirect() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.haveDirect = false
	p.direct = netip.AddrPort{}
}

// Current reports the active path type and, for direct paths, the endpoint.
func (p *PeerPath) Current() (PathType, netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.haveDirect {
		return PathDirect, p.direct
	}
	return PathRelay, netip.AddrPort{}
}

func sortAddrPorts(s []netip.AddrPort) {
	sort.Slice(s, func(i, j int) bool { return s[i].String() < s[j].String() })
}

func containsAddrPort(s []netip.AddrPort, x netip.AddrPort) bool {
	for _, e := range s {
		if e == x {
			return true
		}
	}
	return false
}
