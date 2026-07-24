package magicsock

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/ratelmesh/ratelmesh/internal/relay"
	"github.com/ratelmesh/ratelmesh/internal/types"
)

// RelayBridge makes the ratelmesh-relay usable as a WireGuard transport, so two peers
// that cannot reach each other directly still exchange traffic (DESIGN.md §3.2:
// relay is the always-available fallback path).
//
// For each peer it opens a local UDP socket and hands its address to WireGuard
// as that peer's endpoint. WireGuard is oblivious to the relay: packets it sends
// to the peer's "endpoint" land on the local socket, which forwards them over
// the relay; packets the relay delivers are written back into WireGuard from the
// same socket, so WG sees them arriving from the peer's (stable) endpoint and
// replies there. WG demultiplexes peers by their static public key, so many
// peers can share one relay connection.
type RelayBridge struct {
	ctx    context.Context
	rc     *relay.Client
	wgAddr *net.UDPAddr // WireGuard's listen socket; inbound packets are injected here
	log    *slog.Logger

	mu      sync.Mutex
	peers   map[types.Key]*peerBridge
	allowed map[types.Key]bool // peers we expect (netmap members); bounds lazy creation
	closed  bool
}

type peerBridge struct {
	peer  types.Key
	conn  *net.UDPConn
	local netip.AddrPort
}

// NewRelayBridge starts a bridge over an already-connected relay client. wgAddr
// is the local address WireGuard listens on (where inbound relayed packets are
// injected). onDisconnect, if non-nil, is called once when the relay connection
// drops (not due to ctx cancellation), with THIS bridge as its argument so the
// caller can verify the callback is from the current bridge before acting — a
// late callback from a rotated-out bridge must not tear down its replacement
// (security review). It runs until ctx is cancelled.
func NewRelayBridge(ctx context.Context, rc *relay.Client, wgAddr netip.AddrPort, log *slog.Logger, onDisconnect func(*RelayBridge)) *RelayBridge {
	if log == nil {
		log = slog.Default()
	}
	b := &RelayBridge{
		ctx:     ctx,
		rc:      rc,
		wgAddr:  net.UDPAddrFromAddrPort(wgAddr),
		log:     log,
		peers:   make(map[types.Key]*peerBridge),
		allowed: make(map[types.Key]bool),
	}
	go func() {
		// Receive returns when the relay link drops (or ctx ends). If it dropped
		// on its own, notify so the caller can reconnect and stop black-holing.
		_ = rc.Receive(ctx, b.inject)
		if ctx.Err() == nil && onDisconnect != nil {
			onDisconnect(b)
		}
	}()
	return b
}

// Allow marks a peer as expected (a netmap member), so an inbound relayed packet
// from it may lazily establish the reverse bridge. Bounds lazy socket creation
// to real peers, not arbitrary relay senders.
func (b *RelayBridge) Allow(peer types.Key) {
	b.mu.Lock()
	b.allowed[peer] = true
	b.mu.Unlock()
}

// Endpoint returns the local UDP endpoint WireGuard should use as peer's
// endpoint, creating the per-peer socket and its forward loop on first use. The
// returned address is stable for the life of the bridge.
func (b *RelayBridge) Endpoint(peer types.Key) (netip.AddrPort, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allowed[peer] = true
	pb, err := b.ensurePeerLocked(peer)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return pb.local, nil
}

// ensurePeerLocked returns the per-peer bridge, creating its socket + forward
// loop on first use. Caller holds b.mu.
func (b *RelayBridge) ensurePeerLocked(peer types.Key) (*peerBridge, error) {
	if b.closed {
		return nil, net.ErrClosed
	}
	if pb, ok := b.peers[peer]; ok {
		return pb, nil
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	pb := &peerBridge{
		peer:  peer,
		conn:  conn,
		local: conn.LocalAddr().(*net.UDPAddr).AddrPort(),
	}
	b.peers[peer] = pb
	go b.forwardLoop(b.ctx, pb)
	return pb, nil
}

// forwardLoop reads packets WireGuard sent to the peer's local endpoint and
// forwards them over the relay to that peer.
func (b *RelayBridge) forwardLoop(ctx context.Context, pb *peerBridge) {
	buf := make([]byte, 65535)
	for {
		n, _, err := pb.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed (peer removed or bridge shut down)
		}
		if ctx.Err() != nil {
			return
		}
		// Copy: the relay send may outlive this buffer's next reuse.
		pkt := append([]byte(nil), buf[:n]...)
		if err := b.rc.Send(pb.peer, pkt); err != nil {
			b.log.Debug("relaybridge: send failed", "peer", pb.peer.ShortString(), "err", err)
		}
	}
}

// inject writes a packet delivered by the relay into WireGuard, sourced from the
// peer's local endpoint so WG attributes it to that peer and replies there. The
// per-peer socket is created on demand: an inbound relayed packet auto-
// establishes the reverse bridge, so a peer that switches to the relay pulls the
// other end onto the relay too (via WireGuard endpoint roaming) without both
// sides having to independently decide to fall back.
func (b *RelayBridge) inject(src types.Key, data []byte) {
	b.mu.Lock()
	pb, ok := b.peers[src]
	if !ok {
		if !b.allowed[src] {
			b.mu.Unlock()
			b.log.Debug("relaybridge: drop packet from unexpected peer", "peer", src.ShortString())
			return
		}
		var err error
		if pb, err = b.ensurePeerLocked(src); err != nil {
			b.mu.Unlock()
			return
		}
	}
	b.mu.Unlock()
	if _, err := pb.conn.WriteToUDP(data, b.wgAddr); err != nil {
		b.log.Debug("relaybridge: inject failed", "peer", src.ShortString(), "err", err)
	}
}

// RetainPeers reconciles the bridge to the current netmap: any peer not in keep
// has its socket closed and its allow-entry dropped, so a revoked or ACL-hidden
// peer can no longer keep a bridge socket or lazily create one (security review).
func (b *RelayBridge) RetainPeers(keep []types.Key) {
	want := make(map[types.Key]bool, len(keep))
	for _, k := range keep {
		want[k] = true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k := range b.allowed {
		if !want[k] {
			delete(b.allowed, k)
		}
	}
	for k, pb := range b.peers {
		if !want[k] {
			_ = pb.conn.Close()
			delete(b.peers, k)
		}
	}
}

// Remove tears down the bridge socket for a peer (e.g. it left the netmap).
func (b *RelayBridge) Remove(peer types.Key) {
	b.mu.Lock()
	pb := b.peers[peer]
	delete(b.peers, peer)
	b.mu.Unlock()
	if pb != nil {
		_ = pb.conn.Close()
	}
}

// Close tears down every peer socket. The relay client is owned by the caller.
func (b *RelayBridge) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for k, pb := range b.peers {
		_ = pb.conn.Close()
		delete(b.peers, k)
	}
}
