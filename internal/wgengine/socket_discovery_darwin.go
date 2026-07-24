//go:build wgreal && darwin

package wgengine

import (
	"context"
	"fmt"
	"net/netip"
)

// DiscoverPublicEndpoint sends STUN through the persistent socket owned by the
// in-process macOS wireguard-go device. This method deliberately exists only on
// Darwin: kernel WireGuard implementations cannot lend their live socket to the
// daemon, so advertising this capability on Linux or Windows would be false.
func (e *RealEngine) DiscoverPublicEndpoint(ctx context.Context, addr string) (netip.AddrPort, error) {
	e.mu.Lock()
	bind := e.stunBind
	e.mu.Unlock()
	if bind == nil {
		return netip.AddrPort{}, fmt.Errorf("wgengine: socket STUN is unavailable")
	}
	return bind.Discover(ctx, addr)
}

// ProbeEndpoint proves a peer candidate over that same persistent WireGuard
// socket, so success validates the path that encrypted traffic actually uses.
func (e *RealEngine) ProbeEndpoint(ctx context.Context, endpoint netip.AddrPort) error {
	e.mu.Lock()
	bind := e.stunBind
	e.mu.Unlock()
	if bind == nil {
		return fmt.Errorf("wgengine: endpoint probing is unavailable")
	}
	return bind.Probe(ctx, endpoint)
}

var _ PublicEndpointDiscoverer = (*RealEngine)(nil)
var _ EndpointProber = (*RealEngine)(nil)
