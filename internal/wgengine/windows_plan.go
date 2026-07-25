package wgengine

import (
	"net/netip"
	"slices"

	"github.com/shan25519/ratelmesh/internal/types"
)

// WindowsTunnelName is the WireGuard for Windows adapter name, derived by the
// tunnel service from the configuration file name. Exported (and defined
// outside the wgreal build tag) so other packages — e.g. the Windows DNS
// upstream discovery — reference the same name instead of a drifting literal.
const WindowsTunnelName = "ratelmesh0"

// windowsRoutePlan is intentionally platform-independent so Windows route
// semantics can be tested on the normal developer and CI hosts.
type windowsRoutePlan struct {
	hasDefault bool
	direct     []netip.Prefix
	block      []netip.Prefix
	// pins are the default-route peers' endpoint IPs. They must be host-routed
	// to the physical path (mirroring the Unix pinEndpoint) because the /1
	// halves the tunnel service installs would otherwise route packets to the
	// exit's own endpoint back into the tunnel — a loop that prevents the
	// handshake from ever completing.
	pins []netip.Addr
}

type windowsManagedRoute struct {
	prefix         netip.Prefix
	interfaceIndex string
	nextHop        string
}

func planWindowsRoutes(cfg Config) windowsRoutePlan {
	var plan windowsRoutePlan
	seen := make(map[netip.Addr]bool)
	addPin := func(addr netip.Addr) {
		addr = addr.Unmap()
		if addr.IsValid() && !seen[addr] {
			seen[addr] = true
			plan.pins = append(plan.pins, addr)
		}
	}
	for _, peer := range cfg.Peers {
		peerDefault := false
		for _, allowed := range peer.AllowedIPs {
			if allowed.Addr().Is4() && allowed.Bits() == 0 {
				plan.hasDefault = true
				peerDefault = true
				break
			}
		}
		if !peerDefault || len(peer.Endpoints) == 0 {
			continue
		}
		if ap, err := netip.ParseAddrPort(peer.Endpoints[0]); err == nil {
			addPin(ap.Addr())
		}
	}
	if plan.hasDefault {
		for _, addr := range cfg.PhysicalEndpoints {
			addPin(addr)
		}
		plan.direct = append(plan.direct, cfg.DirectRoutes...)
		plan.block = append(plan.block, cfg.BlockRoutes...)
	}
	return plan
}

// defaultRouteHalves is the split-default trick shared by the Unix route
// programmer and the Windows config renderer: a /0 is expressed as two /1
// halves, which win over the physical default route without deleting it (and,
// on Windows, without triggering the tunnel service's /0 kill-switch mode).
func defaultRouteHalves(is6 bool) []netip.Prefix {
	if is6 {
		return []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
	}
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
}

// windowsSplitDefaults returns a copy of cfg whose /0 AllowedIPs are expressed
// as /1 halves. When KillSwitch is explicitly requested, /0 entries are
// retained so the official tunnel service applies its fail-closed firewall.
func windowsSplitDefaults(cfg Config) Config {
	windowsCfg := cfg
	windowsCfg.Peers = make([]Peer, len(cfg.Peers))
	for i, peer := range cfg.Peers {
		windowsCfg.Peers[i] = peer
		windowsCfg.Peers[i].AllowedIPs = make([]netip.Prefix, 0, len(peer.AllowedIPs)+1)
		for _, allowed := range peer.AllowedIPs {
			if !cfg.KillSwitch && allowed.Bits() == 0 {
				windowsCfg.Peers[i].AllowedIPs = append(windowsCfg.Peers[i].AllowedIPs,
					defaultRouteHalves(allowed.Addr().Is6())...)
				continue
			}
			windowsCfg.Peers[i].AllowedIPs = append(windowsCfg.Peers[i].AllowedIPs, allowed)
		}
	}
	return windowsCfg
}

// windowsTunnelConfig renders the wg-quick configuration handed to the
// WireGuard for Windows tunnel service.
func windowsTunnelConfig(cfg Config) string {
	return WgQuickConfig(windowsSplitDefaults(cfg))
}

// windowsReconfigureUnchanged reports whether the desired tunnel-service state
// is identical to what is already applied — same rendered service config
// (covers key material, addresses, DNS, peers, endpoints) and the same
// direct/block route plans — so Reconfigure can skip touching the service.
// Netmap bumps caused by unrelated peers' status are the common case.
func windowsReconfigureUnchanged(prev, next Config) bool {
	return windowsTunnelConfig(prev) == windowsTunnelConfig(next) &&
		slices.Equal(prev.PhysicalEndpoints, next.PhysicalEndpoints) &&
		slices.Equal(prev.DirectRoutes, next.DirectRoutes) &&
		slices.Equal(prev.BlockRoutes, next.BlockRoutes)
}

// windowsSyncconfSufficient reports whether next differs from prev only in
// ways `wg syncconf` can apply to the live adapter (peer endpoints, keepalive,
// preshared state). Everything that drives adapter identity or routes must be
// unchanged: interface key/port/addresses/DNS, kill-switch mode, the peer set
// and every peer's AllowedIPs (the service builds routes from them), plus the
// direct/block plans. Endpoint and physical-transport changes are applied with
// wg syncconf while RealEngine stages their replacement host-route pins.
func windowsSyncconfSufficient(prev, next Config) bool {
	if prev.PrivateKey != next.PrivateKey || prev.ListenPort != next.ListenPort || prev.KillSwitch != next.KillSwitch {
		return false
	}
	if !slices.Equal(prev.Addresses, next.Addresses) || !slices.Equal(prev.DNSServers, next.DNSServers) {
		return false
	}
	if !slices.Equal(prev.DirectRoutes, next.DirectRoutes) || !slices.Equal(prev.BlockRoutes, next.BlockRoutes) {
		return false
	}
	if len(prev.Peers) != len(next.Peers) {
		return false
	}
	prevPeers := make(map[types.Key]Peer, len(prev.Peers))
	for _, peer := range prev.Peers {
		prevPeers[peer.PublicKey] = peer
	}
	for _, peer := range next.Peers {
		prevPeer, ok := prevPeers[peer.PublicKey]
		if !ok || !slices.Equal(prevPeer.AllowedIPs, peer.AllowedIPs) {
			return false
		}
	}
	return true
}

func peerHasDefaultRoute(peer Peer) bool {
	for _, allowed := range peer.AllowedIPs {
		if allowed.Bits() == 0 {
			return true
		}
	}
	return false
}
