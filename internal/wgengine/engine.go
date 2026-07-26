// Package wgengine abstracts the WireGuard data plane so the rest of ratelmeshd is
// platform- and implementation-independent (DESIGN.md §10.1). The default build
// uses a rootless stub that records configuration without touching the network,
// which lets the control-plane logic be exercised in CI and sandboxes. The real
// kernel/userspace WireGuard implementation lives behind the `wgreal` build tag.
package wgengine

import (
	"context"
	"net/netip"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

// pathSafeTunnelMTU is IPv6's guaranteed minimum link MTU. Keeping the inner
// tunnel at this size avoids silent HTTPS/QUIC blackholes when WireGuard is
// nested inside relay/TLS, cross-border, hotspot, or other low-MTU paths.
const pathSafeTunnelMTU = 1280

// PublicEndpointDiscoverer discovers the NAT mapping of the exact UDP socket
// used by WireGuard. Implementations must not use a separate ephemeral socket:
// its mapped port is unrelated and cannot receive peer handshakes.
type PublicEndpointDiscoverer interface {
	DiscoverPublicEndpoint(context.Context, string) (netip.AddrPort, error)
}

// EndpointProber checks direct reachability through the exact UDP socket used
// by WireGuard. Using that socket is essential: a successful probe both proves
// the candidate and opens the same NAT mapping that encrypted packets use.
type EndpointProber interface {
	ProbeEndpoint(context.Context, netip.AddrPort) error
}

// EndpointDiscoveryPreparer opens the real WireGuard UDP socket before the
// daemon's first coordinator registration. STUN must use that exact persistent
// socket; discovering through a temporary socket advertises the wrong NAT
// mapping. Implementations that need this hook should install only the private
// key and listen port, without routes or peers.
type EndpointDiscoveryPreparer interface {
	PrepareEndpointDiscovery(Config) error
}

// PeerStat is a snapshot of one peer's WireGuard liveness.
type PeerStat struct {
	// Endpoint is WireGuard's authenticated current transport endpoint. It can
	// differ from every coordinator-advertised candidate after roaming or
	// symmetric-NAT translation, so macOS must preserve it when arming PF.
	Endpoint        netip.AddrPort
	LatestHandshake time.Time // last successful handshake (zero => never)
	RxBytes         int64     // cumulative bytes received from this peer
	TxBytes         int64     // cumulative bytes sent to this peer
}

// PeerStatsReporter is implemented by engines that can report per-peer WireGuard
// liveness. The daemon uses it to detect a dead direct path (fall back to the
// relay) and a recovered one (upgrade back), keyed on received-byte progress
// (DESIGN.md §3.2). Optional: engines may not implement it.
type PeerStatsReporter interface {
	PeerStats() (map[types.Key]PeerStat, error)
}

// DataPlaneRecoverer is implemented by engines that can rebuild a failed
// interface without restarting the whole daemon. The daemon invokes it only
// after repeated health-check failures and only after at least one netmap was
// successfully applied, so a transient command error does not flap routes.
type DataPlaneRecoverer interface {
	DataPlaneRecoveryEnabled() bool
	RecoverDataPlane() error
}

// NetworkPathRecoverer rebuilds a userspace data plane whose UDP socket still
// answers control queries but can no longer send after the physical interface
// changes. This is distinct from DataPlaneRecoverer: a stale macOS socket may
// have a healthy utun and IPC channel while every send fails with
// EADDRNOTAVAIL.
type NetworkPathRecoverer interface {
	RecoverNetworkPath() error
}

// PersistentCleanupPreparer lets a production engine reconcile only
// previously recorded route owners before it mutates the network again.
type PersistentCleanupPreparer interface {
	PreparePersistentCleanup(stateDir string) error
}

// ExitHandshakeGater marks a production engine that must not receive default
// routes until the selected exit peer has completed a recent WireGuard
// handshake. This prevents a dead exit path from blackholing the host before
// relay/control connectivity can finish bringing that path up.
type ExitHandshakeGater interface {
	RequiresExitHandshake() bool
}

// Peer is one WireGuard peer as programmed into the data plane.
type Peer struct {
	PublicKey    types.Key
	PresharedKey types.Key      // hybrid ML-KEM-derived PSK; zero only in explicit legacy mode
	Endpoints    []string       // candidate ip:port; the engine/magicsock picks one
	AllowedIPs   []netip.Prefix // routes owned by this peer
	// Keepalive, if >0, sets PersistentKeepalive (seconds): WG sends periodic
	// keepalives, which keeps NAT mappings open and, crucially, drives handshake
	// attempts so the daemon can tell whether a path works (relay fallback).
	Keepalive int
}

// Config is a full data-plane snapshot. ratelmeshd recomputes it from each netmap and
// hands it to the engine, which diffs against current state.
type Config struct {
	PrivateKey types.Key
	ListenPort uint16
	// KillSwitch requests fail-closed firewall behavior while a default-route
	// peer is active. On Windows the official tunnel service implements this
	// when a peer retains a /0 AllowedIP; other platforms use netguard.
	KillSwitch bool
	// Addresses assigned to the local TUN interface (this device's mesh IPs).
	Addresses []netip.Prefix
	// DNSServers are emitted only by the wg-quick renderer. WireGuard for
	// Windows applies them to the tunnel adapter and restores the prior system
	// resolver state when the tunnel service is removed.
	DNSServers []netip.Addr
	Peers      []Peer
	// PhysicalEndpoints are control/relay server IPs that must stay on their
	// current physical path while a default-route peer is active. Without these
	// host-route pins, a relay-backed exit can route the relay's own TCP/WSS
	// connection into the not-yet-working tunnel and deadlock bootstrap.
	PhysicalEndpoints []netip.Addr
	// Split-tunnel overrides, applied only when an exit provides a default route
	// (DESIGN.md §8.4). DirectRoutes bypass the tunnel via the physical gateway;
	// BlockRoutes are dropped (blackholed).
	DirectRoutes []netip.Prefix
	BlockRoutes  []netip.Prefix
}

// Engine is the data-plane contract. Implementations must be safe to call
// Reconfigure repeatedly with the latest desired state.
type Engine interface {
	// Up brings the interface online (creates TUN, binds the UDP socket).
	Up() error
	// Reconfigure applies the desired peer/address set, diffing internally.
	Reconfigure(cfg Config) error
	// Peers returns the public keys currently programmed (for status output).
	Peers() []types.Key
	// Down tears the interface down.
	Down() error
	// Close releases all resources.
	Close() error
}

// InterfaceNamer is implemented by engines that own a named OS interface (the
// real data plane). The daemon uses it to allow traffic out the WireGuard
// interface in the kill switch. The stub engine does not implement it.
type InterfaceNamer interface {
	// InterfaceName returns the WG interface name ("ratelmesh0" on Linux/Windows,
	// "utunN" on macOS), or "" if the interface is not up yet.
	InterfaceName() string
}

// ParseAllowedIPs converts CIDR strings from a netmap into prefixes, skipping
// any that fail to parse.
func ParseAllowedIPs(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p)
		}
	}
	return out
}
