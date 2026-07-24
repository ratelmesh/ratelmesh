package wgengine

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// FirstRenderableEndpoint returns the first candidate that is a well-formed
// ip:port, or "" if none is.
//
// Both config formats here are line-oriented, so an endpoint carrying a newline
// would inject arbitrary directives into the peer's block — an endpoint of
// "1.2.3.4:51820\nallowed_ip=0.0.0.0/0" makes the remote peer own the default
// route and captures the host's traffic. Endpoints are deliberately excluded
// from the authority signature (see types.Node.Endpoints), so they are attacker
// -controlled input even when the netmap signature verifies; validating here is
// what keeps that exclusion safe. netip.ParseAddrPort accepts no whitespace, so
// it rejects the whole class rather than just newlines.
//
// Dropping an unparseable candidate is fail-safe: the peer is rendered with no
// endpoint, exactly as when none was advertised, and connectivity falls back to
// relay instead of trusting a malformed value.
func FirstRenderableEndpoint(endpoints []string) string {
	for _, ep := range endpoints {
		if _, err := netip.ParseAddrPort(ep); err == nil {
			return ep
		}
	}
	return ""
}

// UAPIConfig renders the userspace WireGuard configuration protocol used by an
// in-process wireguard-go device. Unlike wg setconf, keys are lowercase hex and
// fields are key=value lines.
func UAPIConfig(cfg Config) string {
	return uapiConfig(cfg, Config{}, true)
}

// UAPIConfigUpdate updates an already-running userspace WireGuard device
// without replacing unchanged peers. replace_peers tears down peer handshake
// state, so using it for a route-only EXIT promotion creates a promote/demote
// loop. Removed peers are deleted explicitly instead.
func UAPIConfigUpdate(cfg, previous Config) string {
	return uapiConfig(cfg, previous, false)
}

func uapiConfig(cfg, previous Config, replacePeers bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	if replacePeers {
		b.WriteString("replace_peers=true\n")
	} else {
		current := make(map[string]struct{}, len(cfg.Peers))
		for _, p := range cfg.Peers {
			current[p.PublicKey.String()] = struct{}{}
		}
		removed := make([]Peer, 0)
		for _, p := range previous.Peers {
			if _, ok := current[p.PublicKey.String()]; !ok {
				removed = append(removed, p)
			}
		}
		sort.Slice(removed, func(i, j int) bool { return removed[i].PublicKey.String() < removed[j].PublicKey.String() })
		for _, p := range removed {
			fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
			b.WriteString("remove=true\n")
		}
	}
	peers := append([]Peer(nil), cfg.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey.String() < peers[j].PublicKey.String() })
	for _, p := range peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		if !p.PresharedKey.IsZero() {
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(p.PresharedKey[:]))
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, prefix := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", prefix)
		}
		if ep := FirstRenderableEndpoint(p.Endpoints); ep != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", ep)
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
	}
	return b.String()
}

// WgQuickConfig renders a Config as a wg-quick INI document (includes the
// Address line, which wg-quick programs on the interface).
func WgQuickConfig(cfg Config) string { return wgConfig(cfg, true) }

// WgSetConf renders a Config for `wg setconf`, which understands only keys/peers
// — NOT the Address line (that is a wg-quick extension). The real engine uses
// this and programs addresses separately with `ip addr`.
func WgSetConf(cfg Config) string { return wgConfig(cfg, false) }

// wgConfig is the shared renderer. This is the platform-independent heart of the
// real data plane; keeping it untagged means it is always compiled and tested.
func wgConfig(cfg Config, includeAddress bool) string {
	var b strings.Builder

	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.PrivateKey.String())
	if cfg.ListenPort != 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", cfg.ListenPort)
	}
	if includeAddress && len(cfg.Addresses) > 0 {
		addrs := make([]string, len(cfg.Addresses))
		for i, a := range cfg.Addresses {
			addrs[i] = a.String()
		}
		fmt.Fprintf(&b, "Address = %s\n", strings.Join(addrs, ", "))
	}
	if includeAddress && len(cfg.DNSServers) > 0 {
		servers := make([]string, len(cfg.DNSServers))
		for i, server := range cfg.DNSServers {
			servers[i] = server.String()
		}
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(servers, ", "))
	}

	// Deterministic peer ordering keeps the output stable (testable, diffable).
	peers := append([]Peer(nil), cfg.Peers...)
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].PublicKey.String() < peers[j].PublicKey.String()
	})

	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey.String())
		if !p.PresharedKey.IsZero() {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey.String())
		}
		if len(p.AllowedIPs) > 0 {
			ips := make([]string, len(p.AllowedIPs))
			for i, a := range p.AllowedIPs {
				ips[i] = a.String()
			}
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(ips, ", "))
		}
		if ep := FirstRenderableEndpoint(p.Endpoints); ep != "" {
			// M1 uses the first candidate; magicsock will pick dynamically in M2.
			fmt.Fprintf(&b, "Endpoint = %s\n", ep)
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
	}

	return b.String()
}
