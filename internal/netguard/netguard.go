// Package netguard implements the kill switch and DNS-leak protection
// (DESIGN.md §3.3). When an exit node carries all traffic, the kill switch makes
// the host fail closed: if the tunnel drops, everything except the paths needed
// to rebuild the tunnel (and local/LAN) is blocked, so the real IP never leaks.
// This package computes the desired firewall policy and renders it for the host
// firewall (pf on macOS, nftables on Linux); an Enforcer applies it.
package netguard

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Policy is the desired fail-closed firewall state.
type Policy struct {
	// Enabled turns the kill switch on. When false, an Enforcer clears all rules.
	Enabled bool
	// TunnelEndpoints are the exit ip:port(s) reached by UDP (direct WireGuard)
	// that must remain reachable so the tunnel can (re)connect.
	TunnelEndpoints []netip.AddrPort
	// RelayEndpoints are relay ip:port(s) reached by TCP. When the tunnel runs
	// over a relay, this TCP path must stay open or the kill switch would sever
	// the very transport carrying the tunnel (security review).
	RelayEndpoints []netip.AddrPort
	// ControlEndpoints are coordinator ip:port(s) reached by TCP. They remain
	// reachable while fail-closed so registration and long-poll reconnects can
	// restore a selected exit after sleep or roaming.
	ControlEndpoints []netip.AddrPort
	// AllowCIDRs are networks always permitted directly: the mesh range, RFC1918
	// LAN, loopback. Everything else is blocked while the kill switch is armed.
	AllowCIDRs []netip.Prefix
	// TunnelInterface is the WireGuard interface name (Linux "ratelmesh0", macOS a
	// dynamic "utunN"). Traffic OUT this interface is allowed, so full-tunnel app
	// packets — which hit the OUTPUT hook with a PUBLIC destination before
	// WireGuard encapsulates them — are not dropped by the kill switch (Grok #1).
	// Safe: if the tunnel is down WireGuard drops these packets, so no cleartext
	// leaks; only encrypted traffic ever reaches the physical interface.
	TunnelInterface string
}

// DefaultAllowCIDRs returns the always-allowed ranges: loopback, mesh, and
// private LAN space (so the user keeps local connectivity under the kill switch).
func DefaultAllowCIDRs() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("100.64.0.0/10"), // mesh
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fe80::/10"), // link-local
	}
}

// RenderPF renders the policy as a pf.conf ruleset (macOS/BSD).
func RenderPF(p Policy) string {
	if !p.Enabled {
		return "# ratelmesh kill switch disabled\n"
	}
	var b strings.Builder
	b.WriteString("# RatelMesh kill switch (fail-closed)\n")
	b.WriteString("set block-policy drop\n")
	// Keep the local control plane completely outside PF state tracking. A plain
	// pass rule is not enough when a ruleset is replaced while a connection is in
	// flight: macOS can retain half-open loopback state, filling the GUI listener's
	// backlog after Wi-Fi/cellular roaming even though the encrypted data path is
	// healthy. `set skip` is PF's canonical loopback treatment and does not permit
	// any traffic onto a physical interface.
	b.WriteString("set skip on lo0\n")
	b.WriteString("block out all\n")
	// These are static destination/interface allowlists, not a stateful
	// firewall boundary. Loading a new global PF ruleset while an established
	// SSH, WireGuard UDP, or coordinator TCP flow is in flight gives that flow
	// no SYN-created state in the new ruleset; PF then drops it despite the
	// allowlist. `no state` makes every allowed packet match the same explicit
	// boundary across repeated netmap/candidate reconfiguration.
	if p.TunnelInterface != "" {
		fmt.Fprintf(&b, "pass out on %s all no state\n", p.TunnelInterface)
	}
	for _, c := range sortedPrefixes(p.AllowCIDRs) {
		fmt.Fprintf(&b, "pass out to %s no state\n", c)
	}
	for _, ep := range sortedEndpoints(p.TunnelEndpoints) {
		fmt.Fprintf(&b, "pass out proto udp to %s port %d no state\n", ep.Addr(), ep.Port())
	}
	for _, ep := range sortedEndpoints(p.RelayEndpoints) {
		fmt.Fprintf(&b, "pass out proto tcp to %s port %d no state\n", ep.Addr(), ep.Port())
	}
	for _, ep := range sortedEndpoints(p.ControlEndpoints) {
		fmt.Fprintf(&b, "pass out proto tcp to %s port %d no state\n", ep.Addr(), ep.Port())
	}
	return b.String()
}

// RenderNFT renders the policy as an nftables ruleset (Linux).
func RenderNFT(p Policy) string {
	if !p.Enabled {
		return "# ratelmesh kill switch disabled\n"
	}
	var b strings.Builder
	b.WriteString("table inet ratelmesh_killswitch {\n")
	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority 0; policy drop;\n")
	b.WriteString("    oif \"lo\" accept\n")
	if p.TunnelInterface != "" {
		fmt.Fprintf(&b, "    oif %q accept\n", p.TunnelInterface)
	}
	for _, c := range sortedPrefixes(p.AllowCIDRs) {
		fam := "ip"
		if c.Addr().Is6() {
			fam = "ip6"
		}
		fmt.Fprintf(&b, "    %s daddr %s accept\n", fam, c)
	}
	for _, ep := range sortedEndpoints(p.TunnelEndpoints) {
		fam := "ip"
		if ep.Addr().Is6() {
			fam = "ip6"
		}
		fmt.Fprintf(&b, "    %s daddr %s udp dport %d accept\n", fam, ep.Addr(), ep.Port())
	}
	for _, ep := range sortedEndpoints(p.RelayEndpoints) {
		fam := "ip"
		if ep.Addr().Is6() {
			fam = "ip6"
		}
		fmt.Fprintf(&b, "    %s daddr %s tcp dport %d accept\n", fam, ep.Addr(), ep.Port())
	}
	for _, ep := range sortedEndpoints(p.ControlEndpoints) {
		fam := "ip"
		if ep.Addr().Is6() {
			fam = "ip6"
		}
		fmt.Fprintf(&b, "    %s daddr %s tcp dport %d accept\n", fam, ep.Addr(), ep.Port())
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func sortedPrefixes(in []netip.Prefix) []netip.Prefix {
	out := append([]netip.Prefix(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func sortedEndpoints(in []netip.AddrPort) []netip.AddrPort {
	out := append([]netip.AddrPort(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
