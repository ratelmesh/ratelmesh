// Package netguard implements the kill switch and DNS-leak protection
// (DESIGN.md §3.3). When an exit node carries all traffic, the kill switch makes
// the host fail closed: if the tunnel drops, everything except the paths needed
// to rebuild the tunnel (and local/LAN) is blocked, so the real IP never leaks.
// This package computes the desired firewall policy and renders it for the host
// firewall (pf on macOS, nftables on Linux); an Enforcer applies it.
package netguard

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

var (
	meshIPv4 = netip.MustParsePrefix("100.64.0.0/10")
	meshIPv6 = netip.MustParsePrefix("fc00::/7")
)

// ManagedService is a TCP service whose mesh-facing access is deny-by-default.
// TargetMeshIP is deliberately part of the rule: a grant for one local mesh
// address cannot accidentally expose the same port on another address.
type ManagedService struct {
	TargetMeshIP netip.Addr
	TCPPort      uint16
}

// RemoteAccessRule is one exact, temporary authorization. Grant identifiers and
// expiry timestamps are control-plane data and intentionally never enter the
// host firewall text; callers remove an expired grant by applying a new Policy.
type RemoteAccessRule struct {
	SourceMeshIP netip.Addr
	TargetMeshIP netip.Addr
	TCPPort      uint16
}

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
	// WireGuard encapsulates them — are not dropped by the kill switch.
	// Safe: if the tunnel is down WireGuard drops these packets, so no cleartext
	// leaks; only encrypted traffic ever reaches the physical interface.
	TunnelInterface string

	// RemoteEnforcement enables deny-by-default mesh ingress for ManagedServices.
	// It is independent of Enabled: a target which is not using an EXIT still
	// needs its remote-access boundary.
	RemoteEnforcement bool
	ManagedServices   []ManagedService
	RemoteAccessRules []RemoteAccessRule
	// RemoteMeshPrefixes defines mesh source address space. Only the production
	// CGNAT range and IPv6 ULA space are accepted.
	RemoteMeshPrefixes []netip.Prefix
}

// DefaultAllowCIDRs returns the ranges allowed directly on the physical link:
// loopback, private LAN space and IPv6 link-local. The mesh CGNAT range is
// deliberately absent. Mesh packets are allowed by TunnelInterface instead;
// allowing 100.64.0.0/10 independent of interface would leak them to an ISP
// using CGNAT whenever a more-specific mesh route disappeared.
func DefaultAllowCIDRs() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fe80::/10"), // link-local
	}
}

// Active reports whether any host firewall protection must remain loaded.
func (p Policy) Active() bool {
	return p.Enabled || p.RemoteEnforcement
}

// Validate rejects data which could escape the closed firewall grammar.
func (p Policy) Validate() error {
	if !p.Active() {
		if len(p.ManagedServices) != 0 || len(p.RemoteAccessRules) != 0 || len(p.RemoteMeshPrefixes) != 0 {
			return errors.New("netguard: remote policy fields require remote enforcement")
		}
		return nil
	}
	if p.TunnelInterface != "" && !validInterface(p.TunnelInterface) {
		return errors.New("netguard: invalid tunnel interface")
	}
	for _, ep := range append(append(append([]netip.AddrPort(nil), p.TunnelEndpoints...), p.RelayEndpoints...), p.ControlEndpoints...) {
		if !validEndpoint(ep) {
			return errors.New("netguard: invalid endpoint")
		}
	}
	for _, prefix := range p.AllowCIDRs {
		if !validPrefix(prefix) {
			return errors.New("netguard: invalid allowed prefix")
		}
	}
	if !p.RemoteEnforcement {
		if len(p.ManagedServices) != 0 || len(p.RemoteAccessRules) != 0 || len(p.RemoteMeshPrefixes) != 0 {
			return errors.New("netguard: remote policy fields require remote enforcement")
		}
		return nil
	}
	if p.TunnelInterface == "" {
		return errors.New("netguard: remote enforcement requires tunnel interface")
	}
	if p.TunnelInterface == "lo" || p.TunnelInterface == "lo0" {
		return errors.New("netguard: remote enforcement cannot use loopback")
	}
	if len(p.ManagedServices) == 0 {
		return errors.New("netguard: remote enforcement requires managed services")
	}
	prefixes := p.remotePrefixes()
	for _, prefix := range prefixes {
		if !validRemotePrefix(prefix) {
			return errors.New("netguard: invalid remote mesh prefix")
		}
	}
	managed := make(map[ManagedService]struct{}, len(p.ManagedServices))
	for _, service := range p.ManagedServices {
		if !validMeshAddr(service.TargetMeshIP, prefixes) || service.TCPPort == 0 {
			return errors.New("netguard: invalid managed service")
		}
		if _, exists := managed[service]; exists {
			return errors.New("netguard: duplicate managed service")
		}
		managed[service] = struct{}{}
	}
	seenRules := make(map[RemoteAccessRule]struct{}, len(p.RemoteAccessRules))
	for _, rule := range p.RemoteAccessRules {
		if !validMeshAddr(rule.SourceMeshIP, prefixes) ||
			!validMeshAddr(rule.TargetMeshIP, prefixes) ||
			rule.SourceMeshIP.BitLen() != rule.TargetMeshIP.BitLen() ||
			rule.SourceMeshIP == rule.TargetMeshIP ||
			rule.TCPPort == 0 {
			return errors.New("netguard: invalid remote access rule")
		}
		if _, ok := managed[ManagedService{TargetMeshIP: rule.TargetMeshIP, TCPPort: rule.TCPPort}]; !ok {
			return errors.New("netguard: grant does not reference a managed service")
		}
		if _, exists := seenRules[rule]; exists {
			return errors.New("netguard: duplicate remote access rule")
		}
		seenRules[rule] = struct{}{}
	}
	return nil
}

// RenderPF renders the complete policy as a pf.conf ruleset (macOS/BSD).
func RenderPF(p Policy) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if !p.Active() {
		return "# ratelmesh firewall disabled\n", nil
	}
	var b strings.Builder
	b.WriteString("# RatelMesh managed firewall (fail-closed)\n")
	b.WriteString("set block-policy drop\n")
	// Keep the local control plane completely outside PF state tracking. A plain
	// pass rule is not enough when a ruleset is replaced while a connection is in
	// flight: macOS can retain half-open loopback state, filling the GUI listener's
	// backlog after Wi-Fi/cellular roaming even though the encrypted data path is
	// healthy. `set skip` is PF's canonical loopback treatment and does not permit
	// any traffic onto a physical interface.
	b.WriteString("set skip on lo0\n")
	if p.RemoteEnforcement {
		for _, rule := range sortedRules(p.RemoteAccessRules) {
			fmt.Fprintf(&b, "pass in quick on %s proto tcp from %s to %s port = %d no state\n",
				p.TunnelInterface, rule.SourceMeshIP, rule.TargetMeshIP, rule.TCPPort)
		}
		for _, service := range sortedServices(p.ManagedServices) {
			fmt.Fprintf(&b, "block in quick on %s proto tcp from any to %s port = %d\n",
				p.TunnelInterface, service.TargetMeshIP, service.TCPPort)
		}
	}
	if !p.Enabled {
		return b.String(), nil
	}
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
	return b.String(), nil
}

// RenderNFT renders the complete policy as an nftables ruleset (Linux).
func RenderNFT(p Policy) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if !p.Active() {
		return "# ratelmesh firewall disabled\n", nil
	}
	var b strings.Builder
	b.WriteString("table inet ratelmesh_killswitch {\n")
	if p.RemoteEnforcement {
		b.WriteString("  chain input {\n")
		b.WriteString("    type filter hook input priority 0; policy accept;\n")
		for _, rule := range sortedRules(p.RemoteAccessRules) {
			fam := addressFamily(rule.TargetMeshIP)
			fmt.Fprintf(&b, "    iif %q %s saddr %s %s daddr %s tcp dport %d accept\n",
				p.TunnelInterface, fam, rule.SourceMeshIP, fam, rule.TargetMeshIP, rule.TCPPort)
		}
		for _, service := range sortedServices(p.ManagedServices) {
			fam := addressFamily(service.TargetMeshIP)
			fmt.Fprintf(&b, "    iif %q %s daddr %s tcp dport %d drop\n",
				p.TunnelInterface, fam, service.TargetMeshIP, service.TCPPort)
		}
		b.WriteString("  }\n")
	}
	if !p.Enabled {
		b.WriteString("}\n")
		return b.String(), nil
	}
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
	return b.String(), nil
}

func (p Policy) remotePrefixes() []netip.Prefix {
	if len(p.RemoteMeshPrefixes) == 0 {
		return []netip.Prefix{meshIPv4}
	}
	return sortedPrefixes(p.RemoteMeshPrefixes)
}

func validInterface(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

func validEndpoint(ep netip.AddrPort) bool {
	return ep.IsValid() && ep.Port() != 0 && validAddr(ep.Addr())
}

func validPrefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix == prefix.Masked() && validAddr(prefix.Addr())
}

func validAddr(addr netip.Addr) bool {
	return addr.IsValid() && !addr.IsUnspecified() && !addr.IsMulticast() && addr.Zone() == ""
}

func validRemotePrefix(prefix netip.Prefix) bool {
	if !validPrefix(prefix) {
		return false
	}
	if prefix.Addr().Is4() {
		return meshIPv4.Bits() <= prefix.Bits() && meshIPv4.Contains(prefix.Addr())
	}
	return meshIPv6.Bits() <= prefix.Bits() && meshIPv6.Contains(prefix.Addr())
}

func validMeshAddr(addr netip.Addr, prefixes []netip.Prefix) bool {
	if !validAddr(addr) {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func addressFamily(addr netip.Addr) string {
	if addr.Is6() {
		return "ip6"
	}
	return "ip"
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

func sortedServices(in []ManagedService) []ManagedService {
	out := append([]ManagedService(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetMeshIP.Compare(out[j].TargetMeshIP) != 0 {
			return out[i].TargetMeshIP.Compare(out[j].TargetMeshIP) < 0
		}
		return out[i].TCPPort < out[j].TCPPort
	})
	return out
}

func sortedRules(in []RemoteAccessRule) []RemoteAccessRule {
	out := append([]RemoteAccessRule(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetMeshIP.Compare(out[j].TargetMeshIP) != 0 {
			return out[i].TargetMeshIP.Compare(out[j].TargetMeshIP) < 0
		}
		if out[i].TCPPort != out[j].TCPPort {
			return out[i].TCPPort < out[j].TCPPort
		}
		return out[i].SourceMeshIP.Compare(out[j].SourceMeshIP) < 0
	})
	return out
}
