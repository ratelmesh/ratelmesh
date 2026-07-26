package netguard

import (
	"net/netip"
	"strings"
	"testing"
)

func samplePolicy() Policy {
	return Policy{
		Enabled:         true,
		TunnelEndpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:51820")},
		AllowCIDRs:      DefaultAllowCIDRs(),
	}
}

func mustPF(t *testing.T, p Policy) string {
	t.Helper()
	out, err := RenderPF(p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustNFT(t *testing.T, p Policy) string {
	t.Helper()
	out, err := RenderNFT(p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRenderPFFailsClosed(t *testing.T) {
	out := mustPF(t, samplePolicy())
	for _, want := range []string{
		"block out all",   // default deny
		"set skip on lo0", // local API bypasses PF state tracking
		"pass out to 100.64.0.0/10 no state",
		"pass out proto udp to 203.0.113.7 port 51820 no state", // tunnel endpoint reachable
	} {
		if !strings.Contains(out, want) {
			t.Errorf("pf output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "pass out on lo0") {
		t.Fatalf("loopback must use PF skip instead of a stateful pass rule:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "pass out ") && !strings.HasSuffix(line, " no state") {
			t.Fatalf("PF allow rule can strand established traffic after reload: %q", line)
		}
	}
}

func TestRenderNFTFailsClosed(t *testing.T) {
	out := mustNFT(t, samplePolicy())
	for _, want := range []string{
		"policy drop;",
		"oif \"lo\" accept",
		"ip daddr 100.64.0.0/10 accept",
		"udp dport 51820 accept",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("nft output missing %q\n%s", want, out)
		}
	}
}

func TestDisabledRendersNoBlock(t *testing.T) {
	if strings.Contains(mustPF(t, Policy{Enabled: false}), "block out all") {
		t.Error("disabled kill switch must not block traffic")
	}
	if strings.Contains(mustNFT(t, Policy{Enabled: false}), "policy drop") {
		t.Error("disabled kill switch must not block traffic")
	}
}

func TestStubEnforcerRecordsPolicy(t *testing.T) {
	e := NewStubEnforcer(nil)
	p := samplePolicy()
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	if !e.Current().Enabled {
		t.Error("enforcer did not record applied policy")
	}
	if err := e.Clear(); err != nil {
		t.Fatal(err)
	}
	if e.Current().Enabled {
		t.Error("enforcer did not clear policy")
	}
}

func TestStubEnforcerPolicyStateHasNoSliceAliases(t *testing.T) {
	e := NewStubEnforcer(nil)
	p := remotePolicy()
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	p.RemoteAccessRules[0].TCPPort = 1
	got := e.Current()
	if got.RemoteAccessRules[0].TCPPort == 1 {
		t.Fatal("stub Apply retained caller slice alias")
	}
	got.RemoteAccessRules[0].TCPPort = 2
	if e.Current().RemoteAccessRules[0].TCPPort == 2 {
		t.Fatal("stub Current exposed internal slice alias")
	}
}

// TestRelayEndpointAllowedOverTCP is the §2 regression: when the tunnel rides a
// relay, the relay's TCP port must be permitted or the kill switch would sever
// the tunnel's own transport.
func TestRelayEndpointAllowedOverTCP(t *testing.T) {
	p := Policy{
		Enabled:        true,
		RelayEndpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:3478")},
	}
	nft := mustNFT(t, p)
	if !strings.Contains(nft, "198.51.100.7 tcp dport 3478 accept") {
		t.Errorf("nft ruleset missing relay TCP allow:\n%s", nft)
	}
	pf := mustPF(t, p)
	if !strings.Contains(pf, "pass out proto tcp to 198.51.100.7 port 3478 no state") {
		t.Errorf("pf ruleset missing relay TCP allow:\n%s", pf)
	}
}

func TestControlEndpointAllowedOverTCP(t *testing.T) {
	p := Policy{
		Enabled:          true,
		ControlEndpoints: []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::7]:443")},
	}
	nft := mustNFT(t, p)
	if !strings.Contains(nft, "ip6 daddr 2001:db8::7 tcp dport 443 accept") {
		t.Errorf("nft ruleset missing IPv6 coordinator allow:\n%s", nft)
	}
	pf := mustPF(t, p)
	if !strings.Contains(pf, "pass out proto tcp to 2001:db8::7 port 443 no state") {
		t.Errorf("pf ruleset missing IPv6 coordinator allow:\n%s", pf)
	}
}

func TestKillSwitchBlocksBothAddressFamiliesOffTunnel(t *testing.T) {
	pf := mustPF(t, Policy{Enabled: true, TunnelInterface: "utun9"})
	if !strings.Contains(pf, "block out all") || !strings.Contains(pf, "pass out on utun9 all") {
		t.Fatalf("pf policy must block IPv4/IPv6 on physical interfaces and allow the tunnel:\n%s", pf)
	}
	nft := mustNFT(t, Policy{Enabled: true, TunnelInterface: "ratelmesh0"})
	if !strings.Contains(nft, "table inet ") || !strings.Contains(nft, "policy drop;") {
		t.Fatalf("nft inet policy must cover IPv4 and IPv6:\n%s", nft)
	}
}

// TestKillSwitchAllowsTunnelInterface verifies that with a TunnelInterface set,
// the rendered rules allow traffic OUT the WireGuard interface, so a
// full-tunnel app packet (public dest, pre-encapsulation) is not dropped —
// arming the kill switch must not break exit egress.
func TestKillSwitchAllowsTunnelInterface(t *testing.T) {
	p := Policy{Enabled: true, AllowCIDRs: DefaultAllowCIDRs(), TunnelInterface: "ratelmesh0"}
	nft := mustNFT(t, p)
	if !strings.Contains(nft, `oif "ratelmesh0" accept`) {
		t.Fatalf("nftables ruleset missing tunnel-interface accept:\n%s", nft)
	}
	pf := mustPF(t, p)
	if !strings.Contains(pf, "pass out on ratelmesh0 all") {
		t.Fatalf("pf ruleset missing tunnel-interface pass:\n%s", pf)
	}
	// Without a TunnelInterface (e.g. stub engine) no such rule is emitted.
	if strings.Contains(mustNFT(t, Policy{Enabled: true}), "oif \"ratelmesh0\"") {
		t.Fatal("emitted a tunnel-interface rule with no interface set")
	}
}
