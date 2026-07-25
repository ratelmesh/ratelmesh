package netguard

import (
	"net/netip"
	"strings"
	"testing"
)

func remotePolicy() Policy {
	return Policy{
		RemoteEnforcement: true,
		TunnelInterface:   "ratelmesh0",
		ManagedServices: []ManagedService{
			{TargetMeshIP: netip.MustParseAddr("100.64.0.5"), TCPPort: 5900},
			{TargetMeshIP: netip.MustParseAddr("100.64.0.5"), TCPPort: 22},
		},
		RemoteAccessRules: []RemoteAccessRule{
			{
				SourceMeshIP: netip.MustParseAddr("100.64.0.9"),
				TargetMeshIP: netip.MustParseAddr("100.64.0.5"),
				TCPPort:      22,
			},
		},
	}
}

func TestRemoteOnlyPolicyLoadsDenyByDefaultInput(t *testing.T) {
	p := remotePolicy()
	nft := mustNFT(t, p)
	if strings.Contains(nft, "chain output") {
		t.Fatalf("remote-only policy unexpectedly changed output traffic:\n%s", nft)
	}
	allow := `iif "ratelmesh0" ip saddr 100.64.0.9 ip daddr 100.64.0.5 tcp dport 22 accept`
	denySSH := `iif "ratelmesh0" ip daddr 100.64.0.5 tcp dport 22 drop`
	denyVNC := `iif "ratelmesh0" ip daddr 100.64.0.5 tcp dport 5900 drop`
	for _, want := range []string{allow, denySSH, denyVNC} {
		if !strings.Contains(nft, want) {
			t.Fatalf("nft output missing %q:\n%s", want, nft)
		}
	}
	if strings.Index(nft, allow) > strings.Index(nft, denySSH) {
		t.Fatalf("exact grant must precede managed-port deny:\n%s", nft)
	}

	pf := mustPF(t, p)
	for _, want := range []string{
		"pass in quick on ratelmesh0 proto tcp from 100.64.0.9 to 100.64.0.5 port = 22 no state",
		"block in quick on ratelmesh0 proto tcp from any to 100.64.0.5 port = 22",
		"block in quick on ratelmesh0 proto tcp from any to 100.64.0.5 port = 5900",
	} {
		if !strings.Contains(pf, want) {
			t.Fatalf("pf output missing %q:\n%s", want, pf)
		}
	}
}

func TestZeroGrantStillDeniesManagedService(t *testing.T) {
	p := remotePolicy()
	p.RemoteAccessRules = nil
	nft := mustNFT(t, p)
	if strings.Contains(nft, " tcp dport 22 accept") {
		t.Fatalf("zero-grant policy contains service allow:\n%s", nft)
	}
	if !strings.Contains(nft, "tcp dport 22 drop") {
		t.Fatalf("zero-grant policy omitted service deny:\n%s", nft)
	}
}

func TestCombinedPolicyContainsInputAndOutputProtection(t *testing.T) {
	p := remotePolicy()
	p.Enabled = true
	p.AllowCIDRs = DefaultAllowCIDRs()
	nft := mustNFT(t, p)
	if !strings.Contains(nft, "chain input") || !strings.Contains(nft, "chain output") ||
		!strings.Contains(nft, "policy drop;") {
		t.Fatalf("combined nft policy is incomplete:\n%s", nft)
	}
	pf := mustPF(t, p)
	if !strings.Contains(pf, "block in quick") || !strings.Contains(pf, "block out all") {
		t.Fatalf("combined pf policy is incomplete:\n%s", pf)
	}
}

func TestRemotePolicyIPv6AndDeterministicOrdering(t *testing.T) {
	p := Policy{
		RemoteEnforcement:  true,
		TunnelInterface:    "utun12",
		RemoteMeshPrefixes: []netip.Prefix{netip.MustParsePrefix("fd42::/48")},
		ManagedServices: []ManagedService{
			{TargetMeshIP: netip.MustParseAddr("fd42::5"), TCPPort: 5900},
			{TargetMeshIP: netip.MustParseAddr("fd42::5"), TCPPort: 22},
		},
		RemoteAccessRules: []RemoteAccessRule{
			{SourceMeshIP: netip.MustParseAddr("fd42::9"), TargetMeshIP: netip.MustParseAddr("fd42::5"), TCPPort: 22},
			{SourceMeshIP: netip.MustParseAddr("fd42::8"), TargetMeshIP: netip.MustParseAddr("fd42::5"), TCPPort: 22},
		},
	}
	first := mustNFT(t, p)
	p.ManagedServices[0], p.ManagedServices[1] = p.ManagedServices[1], p.ManagedServices[0]
	p.RemoteAccessRules[0], p.RemoteAccessRules[1] = p.RemoteAccessRules[1], p.RemoteAccessRules[0]
	second := mustNFT(t, p)
	if first != second {
		t.Fatalf("nft rendering depends on input order:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if !strings.Contains(first, `ip6 saddr fd42::8 ip6 daddr fd42::5 tcp dport 22 accept`) ||
		!strings.Contains(first, `iif "utun12" ip6 daddr fd42::5 tcp dport 5900 drop`) {
		t.Fatalf("IPv6 remote policy missing exact family rules:\n%s", first)
	}
}

func TestManagedServiceDenyCannotBeBypassedBySpoofedPublicSource(t *testing.T) {
	p := remotePolicy()
	nft := mustNFT(t, p)
	if strings.Contains(nft, "saddr 100.64.0.0/10 ip daddr 100.64.0.5 tcp dport 22 drop") {
		t.Fatalf("managed deny is limited to a spoofable source range:\n%s", nft)
	}
	if !strings.Contains(nft, `iif "ratelmesh0" ip daddr 100.64.0.5 tcp dport 22 drop`) {
		t.Fatalf("managed deny does not match every source on tunnel:\n%s", nft)
	}
	pf := mustPF(t, p)
	if !strings.Contains(pf, "from any to 100.64.0.5 port = 22") {
		t.Fatalf("PF managed deny does not match every source:\n%s", pf)
	}
}

func TestRemotePolicyRejectsMalformedOrOverbroadFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{"interface injection", func(p *Policy) { p.TunnelInterface = "wg0\"\naccept" }},
		{"loopback interface", func(p *Policy) { p.TunnelInterface = "lo" }},
		{"zero port", func(p *Policy) { p.ManagedServices[0].TCPPort = 0 }},
		{"public source", func(p *Policy) { p.RemoteAccessRules[0].SourceMeshIP = netip.MustParseAddr("8.8.8.8") }},
		{"public target", func(p *Policy) { p.ManagedServices[0].TargetMeshIP = netip.MustParseAddr("8.8.8.8") }},
		{"mixed family", func(p *Policy) {
			p.RemoteMeshPrefixes = append(p.RemoteMeshPrefixes, netip.MustParsePrefix("fd42::/48"))
			p.RemoteAccessRules[0].SourceMeshIP = netip.MustParseAddr("fd42::9")
		}},
		{"unmanaged grant", func(p *Policy) { p.RemoteAccessRules[0].TCPPort = 3389 }},
		{"overbroad v4 prefix", func(p *Policy) { p.RemoteMeshPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} }},
		{"overbroad v6 prefix", func(p *Policy) { p.RemoteMeshPrefixes = []netip.Prefix{netip.MustParsePrefix("::/0")} }},
		{"fields while disabled", func(p *Policy) { p.RemoteEnforcement = false }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := remotePolicy()
			tt.mutate(&p)
			if _, err := RenderNFT(p); err == nil {
				t.Fatal("RenderNFT accepted invalid policy")
			}
			if _, err := RenderPF(p); err == nil {
				t.Fatal("RenderPF accepted invalid policy")
			}
		})
	}

	invalidAddr := remotePolicy()
	invalidAddr.RemoteAccessRules[0].SourceMeshIP = netip.Addr{}
	if err := invalidAddr.Validate(); err == nil {
		t.Fatal("invalid address accepted")
	}
}
