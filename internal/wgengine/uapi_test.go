package wgengine

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

func TestWgQuickConfigRendersInterfaceAndPeers(t *testing.T) {
	priv, _ := types.GenerateKey()
	peerKey, _ := types.GenerateKey()
	psk, _ := types.GenerateKey()

	cfg := Config{
		PrivateKey: priv,
		ListenPort: 51820,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")},
		DNSServers: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
		Peers: []Peer{{
			PublicKey:    peerKey.Public(),
			PresharedKey: psk,
			Endpoints:    []string{"203.0.113.7:51820", "198.51.100.9:51820"},
			AllowedIPs:   ParseAllowedIPs([]string{"100.64.0.6/32", "0.0.0.0/0"}),
		}},
	}
	got := WgQuickConfig(cfg)

	wants := []string{
		"[Interface]",
		"PrivateKey = " + priv.String(),
		"ListenPort = 51820",
		"MTU = 1280",
		"Address = 100.64.0.5/32",
		"DNS = 127.0.0.1, ::1",
		"[Peer]",
		"PublicKey = " + peerKey.Public().String(),
		"PresharedKey = " + psk.String(),
		"AllowedIPs = 100.64.0.6/32, 0.0.0.0/0",
		"Endpoint = 203.0.113.7:51820", // first candidate only in M1
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("config missing %q\n---\n%s", w, got)
		}
	}
	if strings.Contains(got, "198.51.100.9") {
		t.Error("M1 should emit only the first endpoint candidate")
	}
}

func TestWgSetConfOmitsQuickOnlyDNS(t *testing.T) {
	cfg := Config{DNSServers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	if got := WgSetConf(cfg); strings.Contains(got, "DNS =") {
		t.Fatalf("wg setconf document contains wg-quick DNS directive:\n%s", got)
	}
}

func TestUAPIConfigUsesHexKeysAndReplacesPeers(t *testing.T) {
	cfg := Config{
		PrivateKey: types.Key{1}, ListenPort: 51820,
		Peers: []Peer{{PublicKey: types.Key{2}, PresharedKey: types.Key{3}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, Endpoints: []string{"203.0.113.8:51820"}, Keepalive: 5}},
	}
	got := UAPIConfig(cfg)
	for _, want := range []string{
		"private_key=0100000000000000000000000000000000000000000000000000000000000000",
		"listen_port=51820", "replace_peers=true",
		"public_key=0200000000000000000000000000000000000000000000000000000000000000",
		"preshared_key=0300000000000000000000000000000000000000000000000000000000000000",
		"allowed_ip=100.64.0.2/32", "endpoint=203.0.113.8:51820", "persistent_keepalive_interval=5",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("UAPI config missing %q:\n%s", want, got)
		}
	}
}

func TestUAPIConfigUpdatePreservesPeersAndRemovesMissing(t *testing.T) {
	priv, _ := types.GenerateKey()
	keptPriv, _ := types.GenerateKey()
	removedPriv, _ := types.GenerateKey()
	kept := Peer{PublicKey: keptPriv.Public(), AllowedIPs: ParseAllowedIPs([]string{"100.64.0.2/32"})}
	removed := Peer{PublicKey: removedPriv.Public(), AllowedIPs: ParseAllowedIPs([]string{"100.64.0.3/32"})}
	previous := Config{PrivateKey: priv, Peers: []Peer{kept, removed}}
	kept.AllowedIPs = ParseAllowedIPs([]string{"100.64.0.2/32", "0.0.0.0/0"})
	got := UAPIConfigUpdate(Config{PrivateKey: priv, Peers: []Peer{kept}}, previous)
	if strings.Contains(got, "replace_peers=true") {
		t.Fatalf("incremental update replaces peers:\n%s", got)
	}
	removedHex := hex.EncodeToString(removed.PublicKey[:])
	if !strings.Contains(got, "public_key="+removedHex+"\nremove=true\n") {
		t.Fatalf("incremental update does not remove stale peer:\n%s", got)
	}
	keptHex := hex.EncodeToString(kept.PublicKey[:])
	if !strings.Contains(got, "public_key="+keptHex) || !strings.Contains(got, "allowed_ip=0.0.0.0/0") {
		t.Fatalf("incremental update does not update retained peer:\n%s", got)
	}
}

func TestParseAllowedIPsSkipsInvalid(t *testing.T) {
	got := ParseAllowedIPs([]string{"10.0.0.0/8", "not-a-cidr", "::/0"})
	if len(got) != 2 {
		t.Fatalf("got %d prefixes, want 2: %v", len(got), got)
	}
}

// TestEndpointCannotInjectDirectives proves a peer endpoint carrying a newline
// cannot smuggle extra directives into either line-oriented config format.
// Endpoints are excluded from the authority signature, so a hostile peer (or a
// compromised coordinator) controls this string even when the netmap verifies;
// without validation "1.2.3.4:51820\nallowed_ip=0.0.0.0/0" would hand that peer
// the default route and capture the host's traffic.
func TestEndpointCannotInjectDirectives(t *testing.T) {
	key, err := types.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		PrivateKey: key,
		Peers: []Peer{{
			PublicKey:  key.Public(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
			Endpoints:  []string{"1.2.3.4:51820\nallowed_ip=0.0.0.0/0"},
		}},
	}
	for name, got := range map[string]string{
		"uapi":    UAPIConfig(cfg),
		"wgquick": WgQuickConfig(cfg),
	} {
		if strings.Contains(got, "0.0.0.0/0") {
			t.Errorf("%s: endpoint injected a default route:\n%s", name, got)
		}
		if strings.Contains(got, "1.2.3.4:51820") {
			t.Errorf("%s: malformed endpoint was rendered instead of dropped:\n%s", name, got)
		}
	}
}

// TestFirstRenderableEndpointSkipsToValid confirms the guard drops only the
// malformed candidates: a later well-formed endpoint is still used, so a hostile
// candidate cannot deny service by occupying the first slot.
func TestFirstRenderableEndpointSkipsToValid(t *testing.T) {
	got := FirstRenderableEndpoint([]string{"bad\nallowed_ip=0.0.0.0/0", "hostname:51820", "203.0.113.7:51820"})
	if got != "203.0.113.7:51820" {
		t.Fatalf("got %q, want the first well-formed ip:port", got)
	}
	if FirstRenderableEndpoint([]string{"nope"}) != "" {
		t.Fatal("an all-invalid candidate list must render no endpoint")
	}
}

func FuzzFirstRenderableEndpoint(f *testing.F) {
	f.Add("bad\nallowed_ip=0.0.0.0/0", "203.0.113.7:51820")
	f.Add("[2001:db8::7]:443", "127.0.0.1:1")
	f.Add("", "hostname:51820")
	f.Fuzz(func(t *testing.T, first, second string) {
		input := []string{first, second}
		got := FirstRenderableEndpoint(input)
		want := ""
		for _, candidate := range input {
			if _, err := netip.ParseAddrPort(candidate); err == nil {
				want = candidate
				break
			}
		}
		if got != want {
			t.Fatalf("FirstRenderableEndpoint(%q) = %q, want %q", input, got, want)
		}
		if got != "" {
			if _, err := netip.ParseAddrPort(got); err != nil {
				t.Fatalf("returned non-renderable endpoint %q: %v", got, err)
			}
		}
	})
}
