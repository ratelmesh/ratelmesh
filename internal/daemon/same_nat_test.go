package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"testing"

	"github.com/shan25519/ratelmesh/internal/magicsock"
	"github.com/shan25519/ratelmesh/internal/types"
	"github.com/shan25519/ratelmesh/internal/wgengine"
)

type sequenceDiscoverer struct {
	*wgengine.StubEngine
	endpoint netip.AddrPort
	fail     bool
}

func (e *sequenceDiscoverer) DiscoverPublicEndpoint(context.Context, string) (netip.AddrPort, error) {
	if e.fail {
		return netip.AddrPort{}, errors.New("STUN unavailable")
	}
	return e.endpoint, nil
}

func TestPreferSameNATPrivateEndpoints(t *testing.T) {
	self := []string{"198.51.100.72:51820", "192.168.68.20:51820", "100.64.0.3:51820"}
	peer := []string{"198.51.100.72:1198", "192.168.68.80:51820", "100.64.0.1:51820"}
	want := []string{"192.168.68.80:51820", "198.51.100.72:1198", "100.64.0.1:51820"}
	if got := preferSameNATPrivateEndpoints(self, peer); !reflect.DeepEqual(got, want) {
		t.Fatalf("preferred endpoints = %v, want %v", got, want)
	}
}

func TestPreferSameNATPrivateEndpointsKeepsPublicFirstAcrossIsolatedSubnets(t *testing.T) {
	self := []string{"198.51.100.72:51820", "192.168.1.200:51820"}
	peer := []string{"198.51.100.72:1198", "192.168.68.80:51820"}
	if got := preferSameNATPrivateEndpoints(self, peer); !reflect.DeepEqual(got, peer) {
		t.Fatalf("preferred endpoints = %v, want unchanged %v", got, peer)
	}
}

func TestPreferSameNATPrivateEndpointsKeepsPublicFirstForDifferentNATs(t *testing.T) {
	self := []string{"198.51.100.72:51820", "192.168.1.200:51820"}
	peer := []string{"203.0.113.9:1198", "192.168.68.80:51820"}
	if got := preferSameNATPrivateEndpoints(self, peer); !reflect.DeepEqual(got, peer) {
		t.Fatalf("preferred endpoints = %v, want unchanged %v", got, peer)
	}
}

func TestPreferSameNATPrivateEndpointsDoesNotTreatMeshAddressAsPublic(t *testing.T) {
	self := []string{"100.64.0.3:51820"}
	peer := []string{"100.64.0.3:1198", "192.168.68.80:51820"}
	if got := preferSameNATPrivateEndpoints(self, peer); !reflect.DeepEqual(got, peer) {
		t.Fatalf("preferred endpoints = %v, want unchanged %v", got, peer)
	}
}

func TestPreferConfirmedEndpointPromotesWorkingCandidate(t *testing.T) {
	var key types.Key
	key[0] = 91
	pp := magicsock.NewPeerPath(key)
	public := netip.MustParseAddrPort("198.51.100.20:41123")
	private := netip.MustParseAddrPort("192.168.68.80:51820")
	pp.SetCandidates([]netip.AddrPort{public, private})
	if !pp.ConfirmDirect(private) {
		t.Fatal("private candidate was not accepted")
	}
	d := &Daemon{paths: map[types.Key]*magicsock.PeerPath{key: pp}}
	got := d.preferConfirmedEndpoint(key, []string{public.String(), private.String()})
	want := []string{private.String(), public.String()}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("preferred endpoints = %v, want %v", got, want)
	}
}

func TestProbeCandidateEndpointsKeepsUsablePhysicalPaths(t *testing.T) {
	got := probeCandidateEndpoints([]string{
		"100.64.0.1:51820",    // recursive mesh route
		"192.168.68.80:51820", // LAN candidate
		"198.51.100.20:41123", // reflexive candidate
		"[fe80::1]:51820",     // scoped link-local is not portable
		"198.51.100.20:41123", // duplicate
		"not-an-endpoint",
	})
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.168.68.80:51820"),
		netip.MustParseAddrPort("198.51.100.20:41123"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("probe candidates = %v, want %v", got, want)
	}
}

func TestLocalEndpointsRetainsLastWireGuardReflexiveMapping(t *testing.T) {
	engine := &sequenceDiscoverer{
		StubEngine: wgengine.NewStub(nil),
		endpoint:   netip.MustParseAddrPort("203.0.113.10:41123"),
	}
	d := &Daemon{
		cfg:    Config{ListenPort: 51820, STUNAddr: "stun.example:3478"},
		engine: engine,
		log:    slog.Default(),
	}
	if got := d.localEndpoints(); len(got) == 0 || got[0] != engine.endpoint.String() {
		t.Fatalf("first endpoints = %v, want reflexive first", got)
	}
	engine.fail = true
	if got := d.localEndpoints(); len(got) == 0 || got[0] != engine.endpoint.String() {
		t.Fatalf("endpoints after STUN failure = %v, want cached reflexive first", got)
	}
}

func TestLocalEndpointsPrefersNativePublicCandidate(t *testing.T) {
	d := &Daemon{
		cfg: Config{
			ListenPort:     51820,
			ExtraEndpoints: []string{"203.0.113.10:41123"},
		},
		engine: wgengine.NewStub(nil),
		log:    slog.Default(),
	}
	got := d.localEndpoints()
	if len(got) == 0 || got[0] != "203.0.113.10:41123" {
		t.Fatalf("endpoints = %v, want native public candidate first", got)
	}
}

func TestExitPhysicalEndpointsPinsSTUNServer(t *testing.T) {
	d := &Daemon{cfg: Config{STUNAddr: "203.0.113.10:3478"}}
	got := d.exitPhysicalEndpoints(nil)
	want := netip.MustParseAddr("203.0.113.10")
	if !containsAddr(got, want) {
		t.Fatalf("physical endpoints = %v, want STUN address %v", got, want)
	}
}
