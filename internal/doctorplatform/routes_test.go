package doctorplatform

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/ratelmesh/ratelmesh/internal/diagnose"
)

func TestParseLinuxRulesAcceptsOnlyStandardGlobalRules(t *testing.T) {
	if err := parseLinuxRules(standardLinuxRules()); err != nil {
		t.Fatal(err)
	}
	withExplicitAction := []byte(`[
{"priority":0,"src":"all","table":255,"action":"to_tbl","protocol":"kernel"},
{"priority":32766,"src":"all","table":254,"action":"lookup","protocol":"kernel"},
{"priority":32767,"src":"all","table":253,"action":"lookup","protocol":"kernel"}
]`)
	if err := parseLinuxRules(withExplicitAction); err != nil {
		t.Fatal(err)
	}
}

func TestParseLinuxRulesRejectsPolicySelectorsAndExtraLookups(t *testing.T) {
	hostile := [][]byte{
		[]byte(`[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","table":"main","fwmark":"0x1"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`),
		[]byte(`[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"10.0.0.0/8","table":"main"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`),
		[]byte(`[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","table":100},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`),
		[]byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`),
	}
	for _, input := range hostile {
		if err := parseLinuxRules(input); err == nil {
			t.Fatalf("non-standard policy rules accepted: %s", input)
		}
	}
}

func TestParseLinuxMainRoutesPreservesRealPrefixesAndMetadata(t *testing.T) {
	v4 := []byte(`[
{"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp","metric":100,"flags":[]},
{"dst":"0.0.0.0/1","dev":"wg0","protocol":"static","scope":"link","metrics":{"mtu":1280}},
{"dst":"192.0.2.44/32","dev":"wg0","src":"100.64.0.2"}
]`)
	routes, err := parseLinuxMainRoutes(v4, diagnose.FamilyV4, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if routes[0].Destination != netip.MustParsePrefix("0.0.0.0/0") ||
		routes[0].Kind != diagnose.RouteKindPhysical ||
		routes[1].Destination != netip.MustParsePrefix("0.0.0.0/1") ||
		routes[1].Kind != diagnose.RouteKindTunnel ||
		routes[2].Destination != netip.MustParsePrefix("192.0.2.44/32") {
		t.Fatalf("routes = %+v", routes)
	}
	v6 := []byte(`[{"dst":"default","dev":"eth0","pref":"low"},{"dst":"8000::/1","dev":"wg0","pref":"high"}]`)
	routes, err = parseLinuxMainRoutes(v6, diagnose.FamilyV6, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if routes[0].Destination != netip.MustParsePrefix("::/0") ||
		routes[1].Destination != netip.MustParsePrefix("8000::/1") {
		t.Fatalf("IPv6 routes = %+v", routes)
	}
}

func TestParseLinuxMainRoutesClassifiesDrops(t *testing.T) {
	input := []byte(`[
{"type":"blackhole","dst":"198.51.100.0/24","metric":10},
{"type":"unreachable","dst":"203.0.113.0/24"}
]`)
	routes, err := parseLinuxMainRoutes(input, diagnose.FamilyV4, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.Kind != diagnose.RouteKindBlackhole || route.Interface != "" {
			t.Fatalf("drop route = %+v", route)
		}
	}
}

func TestParseLinuxMainRoutesRejectsAmbiguousECMP(t *testing.T) {
	sameInterface := []byte(`[{"dst":"default","nexthops":[{"gateway":"192.0.2.1","dev":"wg0","weight":1},{"gateway":"192.0.2.2","dev":"wg0","weight":1}]}]`)
	routes, err := parseLinuxMainRoutes(sameInterface, diagnose.FamilyV4, "wg0")
	if err != nil || routes[0].Kind != diagnose.RouteKindTunnel {
		t.Fatalf("uniform ECMP = %+v, %v", routes, err)
	}
	ambiguous := []byte(`[{"dst":"default","nexthops":[{"gateway":"192.0.2.1","dev":"wg0"},{"gateway":"192.0.2.2","dev":"eth0"}]}]`)
	if _, err := parseLinuxMainRoutes(ambiguous, diagnose.FamilyV4, "wg0"); err == nil {
		t.Fatal("mixed-interface ECMP accepted")
	}
}

func TestParseDarwinRoutesClassifiesAndExpandsPrefixes(t *testing.T) {
	input := []byte(`Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.0.2.1          UGScg                 en0
0/1                link#18            UCS                 utun7
198.51.100/24      127.0.0.1          URB                   lo0
`)
	routes, err := parseDarwinRoutes(input, diagnose.FamilyV4, "utun7")
	if err != nil {
		t.Fatal(err)
	}
	if routes[0].Kind != diagnose.RouteKindPhysical ||
		routes[1].Destination != netip.MustParsePrefix("0.0.0.0/1") ||
		routes[1].Kind != diagnose.RouteKindTunnel ||
		routes[2].Kind != diagnose.RouteKindBlackhole {
		t.Fatalf("routes = %+v", routes)
	}
}

func TestParseWindowsRoutesIPv4AndIPv6(t *testing.T) {
	infos := mustInterfaces(t)
	v4 := []byte(`IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0        192.0.2.1       192.0.2.9     25
          0.0.0.0        128.0.0.0         On-link       100.64.0.2      5
===========================================================================
Persistent Routes:
          0.0.0.0          0.0.0.0       203.0.113.1      192.0.2.9      1
`)
	routes, err := parseWindowsRoutes(v4, diagnose.FamilyV4, infos, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0].Kind != diagnose.RouteKindPhysical || routes[1].Kind != diagnose.RouteKindTunnel {
		t.Fatalf("IPv4 routes = %+v", routes)
	}
	v6 := []byte(`IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  4    256 ::/0                     fe80::1
  9      5 ::/1                     On-link
===========================================================================
Persistent Routes:
  None
`)
	routes, err = parseWindowsRoutes(v6, diagnose.FamilyV6, infos, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[1].Kind != diagnose.RouteKindTunnel {
		t.Fatalf("IPv6 routes = %+v", routes)
	}
}

func TestWindowsRouteRejectsNonContiguousMask(t *testing.T) {
	input := []byte("IPv4 Route Table\nActive Routes:\n0.0.0.0 255.0.255.0 192.0.2.1 192.0.2.9 1\n")
	_, err := parseWindowsRoutes(input, diagnose.FamilyV4, mustInterfaces(t), "wg0")
	if !errors.Is(err, errMalformed) {
		t.Fatalf("error = %v", err)
	}
}

func TestWindowsRouteUnrecognizedOrLocalizedOutputFailsClosed(t *testing.T) {
	for _, input := range [][]byte{
		[]byte(""),
		[]byte("0.0.0.0 0.0.0.0 192.0.2.1 192.0.2.9 1\n"),
		[]byte("IPv4-Routentabelle\nAktive Routen:\n0.0.0.0 0.0.0.0 192.0.2.1 192.0.2.9 1\n"),
	} {
		if _, err := parseWindowsRoutes(input, diagnose.FamilyV4, mustInterfaces(t), "wg0"); err == nil {
			t.Fatalf("unrecognized route output accepted: %q", input)
		}
	}
}
