package doctorplatform

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/ratelmesh/ratelmesh/internal/diagnose"
)

func TestParseWindowsStructuredRoutesIsLocaleIndependent(t *testing.T) {
	infos := []interfaceInfo{
		{Index: 4, Name: "以太网", MTU: 1500},
		{Index: 9, Name: "RatelMesh", MTU: 1280},
	}
	v4 := []byte(`[
		{"destinationPrefix":"0.0.0.0/0","interfaceIndex":4,"nextHop":"192.0.2.1","routeMetric":25},
		{"destinationPrefix":"0.0.0.0/1","interfaceIndex":9,"nextHop":"0.0.0.0","routeMetric":0}
	]`)
	routes, err := parseWindowsStructuredRoutes(v4, diagnose.FamilyV4, infos, "RatelMesh")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 ||
		routes[0].Destination != netip.MustParsePrefix("0.0.0.0/0") ||
		routes[0].Interface != "以太网" ||
		routes[0].Kind != diagnose.RouteKindPhysical ||
		routes[1].Destination != netip.MustParsePrefix("0.0.0.0/1") ||
		routes[1].Kind != diagnose.RouteKindTunnel {
		t.Fatalf("routes = %+v", routes)
	}

	v6 := []byte(`[{"destinationPrefix":"::/0","interfaceIndex":9,"nextHop":"::","routeMetric":0}]`)
	routes, err = parseWindowsStructuredRoutes(v6, diagnose.FamilyV6, infos, "RatelMesh")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Destination != netip.MustParsePrefix("::/0") ||
		routes[0].Kind != diagnose.RouteKindTunnel {
		t.Fatalf("IPv6 routes = %+v", routes)
	}
}

func TestParseWindowsStructuredRoutesRecognizesArbitraryBlackholePrefixes(t *testing.T) {
	infos := []interfaceInfo{
		{Index: 1, Name: "Loopback Pseudo-Interface 1", MTU: 1500},
		{Index: 9, Name: "RatelMesh", MTU: 1280},
	}
	tests := []struct {
		name   string
		family diagnose.AddressFamily
		input  []byte
		kinds  []diagnose.RouteKind
	}{
		{
			name:   "IPv4",
			family: diagnose.FamilyV4,
			input: []byte(`[
				{"destinationPrefix":"198.18.0.0/15","interfaceIndex":1,"nextHop":"0.0.0.0","routeMetric":0},
				{"destinationPrefix":"127.0.0.0/8","interfaceIndex":1,"nextHop":"0.0.0.0","routeMetric":331},
				{"destinationPrefix":"198.18.0.0/15","interfaceIndex":1,"nextHop":"127.0.0.1","routeMetric":0},
				{"destinationPrefix":"198.18.0.0/15","interfaceIndex":9,"nextHop":"0.0.0.0","routeMetric":0}
			]`),
			kinds: []diagnose.RouteKind{
				diagnose.RouteKindBlackhole,
				diagnose.RouteKindPhysical,
				diagnose.RouteKindPhysical,
				diagnose.RouteKindTunnel,
			},
		},
		{
			name:   "IPv6",
			family: diagnose.FamilyV6,
			input: []byte(`[
				{"destinationPrefix":"2001:db8:1234::/48","interfaceIndex":1,"nextHop":"::","routeMetric":0},
				{"destinationPrefix":"::1/128","interfaceIndex":1,"nextHop":"::","routeMetric":331},
				{"destinationPrefix":"2001:db8:1234::/48","interfaceIndex":1,"nextHop":"::1","routeMetric":0},
				{"destinationPrefix":"2001:db8:1234::/48","interfaceIndex":9,"nextHop":"::","routeMetric":0}
			]`),
			kinds: []diagnose.RouteKind{
				diagnose.RouteKindBlackhole,
				diagnose.RouteKindPhysical,
				diagnose.RouteKindPhysical,
				diagnose.RouteKindTunnel,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			routes, err := parseWindowsStructuredRoutes(test.input, test.family, infos, "RatelMesh")
			if err != nil {
				t.Fatal(err)
			}
			if len(routes) != len(test.kinds) {
				t.Fatalf("routes = %+v", routes)
			}
			for index, kind := range test.kinds {
				if routes[index].Kind != kind {
					t.Fatalf("route %d = %+v, want kind %q", index, routes[index], kind)
				}
			}
			if routes[0].ViaTunnel {
				t.Fatalf("blackhole route = %+v", routes[0])
			}
		})
	}
}

func TestWindowsPowerShellScriptsMakeCmdletErrorsTerminating(t *testing.T) {
	for name, script := range map[string]string{
		"IPv4 routes": windowsRoutesIPv4Script,
		"IPv6 routes": windowsRoutesIPv6Script,
		"DNS":         windowsDNSScript,
	} {
		t.Run(name, func(t *testing.T) {
			const stop = `$ErrorActionPreference='Stop';`
			if !strings.HasPrefix(script, stop) {
				t.Fatalf("PowerShell script can serialize partial results after a non-terminating cmdlet error: %q", script)
			}
			if strings.Index(script, stop) > strings.Index(script, "Get-") {
				t.Fatalf("error policy is applied after the first cmdlet: %q", script)
			}
		})
	}
}

func TestParseWindowsStructuredDNSHandlesChineseInterfaceAlias(t *testing.T) {
	input := []byte(`{
		"servers":[
			{"interfaceAlias":"以太网","serverAddresses":["192.0.2.53"]},
			{"interfaceAlias":"RatelMesh","serverAddresses":["100.64.0.1","fd00::53"]}
		],
		"searchDomains":["corp.example","lan.example."]
	}`)
	state, err := parseWindowsStructuredDNS(input, "RatelMesh")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.Servers, []netip.Addr{
		netip.MustParseAddr("192.0.2.53"),
		netip.MustParseAddr("100.64.0.1"),
		netip.MustParseAddr("fd00::53"),
	}) {
		t.Fatalf("servers = %v", state.Servers)
	}
	if !reflect.DeepEqual(state.SearchDomains, []string{"corp.example", "lan.example"}) {
		t.Fatalf("search domains = %v", state.SearchDomains)
	}
	if state.ViaTunnel {
		t.Fatal("mixed physical and tunnel resolvers classified as all-tunnel")
	}
}

func TestParseWindowsStructuredDNSAllResolversOnTunnel(t *testing.T) {
	input := []byte(`{
		"servers":[{"interfaceAlias":"RatelMesh","serverAddresses":["100.64.0.1","fd00::53"]}],
		"searchDomains":[]
	}`)
	state, err := parseWindowsStructuredDNS(input, "RatelMesh")
	if err != nil {
		t.Fatal(err)
	}
	if !state.ViaTunnel {
		t.Fatalf("state = %+v", state)
	}
}

func TestWindowsStructuredRoutesFailClosedWithoutLegacyFallback(t *testing.T) {
	validIPv4 := []byte(`[{"destinationPrefix":"0.0.0.0/0","interfaceIndex":4,"nextHop":"192.0.2.1","routeMetric":25}]`)
	ipv4CommandErr := errors.New("IPv4 PowerShell unavailable")
	ipv6CommandErr := errors.New("IPv6 PowerShell unavailable")
	tests := []struct {
		name      string
		runner    *fakeRunner
		wantErr   error
		wantSpecs []commandSpec
	}{
		{
			name:    "IPv4 command failure",
			runner:  &fakeRunner{errs: []error{ipv4CommandErr}},
			wantErr: ipv4CommandErr,
			wantSpecs: []commandSpec{
				windowsPowerShellSpec(windowsRoutesIPv4Script),
			},
		},
		{
			name:    "IPv4 malformed output",
			runner:  &fakeRunner{outputs: [][]byte{[]byte(`not JSON`)}},
			wantErr: errMalformed,
			wantSpecs: []commandSpec{
				windowsPowerShellSpec(windowsRoutesIPv4Script),
			},
		},
		{
			name: "IPv6 command failure",
			runner: &fakeRunner{
				outputs: [][]byte{validIPv4},
				errs:    []error{nil, ipv6CommandErr},
			},
			wantErr: ipv6CommandErr,
			wantSpecs: []commandSpec{
				windowsPowerShellSpec(windowsRoutesIPv4Script),
				windowsPowerShellSpec(windowsRoutesIPv6Script),
			},
		},
		{
			name: "IPv6 malformed output",
			runner: &fakeRunner{outputs: [][]byte{
				validIPv4,
				[]byte(`not JSON`),
			}},
			wantErr: errMalformed,
			wantSpecs: []commandSpec{
				windowsPowerShellSpec(windowsRoutesIPv4Script),
				windowsPowerShellSpec(windowsRoutesIPv6Script),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			routes, err := captureWindowsRoutes(context.Background(), test.runner, mustInterfaces(t), "wg0")
			if err == nil {
				t.Fatalf("routes = %+v, want observation failure", routes)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if !reflect.DeepEqual(test.runner.specs, test.wantSpecs) {
				t.Fatalf("route commands = %+v, want %+v", test.runner.specs, test.wantSpecs)
			}
		})
	}
}

func TestWindowsStructuredDNSFallsBackToBoundedLegacyCommand(t *testing.T) {
	dnsRunner := &fakeRunner{
		errs: []error{errors.New("PowerShell unavailable"), nil},
		outputs: [][]byte{[]byte(`Windows IP Configuration

Unknown adapter wg0:
   DNS Servers . . . . . . . . . . : 100.64.0.1
`)},
	}
	dns, err := captureWindowsDNS(context.Background(), dnsRunner, &fakeReader{}, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if len(dns.Servers) != 1 || !dns.ViaTunnel {
		t.Fatalf("fallback DNS = %+v", dns)
	}
	wantDNSSpecs := []commandSpec{
		windowsPowerShellSpec(windowsDNSScript),
		{path: `C:\Windows\System32\ipconfig.exe`, args: []string{"/all"}},
	}
	if !reflect.DeepEqual(dnsRunner.specs, wantDNSSpecs) {
		t.Fatalf("DNS commands = %+v, want %+v", dnsRunner.specs, wantDNSSpecs)
	}
}

func TestWindowsStructuredParsersRejectMalformedAndOversized(t *testing.T) {
	infos := mustInterfaces(t)
	routeCases := [][]byte{
		[]byte(`[{"destinationPrefix":"0.0.0.0/0","interfaceIndex":999,"nextHop":"192.0.2.1","routeMetric":25}]`),
		[]byte(`[{"destinationPrefix":"0.0.0.0/0","interfaceIndex":4,"nextHop":"192.0.2.1","routeMetric":25,"extra":"value"}]`),
		[]byte(`[{"destinationPrefix":"::/0","interfaceIndex":4,"nextHop":"192.0.2.1","routeMetric":25}]`),
		[]byte(`[{"destinationPrefix":"0.0.0.0/0","interfaceIndex":4,"nextHop":"192.0.2.1","routeMetric":-1}]`),
	}
	for _, input := range routeCases {
		if _, err := parseWindowsStructuredRoutes(input, diagnose.FamilyV4, infos, "wg0"); err == nil {
			t.Fatalf("malformed route JSON accepted: %s", input)
		}
	}
	dnsCases := [][]byte{
		[]byte(`{"servers":[{"interfaceAlias":"wg0","serverAddresses":["not-an-ip"]}],"searchDomains":[]}`),
		[]byte(`{"servers":[{"interfaceAlias":"wg0","serverAddresses":["1.1.1.1"],"extra":true}],"searchDomains":[]}`),
		[]byte(`{"servers":[],"searchDomains":["bad domain"]}`),
	}
	for _, input := range dnsCases {
		if _, err := parseWindowsStructuredDNS(input, "wg0"); err == nil {
			t.Fatalf("malformed DNS JSON accepted: %s", input)
		}
	}
}
