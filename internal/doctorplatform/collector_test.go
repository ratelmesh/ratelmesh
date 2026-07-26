package doctorplatform

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/diagnose"
)

type fakeRunner struct {
	outputs [][]byte
	err     error
	errs    []error
	specs   []commandSpec
	block   bool
}

func (r *fakeRunner) run(ctx context.Context, spec commandSpec) ([]byte, error) {
	r.specs = append(r.specs, spec)
	if r.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(r.errs) > 0 {
		err := r.errs[0]
		r.errs = r.errs[1:]
		if err != nil {
			return nil, err
		}
	}
	if len(r.outputs) == 0 {
		return nil, errors.New("missing test output")
	}
	out := r.outputs[0]
	r.outputs = r.outputs[1:]
	return out, nil
}

func standardLinuxRules() []byte {
	return []byte(`[
{"priority":0,"src":"all","table":"local"},
{"priority":32766,"src":"all","table":"main"},
{"priority":32767,"src":"all","table":"default"}
]`)
}

type fakeReader struct {
	data []byte
	err  error
	path string
}

func (r *fakeReader) read(ctx context.Context, path string, _ int64) ([]byte, error) {
	r.path = path
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.data, r.err
}

func testInterfaces() ([]interfaceInfo, error) {
	return []interfaceInfo{
		{Index: 4, Name: "en0", MTU: 1500, Addrs: []string{"192.0.2.9/24", "2001:db8::9%en0/64"}},
		{Index: 9, Name: "wg0", MTU: 1280, Addrs: []string{"100.64.0.2/32", "fd00::2/128"}},
	}, nil
}

func TestCapturePreservesDaemonStateAndEnrichesOSFields(t *testing.T) {
	base := diagnose.Snapshot{
		Coordinator:  diagnose.Endpoint{Label: "coordinator", Host: "control.example"},
		Relays:       []diagnose.Endpoint{{Label: "relay", Host: "relay.example"}},
		Exit:         &diagnose.ExitState{PeerPublicKey: "peer-key"},
		WireGuard:    diagnose.WireGuardState{Interface: "wg0", Up: true, Peers: []diagnose.PeerStatus{{PublicKey: "p"}}},
		MediaTargets: []diagnose.Endpoint{{Label: "media", Host: "media.example"}},
		ExitActive:   true,
		Secrets:      []string{"secret"},
	}
	runner := &fakeRunner{outputs: [][]byte{
		standardLinuxRules(),
		[]byte(`[{"dst":"default","dev":"en0"},{"dst":"0.0.0.0/1","dev":"wg0"}]`),
		standardLinuxRules(),
		[]byte(`[{"dst":"default","dev":"en0","pref":"medium"},{"dst":"::/1","dev":"wg0","pref":"high"}]`),
	}}
	reader := &fakeReader{data: []byte("nameserver 100.64.0.1\nnameserver 2001:4860:4860::8888\nsearch corp.example\n")}
	collector := newCollector(runner, reader, testInterfaces, linuxPlatformOps())

	got, observationErrors := collector.Capture(context.Background(), Inputs{Snapshot: base})
	if len(observationErrors) != 0 {
		t.Fatalf("Capture errors = %+v", observationErrors)
	}
	if got.Coordinator != base.Coordinator ||
		!reflect.DeepEqual(got.Relays, base.Relays) ||
		!reflect.DeepEqual(got.Exit, base.Exit) ||
		!reflect.DeepEqual(got.WireGuard.Peers, base.WireGuard.Peers) ||
		!reflect.DeepEqual(got.MediaTargets, base.MediaTargets) ||
		!reflect.DeepEqual(got.Secrets, base.Secrets) ||
		got.ExitActive != base.ExitActive {
		t.Fatalf("daemon-owned state changed: got %+v", got)
	}
	if got.WireGuard.LinkMTU != 1280 {
		t.Fatalf("LinkMTU = %d, want 1280", got.WireGuard.LinkMTU)
	}
	if len(got.Addresses) != 4 || len(got.Routes) != 4 || len(got.DNS.Servers) != 2 {
		t.Fatalf("OS enrichment incomplete: addresses=%d routes=%d DNS=%d", len(got.Addresses), len(got.Routes), len(got.DNS.Servers))
	}
	if runner.specs[0].path != "/usr/sbin/ip" ||
		!reflect.DeepEqual(runner.specs[0].args, []string{"-j", "-4", "rule", "show"}) ||
		runner.specs[1].path != "/usr/sbin/ip" {
		t.Fatalf("unexpected production commands: %+v", runner.specs)
	}
	if reader.path != "/etc/resolv.conf" {
		t.Fatalf("resolver path = %q", reader.path)
	}
}

func TestCaptureReturnsPartialSnapshotAndTypedRedactedError(t *testing.T) {
	secretOutput := "failed near private.search.example and 192.0.2.44"
	runner := &fakeRunner{err: errors.New(secretOutput)}
	collector := newCollector(runner, &fakeReader{data: []byte("nameserver 1.1.1.1\n")}, testInterfaces, linuxPlatformOps())
	base := diagnose.Snapshot{Coordinator: diagnose.Endpoint{Host: "keep.example"}, WireGuard: diagnose.WireGuardState{Interface: "wg0"}}

	got, observationErrors := collector.Capture(context.Background(), Inputs{Snapshot: base})
	if got.Coordinator != base.Coordinator || len(got.Addresses) == 0 || got.WireGuard.LinkMTU != 1280 {
		t.Fatalf("partial snapshot lost successful fields: %+v", got)
	}
	if len(observationErrors) != 1 || observationErrors[0].Observation != ObservationRoutes || observationErrors[0].Kind != ErrorUnavailable {
		t.Fatalf("errors = %+v", observationErrors)
	}
	if strings.Contains(observationErrors[0].Error(), "private.search") ||
		strings.Contains(observationErrors[0].Error(), "192.0.2.44") {
		t.Fatalf("ObservationError leaked command output: %q", observationErrors[0])
	}
}

func TestCaptureWindowsRoutesFailsClosedAndContinuesToDNS(t *testing.T) {
	runner := &fakeRunner{
		errs: []error{errors.New("structured Windows routes unavailable"), nil},
		outputs: [][]byte{
			[]byte(`{"servers":[{"interfaceAlias":"wg0","serverAddresses":["100.64.0.1"]}],"searchDomains":[]}`),
		},
	}
	collector := newCollector(runner, &fakeReader{}, testInterfaces, windowsPlatformOps())

	got, observationErrors := collector.Capture(context.Background(), Inputs{
		Snapshot: diagnose.Snapshot{
			Routes:    []diagnose.Route{{Destination: netip.MustParsePrefix("0.0.0.0/0")}},
			WireGuard: diagnose.WireGuardState{Interface: "wg0"},
		},
	})
	if len(got.Routes) != 0 {
		t.Fatalf("failed route observation retained stale or partial routes: %+v", got.Routes)
	}
	if len(got.DNS.Servers) != 1 || got.DNS.Servers[0] != netip.MustParseAddr("100.64.0.1") || !got.DNS.ViaTunnel {
		t.Fatalf("independent DNS observation did not continue: %+v", got.DNS)
	}
	if len(observationErrors) != 1 ||
		observationErrors[0].Observation != ObservationRoutes ||
		observationErrors[0].Kind != ErrorUnavailable {
		t.Fatalf("observation errors = %+v", observationErrors)
	}
	wantSpecs := []commandSpec{
		windowsPowerShellSpec(windowsRoutesIPv4Script),
		windowsPowerShellSpec(windowsDNSScript),
	}
	if !reflect.DeepEqual(runner.specs, wantSpecs) {
		t.Fatalf("commands = %+v, want %+v", runner.specs, wantSpecs)
	}
}

func TestCaptureClassifiesOversizedOutput(t *testing.T) {
	runner := &fakeRunner{outputs: [][]byte{make([]byte, maxCommandSize+1), nil}}
	collector := newCollector(runner, &fakeReader{data: []byte("nameserver 1.1.1.1\n")}, testInterfaces, linuxPlatformOps())
	_, observationErrors := collector.Capture(context.Background(), Inputs{})
	if len(observationErrors) != 1 ||
		observationErrors[0].Observation != ObservationRoutes ||
		observationErrors[0].Kind != ErrorOversized {
		t.Fatalf("errors = %+v", observationErrors)
	}
}

func TestCaptureContinuesAfterInterfaceObservationFails(t *testing.T) {
	runner := &fakeRunner{outputs: [][]byte{
		standardLinuxRules(),
		[]byte(`[{"dst":"default","dev":"eth0"}]`),
		standardLinuxRules(),
		[]byte(`[{"dst":"default","dev":"eth0"}]`),
	}}
	interfacesFail := func() ([]interfaceInfo, error) {
		return nil, errors.New("interface API unavailable")
	}
	collector := newCollector(
		runner,
		&fakeReader{data: []byte("nameserver 1.1.1.1\n")},
		interfacesFail,
		linuxPlatformOps(),
	)
	got, observationErrors := collector.Capture(context.Background(), Inputs{
		Snapshot: diagnose.Snapshot{WireGuard: diagnose.WireGuardState{Interface: "wg0"}},
	})
	if len(got.Routes) != 2 || len(got.DNS.Servers) != 1 {
		t.Fatalf("independent observations did not continue: %+v", got)
	}
	if len(observationErrors) != 2 ||
		observationErrors[0].Observation != ObservationInterfaces ||
		observationErrors[1].Observation != ObservationTunnelMTU {
		t.Fatalf("errors = %+v", observationErrors)
	}
}

func TestCaptureCancellationAndTimeout(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		collector := newCollector(&fakeRunner{block: true}, &fakeReader{}, testInterfaces, linuxPlatformOps())
		_, errs := collector.Capture(ctx, Inputs{})
		if len(errs) == 0 || errs[0].Kind != ErrorCanceled {
			t.Fatalf("errors = %+v", errs)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		collector := newCollector(&fakeRunner{block: true}, &fakeReader{}, testInterfaces, linuxPlatformOps())
		_, errs := collector.Capture(ctx, Inputs{})
		if len(errs) == 0 || errs[0].Kind != ErrorTimeout {
			t.Fatalf("errors = %+v", errs)
		}
	})
}

func TestCaptureNilContextFailsClosedWithoutExecuting(t *testing.T) {
	executed := false
	interfaceSource := func() ([]interfaceInfo, error) {
		executed = true
		return nil, nil
	}
	collector := newCollector(&fakeRunner{}, &fakeReader{}, interfaceSource, linuxPlatformOps())
	base := diagnose.Snapshot{
		Coordinator: diagnose.Endpoint{Host: "keep.example"},
		WireGuard:   diagnose.WireGuardState{Interface: "wg0", LinkMTU: 1280},
	}
	//lint:ignore SA1012 This test deliberately verifies the fail-closed nil-context boundary.
	got, errs := collector.Capture(nil, Inputs{Snapshot: base})
	if executed {
		t.Fatal("nil context executed an observation")
	}
	if got.Coordinator != base.Coordinator || got.WireGuard.Interface != "wg0" ||
		got.WireGuard.LinkMTU != 0 || len(got.Addresses) != 0 ||
		len(got.Routes) != 0 || len(got.DNS.Servers) != 0 {
		t.Fatalf("snapshot did not clear OS-owned state: %+v", got)
	}
	if len(errs) != 4 {
		t.Fatalf("errors = %+v", errs)
	}
	for _, err := range errs {
		if err.Kind != ErrorInvalid {
			t.Fatalf("error = %+v, want invalid input", err)
		}
	}
}

func TestCaptureFailureClearsStaleOSOwnedState(t *testing.T) {
	base := diagnose.Snapshot{
		Coordinator: diagnose.Endpoint{Host: "keep.example"},
		WireGuard: diagnose.WireGuardState{
			Interface: "wg0",
			Up:        true,
			LinkMTU:   1420,
		},
		Addresses: []diagnose.InterfaceAddr{{Interface: "stale0", Addr: netip.MustParseAddr("192.0.2.1")}},
		Routes: []diagnose.Route{{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Interface:   "wg0",
			ViaTunnel:   true,
			Kind:        diagnose.RouteKindTunnel,
		}},
		DNS: diagnose.DNSState{Servers: []netip.Addr{netip.MustParseAddr("100.64.0.1")}, ViaTunnel: true},
	}
	allFail := func() ([]interfaceInfo, error) { return nil, errors.New("unavailable") }
	collector := newCollector(
		&fakeRunner{err: errors.New("route unavailable")},
		&fakeReader{err: errors.New("DNS unavailable")},
		allFail,
		linuxPlatformOps(),
	)
	got, errs := collector.Capture(context.Background(), Inputs{Snapshot: base})
	if len(errs) != 4 {
		t.Fatalf("errors = %+v", errs)
	}
	if got.Coordinator != base.Coordinator || got.WireGuard.Interface != "wg0" || !got.WireGuard.Up {
		t.Fatalf("daemon-owned state changed: %+v", got)
	}
	if got.WireGuard.LinkMTU != 0 || len(got.Addresses) != 0 ||
		len(got.Routes) != 0 || len(got.DNS.Servers) != 0 ||
		len(got.DNS.SearchDomains) != 0 || got.DNS.ViaTunnel {
		t.Fatalf("stale OS state survived failed capture: %+v", got)
	}
}

func TestLinuxCapturePreservesPhysicalDefaultAlongsideWGHostRoute(t *testing.T) {
	staleTunnelRoutes := []diagnose.Route{
		{Destination: netip.MustParsePrefix("0.0.0.0/1"), Interface: "wg0", ViaTunnel: true, Kind: diagnose.RouteKindTunnel},
		{Destination: netip.MustParsePrefix("128.0.0.0/1"), Interface: "wg0", ViaTunnel: true, Kind: diagnose.RouteKindTunnel},
		{Destination: netip.MustParsePrefix("::/1"), Interface: "wg0", ViaTunnel: true, Kind: diagnose.RouteKindTunnel},
		{Destination: netip.MustParsePrefix("8000::/1"), Interface: "wg0", ViaTunnel: true, Kind: diagnose.RouteKindTunnel},
	}
	runner := &fakeRunner{outputs: [][]byte{
		standardLinuxRules(),
		[]byte(`[{"dst":"default","dev":"eth0","table":"main"},{"dst":"192.0.2.44/32","dev":"wg0","table":"main"}]`),
		standardLinuxRules(),
		[]byte(`[{"dst":"default","dev":"eth0","table":"main","pref":"medium"}]`),
	}}
	collector := newCollector(
		runner,
		&fakeReader{data: []byte("nameserver 1.1.1.1\n")},
		testInterfaces,
		linuxPlatformOps(),
	)
	got, errs := collector.Capture(context.Background(), Inputs{Snapshot: diagnose.Snapshot{
		WireGuard: diagnose.WireGuardState{Interface: "wg0"},
		Routes:    staleTunnelRoutes,
	}})
	if len(errs) != 0 {
		t.Fatalf("errors = %+v", errs)
	}
	if len(got.Routes) != 3 {
		t.Fatalf("routes = %+v", got.Routes)
	}
	if got.Routes[0].Kind != diagnose.RouteKindPhysical ||
		got.Routes[0].Destination != netip.MustParsePrefix("0.0.0.0/0") ||
		got.Routes[1].Kind != diagnose.RouteKindTunnel ||
		got.Routes[1].Destination != netip.MustParsePrefix("192.0.2.44/32") ||
		got.Routes[2].Kind != diagnose.RouteKindPhysical {
		t.Fatalf("real main prefixes were not preserved: %+v", got.Routes)
	}
}

func TestLinuxCaptureKeepsIPv4WhenIPv6ObservationFails(t *testing.T) {
	runner := &fakeRunner{
		errs: []error{nil, nil, errors.New("IPv6 unavailable")},
		outputs: [][]byte{
			standardLinuxRules(),
			[]byte(`[{"dst":"default","dev":"eth0"},{"dst":"0.0.0.0/1","dev":"wg0"}]`),
		},
	}
	collector := newCollector(
		runner,
		&fakeReader{data: []byte("nameserver 1.1.1.1\n")},
		testInterfaces,
		linuxPlatformOps(),
	)
	got, errs := collector.Capture(context.Background(), Inputs{
		Snapshot: diagnose.Snapshot{WireGuard: diagnose.WireGuardState{Interface: "wg0"}},
	})
	if len(errs) != 1 || errs[0].Observation != ObservationRoutes || errs[0].Kind != ErrorUnavailable {
		t.Fatalf("errors = %+v", errs)
	}
	if len(got.Routes) != 2 ||
		got.Routes[0].Destination != netip.MustParsePrefix("0.0.0.0/0") ||
		got.Routes[1].Destination != netip.MustParsePrefix("0.0.0.0/1") {
		t.Fatalf("successful IPv4 routes were discarded: %+v", got.Routes)
	}
}

func TestInterfaceAddressesIPv4AndIPv6RejectMalformed(t *testing.T) {
	got, err := interfaceAddresses(mustInterfaces(t))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Family != diagnose.FamilyV4 || got[0].Addr != netip.MustParseAddr("192.0.2.9") ||
		got[1].Family != diagnose.FamilyV6 || got[1].Addr != netip.MustParseAddr("2001:db8::9") {
		t.Fatalf("addresses = %+v", got)
	}
	if _, err := interfaceAddresses([]interfaceInfo{{Name: "en0", Addrs: []string{"not-an-address"}}}); err == nil {
		t.Fatal("malformed address accepted")
	}
}

func mustInterfaces(t *testing.T) []interfaceInfo {
	t.Helper()
	infos, err := testInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	return infos
}

func TestLimitedBufferRejectsOversizedOutput(t *testing.T) {
	var b limitedBuffer
	payload := make([]byte, maxCommandSize+1)
	n, err := b.Write(payload)
	if err != nil || n != len(payload) || !b.overflow {
		t.Fatalf("Write = (%d, %v), overflow=%v", n, err, b.overflow)
	}
}

func TestPlatformCommandsAreFixedAbsoluteAllowlist(t *testing.T) {
	cases := []struct {
		name    string
		ops     platformOps
		outputs [][]byte
		want    []commandSpec
	}{
		{
			name: "linux",
			ops:  linuxPlatformOps(),
			outputs: [][]byte{
				standardLinuxRules(),
				[]byte(`[]`),
				standardLinuxRules(),
				[]byte(`[]`),
			},
			want: []commandSpec{
				{path: "/usr/sbin/ip", args: []string{"-j", "-4", "rule", "show"}},
				{path: "/usr/sbin/ip", args: []string{"-j", "-4", "route", "show", "table", "main"}},
				{path: "/usr/sbin/ip", args: []string{"-j", "-6", "rule", "show"}},
				{path: "/usr/sbin/ip", args: []string{"-j", "-6", "route", "show", "table", "main"}},
			},
		},
		{
			name: "darwin",
			ops:  darwinPlatformOps(),
			outputs: [][]byte{
				nil,
				nil,
				nil,
			},
			want: []commandSpec{
				{path: "/usr/sbin/netstat", args: []string{"-rn", "-f", "inet"}},
				{path: "/usr/sbin/netstat", args: []string{"-rn", "-f", "inet6"}},
				{path: "/usr/sbin/scutil", args: []string{"--dns"}},
			},
		},
		{
			name: "windows",
			ops:  windowsPlatformOps(),
			outputs: [][]byte{
				[]byte(`[]`),
				[]byte(`[]`),
				[]byte(`{"servers":[],"searchDomains":[]}`),
			},
			want: []commandSpec{
				windowsPowerShellSpec(windowsRoutesIPv4Script),
				windowsPowerShellSpec(windowsRoutesIPv6Script),
				windowsPowerShellSpec(windowsDNSScript),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{outputs: tc.outputs}
			_, _ = tc.ops.routes(context.Background(), runner, mustInterfaces(t), "wg0")
			_, _ = tc.ops.dns(context.Background(), runner, &fakeReader{}, "wg0")
			if !reflect.DeepEqual(runner.specs, tc.want) {
				t.Fatalf("commands = %+v, want %+v", runner.specs, tc.want)
			}
		})
	}
}
