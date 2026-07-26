//go:build wgreal

package wgengine

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestApplyRoutesScrubsCrashLeftoversOnlyOnce(t *testing.T) {
	var scrubbed []string
	e := &RealEngine{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface: "utun-test",
		routeAddFunc: func(netip.Prefix, string) error {
			return nil
		},
		routeDelFunc: func(netip.Prefix) error {
			return nil
		},
		routeScrubFunc: func(iface string) {
			scrubbed = append(scrubbed, iface)
		},
	}
	cfg := Config{Peers: []Peer{{AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("100.64.0.3/32"),
	}}}}
	if err := e.applyRoutes(cfg); err != nil {
		t.Fatal(err)
	}
	if err := e.applyRoutes(cfg); err != nil {
		t.Fatal(err)
	}
	if len(scrubbed) != 1 || scrubbed[0] != "utun-test" {
		t.Fatalf("stale-route scrubs = %v, want one for utun-test", scrubbed)
	}
}

func TestApplyRoutesSkipsUnchangedRoutePlan(t *testing.T) {
	var added, deleted []netip.Prefix
	e := &RealEngine{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface: "utun-test",
		routeAddFunc: func(prefix netip.Prefix, _ string) error {
			added = append(added, prefix)
			return nil
		},
		routeDelFunc: func(prefix netip.Prefix) error {
			deleted = append(deleted, prefix)
			return nil
		},
		routeScrubFunc: func(string) {},
	}
	cfg := Config{Peers: []Peer{{
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}}}
	if err := e.applyRoutes(cfg); err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	firstAdded := len(added)
	if err := e.applyRoutes(cfg); err != nil {
		t.Fatal(err)
	}
	if len(added) != firstAdded {
		t.Fatalf("unchanged plan added routes again: got %v", added)
	}
	if len(deleted) != 0 {
		t.Fatalf("unchanged plan deleted live routes: %v", deleted)
	}
}

func TestApplyRoutesKeepsRoutesWhenOnlyNonExitEndpointChanges(t *testing.T) {
	var added, deleted []netip.Prefix
	e := &RealEngine{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface: "utun-test",
		routeAddFunc: func(prefix netip.Prefix, _ string) error {
			added = append(added, prefix)
			return nil
		},
		routeDelFunc: func(prefix netip.Prefix) error {
			deleted = append(deleted, prefix)
			return nil
		},
		routeScrubFunc: func(string) {},
	}
	prev := Config{Peers: []Peer{{
		Endpoints:  []string{"203.0.113.7:51820"},
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
	}}}
	if err := e.applyRoutes(prev); err != nil {
		t.Fatal(err)
	}
	e.cfg = prev
	firstAdded := len(added)
	next := prev
	next.Peers = append([]Peer(nil), prev.Peers...)
	next.Peers[0].Endpoints = []string{"198.51.100.9:51820"}
	if err := e.applyRoutes(next); err != nil {
		t.Fatal(err)
	}
	if len(added) != firstAdded {
		t.Fatalf("endpoint-only refresh added tunnel routes again: %v", added)
	}
	if len(deleted) != 0 {
		t.Fatalf("endpoint-only refresh deleted live tunnel routes: %v", deleted)
	}
}

func TestApplyRoutesRefreshesExitPinThroughPhysicalDefault(t *testing.T) {
	oldEndpoint := netip.MustParseAddr("203.0.113.7")
	newEndpoint := netip.MustParseAddr("198.51.100.9")
	physicalGateway := netip.MustParseAddr("192.168.31.1")
	var pinned []struct {
		prefix  netip.Prefix
		gateway netip.Addr
		device  string
	}
	var deleted []netip.Addr
	e := &RealEngine{
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface:         "utun-test",
		routesApplied: true,
		pinned:        []netip.Addr{oldEndpoint},
		physicalDefaultFunc: func(target netip.Addr) (netip.Addr, string) {
			if target != newEndpoint {
				t.Fatalf("physical path queried for %s, want %s", target, newEndpoint)
			}
			return physicalGateway, "en0"
		},
		routeViaFunc: func(prefix netip.Prefix, gateway netip.Addr, device string) error {
			pinned = append(pinned, struct {
				prefix  netip.Prefix
				gateway netip.Addr
				device  string
			}{prefix, gateway, device})
			return nil
		},
		hostRouteDelFunc: func(addr netip.Addr) error {
			deleted = append(deleted, addr)
			return nil
		},
	}
	e.cfg = Config{PhysicalEndpoints: []netip.Addr{oldEndpoint}, Peers: []Peer{{
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}}}
	next := e.cfg
	next.PhysicalEndpoints = []netip.Addr{newEndpoint}

	if err := e.applyRoutes(next); err != nil {
		t.Fatal(err)
	}
	if len(pinned) != 1 ||
		pinned[0].prefix != netip.PrefixFrom(newEndpoint, 32) ||
		pinned[0].gateway != physicalGateway ||
		pinned[0].device != "en0" {
		t.Fatalf("refreshed pin = %+v, want %s via %s on en0", pinned, newEndpoint, physicalGateway)
	}
	if len(deleted) != 1 || deleted[0] != oldEndpoint {
		t.Fatalf("obsolete pins deleted = %v, want [%s]", deleted, oldEndpoint)
	}
}

func TestInstallManagedRoutePersistsIntentBeforeMutation(t *testing.T) {
	e := &RealEngine{
		log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		routeLedgerPath: filepath.Join(t.TempDir(), routeLedgerFile),
	}
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	owner := unixManagedRoute{prefix: prefix, device: "utun-test", kind: unixRouteTunnel}
	if err := e.installManagedRoute(owner, func() error {
		data, err := os.ReadFile(e.routeLedgerPath)
		if err != nil {
			t.Fatalf("route mutation ran before ledger persistence: %v", err)
		}
		if !bytes.Contains(data, []byte(prefix.String())) {
			t.Fatalf("write-ahead ledger %q omitted %s", data, prefix)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRoutesUsesFamilySpecificPhysicalDefaults(t *testing.T) {
	var queried []bool
	var installed []unixManagedRoute
	e := &RealEngine{
		log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface:          "utun-test",
		routeAddFunc:   func(netip.Prefix, string) error { return nil },
		routeDelFunc:   func(netip.Prefix) error { return nil },
		routeScrubFunc: func(string) {},
		routeViaFunc: func(prefix netip.Prefix, gateway netip.Addr, device string) error {
			installed = append(installed, unixManagedRoute{prefix: prefix, gateway: gateway, device: device})
			return nil
		},
		physicalDefaultFunc: func(target netip.Addr) (netip.Addr, string) {
			queried = append(queried, target.Is6())
			if target.Is6() {
				return netip.MustParseAddr("2001:db8::1"), "en6"
			}
			return netip.MustParseAddr("192.0.2.1"), "en4"
		},
	}
	cfg := Config{
		Peers: []Peer{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}},
		DirectRoutes: []netip.Prefix{
			netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("2001:db8:100::/48"),
		},
	}
	if err := e.applyRoutes(cfg); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(queried, false) || !slices.Contains(queried, true) {
		t.Fatalf("physical default queries = %v, want both families", queried)
	}
	if len(installed) != 2 || installed[0].gateway.Is6() || !installed[1].gateway.Is6() {
		t.Fatalf("direct route owners = %#v, want family-matched gateways", installed)
	}
}

func TestDownPropagatesInterfaceRemovalFailure(t *testing.T) {
	want := errors.New("uninstall failed")
	e := &RealEngine{
		log:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
		up:                  true,
		iface:               "ratelmesh0",
		interfaceDeleteFunc: func(string) error { return want },
	}
	err := e.Down()
	if !errors.Is(err, want) {
		t.Fatalf("Down error = %v, want uninstall failure", err)
	}
	if !e.up {
		t.Fatal("failed interface removal was incorrectly reported as down")
	}
}

func TestApplyRoutesKeepsOldPinWithoutPhysicalDefault(t *testing.T) {
	oldEndpoint := netip.MustParseAddr("203.0.113.7")
	newEndpoint := netip.MustParseAddr("198.51.100.9")
	var pinAttempted bool
	var deleted []netip.Addr
	e := &RealEngine{
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface:         "utun-test",
		routesApplied: true,
		pinned:        []netip.Addr{oldEndpoint},
		physicalDefaultFunc: func(netip.Addr) (netip.Addr, string) {
			return netip.Addr{}, ""
		},
		routeViaFunc: func(netip.Prefix, netip.Addr, string) error {
			pinAttempted = true
			return nil
		},
		hostRouteDelFunc: func(addr netip.Addr) error {
			deleted = append(deleted, addr)
			return nil
		},
	}
	e.cfg = Config{PhysicalEndpoints: []netip.Addr{oldEndpoint}, Peers: []Peer{{
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}}}
	next := e.cfg
	next.PhysicalEndpoints = []netip.Addr{newEndpoint}

	if err := e.applyRoutes(next); err != nil {
		t.Fatal(err)
	}
	if pinAttempted || len(deleted) != 0 {
		t.Fatalf("unproven refresh mutated pins: attempted=%v deleted=%v", pinAttempted, deleted)
	}
	if len(e.pinned) != 1 || e.pinned[0] != oldEndpoint {
		t.Fatalf("retained pins = %v, want [%s]", e.pinned, oldEndpoint)
	}
}

func TestDesiredPinnedEndpointsIgnoreUncapturedAddressFamily(t *testing.T) {
	ipv4Exit := netip.MustParseAddr("203.0.113.7")
	ipv4Control := netip.MustParseAddr("198.51.100.8")
	ipv6Control := netip.MustParseAddr("2001:db8::8")
	cfg := Config{
		PhysicalEndpoints: []netip.Addr{ipv4Control, ipv6Control},
		Peers: []Peer{{
			Endpoints:  []string{netip.AddrPortFrom(ipv4Exit, 51820).String()},
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	}
	got := desiredPinnedEndpoints(cfg)
	want := []netip.Addr{ipv4Control, ipv4Exit}
	if !slices.Equal(got, want) {
		t.Fatalf("IPv4-only EXIT pins = %v, want %v; an unavailable IPv6 physical path must not block IPv4", got, want)
	}
}

func TestPhysicalDefaultRouteParsersIgnoreTunnelSplitDefaults(t *testing.T) {
	gateway, device := parseDarwinDefaultRoute(`   route to: default
destination: default
    gateway: 192.168.31.1
  interface: en0
`)
	if gateway != netip.MustParseAddr("192.168.31.1") || device != "en0" {
		t.Fatalf("darwin physical default = %s/%q", gateway, device)
	}
	gateway, device = parseLinuxDefaultRoute("default via 192.168.31.1 dev wlan0 proto dhcp metric 600\n", "ratelmesh0")
	if gateway != netip.MustParseAddr("192.168.31.1") || device != "wlan0" {
		t.Fatalf("linux physical default = %s/%q", gateway, device)
	}
}

func TestLinuxPhysicalDefaultChoosesLowestMetricNonTunnelRoute(t *testing.T) {
	output := `default dev ratelmesh0 metric 1
default via 10.8.0.1 dev wg-corp metric 50
default via 192.168.50.1 dev wlan0 proto dhcp metric 600
default via 192.168.31.1 dev eth0 proto dhcp metric 100
`
	gateway, device := parseLinuxDefaultRoute(output, "ratelmesh0")
	if gateway != netip.MustParseAddr("192.168.31.1") || device != "eth0" {
		t.Fatalf("physical default = %s/%q, want 192.168.31.1/eth0", gateway, device)
	}
}

func TestLinuxPhysicalRouteGetUsesPolicySelectedPathAndRejectsTunnel(t *testing.T) {
	output := "203.0.113.9 via 192.0.2.1 dev eth0 table 100 src 192.0.2.20 uid 0\n"
	gateway, device, ok := parseLinuxPhysicalRouteGet(output, "ratelmesh0")
	if !ok || gateway != netip.MustParseAddr("192.0.2.1") || device != "eth0" {
		t.Fatalf("policy-selected path = %s/%q/%v", gateway, device, ok)
	}
	tunnel := "203.0.113.9 dev ratelmesh0 src 100.64.0.2 uid 0\n"
	if _, _, ok := parseLinuxPhysicalRouteGet(tunnel, "ratelmesh0"); ok {
		t.Fatal("active EXIT route was accepted as a physical path")
	}
}

func TestLinuxPhysicalDefaultParsesECMPAndSkipsInvalidMetric(t *testing.T) {
	output := `default proto static metric not-a-number
	nexthop via 198.51.100.1 dev bad0 weight 1
default proto static metric 200
	nexthop via 192.0.2.2 dev eth2 weight 1
	nexthop via 192.0.2.1 dev eth1 weight 1
`
	gateway, device := parseLinuxDefaultRoute(output, "ratelmesh0")
	if gateway != netip.MustParseAddr("192.0.2.2") || device != "eth2" {
		t.Fatalf("ECMP physical default = %s/%q, want first valid nexthop", gateway, device)
	}
}

func TestLinuxPhysicalDefaultRejectsUnresolvedNexthopObject(t *testing.T) {
	gateway, device := parseLinuxDefaultRoute("default nhid 42 proto static metric 100\n", "ratelmesh0")
	if gateway.IsValid() || device != "" {
		t.Fatalf("unresolved nexthop object was guessed as %s/%q", gateway, device)
	}
}

func TestStageEndpointPinsRollsBackWholeAttemptOnFailure(t *testing.T) {
	oldEndpoint := netip.MustParseAddr("203.0.113.7")
	firstNew := netip.MustParseAddr("198.51.100.8")
	secondNew := netip.MustParseAddr("198.51.100.9")
	var deleted []netip.Addr
	e := &RealEngine{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface:  "utun-test",
		pinned: []netip.Addr{oldEndpoint},
		physicalDefaultFunc: func(netip.Addr) (netip.Addr, string) {
			return netip.MustParseAddr("192.168.31.1"), "en0"
		},
		routeViaFunc: func(prefix netip.Prefix, _ netip.Addr, _ string) error {
			if prefix.Addr() == secondNew {
				return errors.New("route rejected")
			}
			return nil
		},
		hostRouteDelFunc: func(addr netip.Addr) error {
			deleted = append(deleted, addr)
			return nil
		},
	}
	cfg := Config{
		PhysicalEndpoints: []netip.Addr{firstNew, secondNew},
		Peers: []Peer{{AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
		}}},
	}
	if _, err := e.stageEndpointPinsLocked(cfg); err == nil {
		t.Fatal("stage accepted a partially pinned endpoint set")
	}
	if len(e.pinned) != 1 || e.pinned[0] != oldEndpoint {
		t.Fatalf("pins after failed stage = %v, want old pin only", e.pinned)
	}
	if len(deleted) != 1 || deleted[0] != firstNew {
		t.Fatalf("rolled-back routes = %v, want [%s]", deleted, firstNew)
	}
}

func TestApplyRouteFailureAfterConfigSwitchPreservesDesiredPins(t *testing.T) {
	endpoint := netip.MustParseAddr("203.0.113.9")
	var deleted []netip.Addr
	e := &RealEngine{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface:  "utun-test",
		pinned: []netip.Addr{endpoint}, // staged before the UAPI switch
		routeAddFunc: func(prefix netip.Prefix, _ string) error {
			if prefix == netip.MustParsePrefix("100.64.0.9/32") {
				return errors.New("route programming failed")
			}
			return nil
		},
		routeDelFunc:   func(netip.Prefix) error { return nil },
		routeScrubFunc: func(string) {},
		hostRouteDelFunc: func(addr netip.Addr) error {
			deleted = append(deleted, addr)
			return nil
		},
	}
	cfg := Config{
		PhysicalEndpoints: []netip.Addr{endpoint},
		Peers: []Peer{{
			Endpoints: []string{"203.0.113.9:51820"},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.9/32"),
				netip.MustParsePrefix("0.0.0.0/0"),
			},
		}},
	}
	if err := e.applyRoutes(cfg); err == nil {
		t.Fatal("applyRoutes accepted a route programming failure")
	}
	if len(e.pinned) != 1 || e.pinned[0] != endpoint {
		t.Fatalf("desired pins after failed route apply = %v, want [%s]", e.pinned, endpoint)
	}
	if len(deleted) != 0 {
		t.Fatalf("failed route apply deleted live desired endpoint pins: %v", deleted)
	}
	if e.routesApplied {
		t.Fatal("failed route apply was marked complete")
	}
}

func TestApplyRouteFailureRetainsUndeletedRoutedRoute(t *testing.T) {
	first := netip.MustParsePrefix("100.64.0.8/32")
	second := netip.MustParsePrefix("100.64.0.9/32")
	e := &RealEngine{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface: "utun-test",
		routeAddFunc: func(prefix netip.Prefix, _ string) error {
			if prefix == second {
				return errors.New("second add failed")
			}
			return nil
		},
		routeDelFunc: func(prefix netip.Prefix) error {
			if prefix == first {
				return errors.New("first delete failed")
			}
			return nil
		},
		routeExistsFunc: func(prefix netip.Prefix) (bool, error) {
			return prefix == first, nil
		},
		routeScrubFunc: func(string) {},
	}
	cfg := Config{Peers: []Peer{{AllowedIPs: []netip.Prefix{first, second}}}}
	err := e.applyRoutes(cfg)
	if err == nil || !strings.Contains(err.Error(), "second add failed") || !strings.Contains(err.Error(), "first delete failed") {
		t.Fatalf("apply error did not aggregate install and cleanup failures: %v", err)
	}
	if len(e.routed) != 1 || e.routed[0] != first {
		t.Fatalf("undeleted routed route disappeared from ledger: %v", e.routed)
	}
}

func TestFailedHostRouteDeletionStaysInLedgerForRetry(t *testing.T) {
	endpoint := netip.MustParseAddr("203.0.113.9")
	attempts := 0
	e := &RealEngine{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		pinned: []netip.Addr{endpoint},
		hostRouteDelFunc: func(netip.Addr) error {
			attempts++
			if attempts == 1 {
				return errors.New("transient delete failure")
			}
			return nil
		},
		hostRouteExistsFunc: func(netip.Addr) (bool, error) {
			return true, nil
		},
	}
	e.clearRoutesPreservingPinsLocked(nil)
	if len(e.pinned) != 1 || e.pinned[0] != endpoint {
		t.Fatalf("failed deletion disappeared from ledger: %v", e.pinned)
	}
	e.clearRoutesPreservingPinsLocked(nil)
	if len(e.pinned) != 0 || attempts != 2 {
		t.Fatalf("cleanup was not retried: pins=%v attempts=%d", e.pinned, attempts)
	}
}

func TestAbsentHostRouteDeletionIsIdempotent(t *testing.T) {
	endpoint := netip.MustParseAddr("203.0.113.9")
	e := &RealEngine{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		pinned: []netip.Addr{endpoint},
		hostRouteDelFunc: func(netip.Addr) error {
			return errors.New("delete command failed")
		},
		hostRouteExistsFunc: func(netip.Addr) (bool, error) {
			return false, nil
		},
	}
	if err := e.clearRoutesPreservingPinsLocked(nil); err != nil {
		t.Fatalf("already-absent host route was not idempotent: %v", err)
	}
	if len(e.pinned) != 0 {
		t.Fatalf("phantom host pin remained in ledger: %v", e.pinned)
	}
}

func TestHostRouteNotFoundErrorIsIdempotent(t *testing.T) {
	endpoint := netip.MustParseAddr("203.0.113.9")
	queried := false
	e := &RealEngine{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		pinned: []netip.Addr{endpoint},
		hostRouteDelFunc: func(netip.Addr) error {
			return errors.New("RTNETLINK answers: No such process")
		},
		hostRouteExistsFunc: func(netip.Addr) (bool, error) {
			queried = true
			return true, nil
		},
	}
	if err := e.clearRoutesPreservingPinsLocked(nil); err != nil {
		t.Fatalf("not-found host route was not idempotent: %v", err)
	}
	if queried || len(e.pinned) != 0 {
		t.Fatalf("not-found delete queried=%v pins=%v, want direct idempotent success", queried, e.pinned)
	}
}

func TestHostRouteVerificationFailureRetainsLedger(t *testing.T) {
	endpoint := netip.MustParseAddr("203.0.113.9")
	e := &RealEngine{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		pinned: []netip.Addr{endpoint},
		hostRouteDelFunc: func(netip.Addr) error {
			return errors.New("delete command failed")
		},
		hostRouteExistsFunc: func(netip.Addr) (bool, error) {
			return false, errors.New("exact query failed")
		},
	}
	err := e.clearRoutesPreservingPinsLocked(nil)
	if err == nil || !strings.Contains(err.Error(), "exact query failed") {
		t.Fatalf("verification failure was not reported: %v", err)
	}
	if len(e.pinned) != 1 || e.pinned[0] != endpoint {
		t.Fatalf("unverified host pin disappeared from ledger: %v", e.pinned)
	}
}

func TestFailedStagedPinRollbackStaysInLedger(t *testing.T) {
	endpoint := netip.MustParseAddr("203.0.113.9")
	e := &RealEngine{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		pinned: []netip.Addr{endpoint},
		hostRouteDelFunc: func(netip.Addr) error {
			return errors.New("transient delete failure")
		},
	}
	e.rollbackStagedPinsLocked([]netip.Addr{endpoint})
	if len(e.pinned) != 1 || e.pinned[0] != endpoint {
		t.Fatalf("failed staged rollback disappeared from ledger: %v", e.pinned)
	}
}

func TestApplyRoutesReplacesChangedRoutePlan(t *testing.T) {
	var deleted []netip.Prefix
	e := &RealEngine{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface: "utun-test",
		routeAddFunc: func(netip.Prefix, string) error {
			return nil
		},
		routeDelFunc: func(prefix netip.Prefix) error {
			deleted = append(deleted, prefix)
			return nil
		},
		routeScrubFunc: func(string) {},
	}
	prev := Config{Peers: []Peer{{AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("100.64.0.1/32"),
	}}}}
	if err := e.applyRoutes(prev); err != nil {
		t.Fatal(err)
	}
	e.cfg = prev
	next := Config{Peers: []Peer{{AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("100.64.0.2/32"),
	}}}}
	if err := e.applyRoutes(next); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != netip.MustParsePrefix("100.64.0.1/32") {
		t.Fatalf("changed plan deleted = %v, want previous route", deleted)
	}
}

func TestApplyRoutesKeepsIPv4WhenIPv6DefaultIsUnavailable(t *testing.T) {
	var added, deleted []netip.Prefix
	e := &RealEngine{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface: "ratelmesh-test0",
		routeAddFunc: func(prefix netip.Prefix, _ string) error {
			added = append(added, prefix)
			if prefix == netip.MustParsePrefix("8000::/1") {
				return errors.New("IPv6 is disabled")
			}
			return nil
		},
		routeDelFunc: func(prefix netip.Prefix) error {
			deleted = append(deleted, prefix)
			return nil
		},
	}
	cfg := Config{KillSwitch: true, Peers: []Peer{{AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
	}}}}
	if err := e.applyRoutes(cfg); err != nil {
		t.Fatalf("applyRoutes rejected working IPv4 because IPv6 is unavailable: %v", err)
	}
	wantFirst := netip.MustParsePrefix("0.0.0.0/1")
	if len(added) == 0 || added[0] != wantFirst {
		t.Fatalf("first default route = %v, want IPv4 %v", added, wantFirst)
	}
	if len(e.routed) != 2 || !e.routed[0].Addr().Is4() || !e.routed[1].Addr().Is4() {
		t.Fatalf("retained routes = %v, want only IPv4 halves", e.routed)
	}
	wantRollback := netip.MustParsePrefix("::/1")
	if len(deleted) != 1 || deleted[0] != wantRollback {
		t.Fatalf("IPv6 rollback = %v, want [%v]", deleted, wantRollback)
	}
}

func TestIPv6PartialRollbackRetainsUndeletedRoute(t *testing.T) {
	firstIPv6 := netip.MustParsePrefix("::/1")
	secondIPv6 := netip.MustParsePrefix("8000::/1")
	e := &RealEngine{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface: "ratelmesh-test0",
		routeAddFunc: func(prefix netip.Prefix, _ string) error {
			if prefix == secondIPv6 {
				return errors.New("IPv6 is disabled")
			}
			return nil
		},
		routeDelFunc: func(prefix netip.Prefix) error {
			if prefix == firstIPv6 {
				return errors.New("kernel retained IPv6 route")
			}
			return nil
		},
		routeExistsFunc: func(prefix netip.Prefix) (bool, error) {
			return prefix == firstIPv6, nil
		},
	}
	cfg := Config{KillSwitch: true, Peers: []Peer{{AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
	}}}}
	if err := e.applyRoutes(cfg); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(e.routed, firstIPv6) || !slices.Contains(e.residualRoutes, firstIPv6) {
		t.Fatalf("failed IPv6 rollback mixed with active routes: active=%v residual=%v", e.routed, e.residualRoutes)
	}
	if !e.routesApplied {
		t.Fatal("partial rollback failure marked the working IPv4 plan inactive")
	}
}

func TestIPv6PartialRollbackSecondApplyPreservesWorkingIPv4(t *testing.T) {
	firstIPv6 := netip.MustParsePrefix("::/1")
	secondIPv6 := netip.MustParsePrefix("8000::/1")
	firstIPv4 := netip.MustParsePrefix("0.0.0.0/1")
	deleteAttempts := 0
	e := &RealEngine{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface: "ratelmesh-test0",
		routeAddFunc: func(prefix netip.Prefix, _ string) error {
			if prefix == secondIPv6 {
				return errors.New("IPv6 is disabled")
			}
			return nil
		},
		routeDelFunc: func(prefix netip.Prefix) error {
			if prefix == firstIPv6 {
				deleteAttempts++
				return errors.New("kernel retained IPv6 route")
			}
			t.Fatalf("second apply deleted active route %s", prefix)
			return nil
		},
		routeExistsFunc: func(prefix netip.Prefix) (bool, error) {
			return prefix == firstIPv6, nil
		},
	}
	cfg := Config{KillSwitch: true, Peers: []Peer{{AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
	}}}}
	if err := e.applyRoutes(cfg); err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	if err := e.applyRoutes(cfg); err != nil {
		t.Fatalf("same-plan retry disrupted fail-closed IPv4 service: %v", err)
	}
	if !slices.Contains(e.routed, firstIPv4) || !slices.Contains(e.residualRoutes, firstIPv6) {
		t.Fatalf("second apply active=%v residual=%v", e.routed, e.residualRoutes)
	}
	if deleteAttempts != 2 {
		t.Fatalf("deferred IPv6 cleanup attempts=%d, want 2", deleteAttempts)
	}
}

func TestUnixExactOwnerDoesNotMatchSamePrefixOnDifferentPath(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	owner := unixManagedRoute{
		prefix:  prefix,
		gateway: netip.MustParseAddr("192.0.2.1"),
		device:  "en0",
		kind:    unixRouteDirect,
	}
	other := "203.0.113.0/24 via 198.51.100.1 dev eth9\n"
	if linuxRouteOutputHasOwner(other, owner) {
		t.Fatal("same-prefix route on another gateway/interface matched our owner")
	}
	mixed := other + "203.0.113.0/24 via 192.0.2.1 dev en0\n"
	if !linuxRouteOutputHasOwner(mixed, owner) {
		t.Fatal("exact owned route was not found")
	}
	args := strings.Join(linuxManagedRouteDeleteArgs(owner), " ")
	if !strings.Contains(args, "via 192.0.2.1") || !strings.Contains(args, "dev en0") {
		t.Fatalf("delete args lost ownership identity: %s", args)
	}
}

func mustDarwinRouteTableHasOwner(t *testing.T, output string, owner unixManagedRoute) bool {
	t.Helper()
	matched, err := darwinRouteTableHasOwner(output, owner)
	if err != nil {
		t.Fatal(err)
	}
	return matched
}

func TestDarwinRouteTableOwnerSurvivesMoreSpecificRouteShadow(t *testing.T) {
	owner := unixManagedRoute{
		prefix:  netip.MustParsePrefix("203.0.113.0/24"),
		gateway: netip.MustParseAddr("192.0.2.1"),
		device:  "en0",
		kind:    unixRouteDirect,
	}
	table := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.0.2.1          UGScg                 en0
203.0.113.0        198.51.100.1       UGHS                  en9
203.0.113/24       192.0.2.1          UGSc                  en0
`
	if !mustDarwinRouteTableHasOwner(t, table, owner) {
		t.Fatal("more-specific host route shadowed the exact managed network route")
	}

	otherOwnerOnly := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
203.0.113/24       198.51.100.1       UGSc                  en9
`
	if mustDarwinRouteTableHasOwner(t, otherOwnerOnly, owner) {
		t.Fatal("same-prefix route on another gateway/interface matched our owner")
	}
}

func TestDarwinRouteTableOwnerMatchesBlackholeIdentity(t *testing.T) {
	owner := unixManagedRoute{
		prefix: netip.MustParsePrefix("2001:db8:dead::/48"),
		kind:   unixRouteBlackhole,
	}
	table := `Routing tables

Internet6:
Destination                             Gateway                         Flags               Netif Expire
2001:db8:dead::/48                      ::1                             UGB                   lo0
`
	if !mustDarwinRouteTableHasOwner(t, table, owner) {
		t.Fatal("exact managed IPv6 blackhole route was not recognized")
	}
	if mustDarwinRouteTableHasOwner(t, strings.Replace(table, "UGB", "UGS", 1), owner) {
		t.Fatal("non-blackhole route matched managed blackhole owner")
	}
	if mustDarwinRouteTableHasOwner(t, strings.Replace(table, "UGB", "UGb", 1), owner) {
		t.Fatal("lowercase broadcast flag was confused with uppercase BLACKHOLE")
	}
	directOwner := owner
	directOwner.kind = unixRouteDirect
	if !mustDarwinRouteTableHasOwner(t, strings.Replace(table, "UGB", "UGb", 1), directOwner) {
		t.Fatal("lowercase broadcast flag was rejected as if it were uppercase BLACKHOLE")
	}
}

func TestDarwinRouteTableOwnerMatchesZonedIPv6GatewayAndInterface(t *testing.T) {
	owner := unixManagedRoute{
		prefix:  netip.MustParsePrefix("2001:db8:1234::/48"),
		gateway: netip.MustParseAddr("fe80::1%en0"),
		device:  "en0",
		kind:    unixRouteDirect,
	}
	table := `Routing tables

Internet6:
Destination                             Gateway                         Flags               Netif Expire
2001:db8:1234::/48                      fe80::1%en0                     UGS                   en0
`
	if !mustDarwinRouteTableHasOwner(t, table, owner) {
		t.Fatal("zoned IPv6 gateway did not match its exact managed route")
	}
}

func TestDarwinRouteTableOwnerAcceptsScopedTunnelHostWithoutHostFlag(t *testing.T) {
	owner := unixManagedRoute{
		prefix: netip.MustParsePrefix("100.64.0.3/32"),
		device: "utun0",
		kind:   unixRouteTunnel,
	}
	table := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
100.64.0.3/32      utun0              USc                 utun0
`
	if !mustDarwinRouteTableHasOwner(t, table, owner) {
		t.Fatal("scoped macOS /32 tunnel route without HOST flag was not recognized")
	}
}

func TestDarwinRouteTableUnknownFormatIsNotRouteAbsence(t *testing.T) {
	owner := unixManagedRoute{
		prefix: netip.MustParsePrefix("100.64.0.3/32"),
		device: "utun0",
		kind:   unixRouteTunnel,
	}
	unknown := `Routing tables

Internet:
Ziel               Gateway            Flags               Schnittstelle
100.64.0.3/32      utun0              USc                 utun0
`
	if matched, err := darwinRouteTableHasOwner(unknown, owner); err == nil || matched {
		t.Fatalf("unknown route-table format = matched %v, err %v; want retained ownership error", matched, err)
	}
	malformed := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
future-format-without-columns
`
	if matched, err := darwinRouteTableHasOwner(malformed, owner); err == nil || matched {
		t.Fatalf("malformed route-table row = matched %v, err %v; want retained ownership error", matched, err)
	}
}

func TestWindowsRouteQueryFailureRetainsLedger(t *testing.T) {
	route := windowsManagedRoute{
		prefix:         netip.MustParsePrefix("203.0.113.0/24"),
		interfaceIndex: "7",
		nextHop:        "192.0.2.1",
	}
	attempts := 0
	e := &RealEngine{
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		windowsRoutes: []windowsManagedRoute{route},
		windowsPins:   []windowsManagedRoute{route},
		windowsRouteRemoveFunc: func(windowsManagedRoute) error {
			attempts++
			return errors.New("Get-NetRoute CIM query failed")
		},
	}
	if err := e.clearWindowsRoutesLocked(); err == nil {
		t.Fatal("Windows query failure was treated as route absence")
	}
	if attempts != 1 || !slices.Equal(e.windowsRoutes, []windowsManagedRoute{route}) ||
		!slices.Equal(e.windowsPins, []windowsManagedRoute{route}) {
		t.Fatalf("query failure lost ownership: attempts=%d routes=%v pins=%v", attempts, e.windowsRoutes, e.windowsPins)
	}
	script := windowsRemoveExactRouteScript(route)
	if !strings.Contains(script, "Get-NetRoute") || !strings.Contains(script, "-ErrorAction Stop") ||
		strings.Contains(script, "SilentlyContinue") {
		t.Fatalf("Windows exact query is not fail-closed: %s", script)
	}
	if strings.Contains(script, "Get-NetRoute -DestinationPrefix") ||
		!strings.Contains(script, "$_.DestinationPrefix -eq '203.0.113.0/24'") ||
		!strings.Contains(script, "$_.InterfaceIndex -eq 7") {
		t.Fatalf("Windows absence query did not filter an error-checked ActiveStore snapshot in memory: %s", script)
	}
}

func TestWindowsPhysicalDefaultScriptEmitsNumericConnectionState(t *testing.T) {
	script := windowsPhysicalDefaultScript("IPv4", "0.0.0.0/0")
	if !strings.Contains(script, "([int]$i.ConnectionState).ToString()") ||
		strings.Contains(script, "$i.ConnectionState.ToString()") {
		t.Fatalf("Windows physical-default script exposes a localized connection-state label: %s", script)
	}
}

func TestApplyRoutesFailsClosedOnIPv6ErrorWithoutKillSwitch(t *testing.T) {
	var added, deleted []netip.Prefix
	e := &RealEngine{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		iface: "ratelmesh-test0",
		routeAddFunc: func(prefix netip.Prefix, _ string) error {
			added = append(added, prefix)
			if prefix == netip.MustParsePrefix("8000::/1") {
				return errors.New("IPv6 is disabled")
			}
			return nil
		},
		routeDelFunc: func(prefix netip.Prefix) error {
			deleted = append(deleted, prefix)
			return nil
		},
	}
	cfg := Config{Peers: []Peer{{AllowedIPs: []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
	}}}}
	if err := e.applyRoutes(cfg); err == nil {
		t.Fatal("applyRoutes accepted an IPv6 leak without a kill switch")
	}
	if len(added) == 0 || !added[0].Addr().Is6() {
		t.Fatalf("default route order = %v, want IPv6 first without kill switch", added)
	}
	if len(e.routed) != 0 {
		t.Fatalf("failed apply retained routes: %v", e.routed)
	}
	if len(deleted) != 1 || deleted[0] != netip.MustParsePrefix("::/1") {
		t.Fatalf("failed apply rollback = %v, want first IPv6 half", deleted)
	}
}

func TestDownRetriesAndReportsPermanentRouteCleanup(t *testing.T) {
	route := netip.MustParsePrefix("100.64.0.9/32")
	attempts := 0
	permanent := true
	e := &RealEngine{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		routed: []netip.Prefix{route},
		routeDelFunc: func(netip.Prefix) error {
			attempts++
			if permanent {
				return errors.New("permission denied")
			}
			return nil
		},
		routeExistsFunc: func(netip.Prefix) (bool, error) {
			return permanent, nil
		},
	}
	err := e.Down()
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Down swallowed permanent cleanup failure: %v", err)
	}
	if attempts != 3 || len(e.routed) != 1 {
		t.Fatalf("Down retry/ledger state: attempts=%d routes=%v", attempts, e.routed)
	}
	permanent = false
	if err := e.Down(); err != nil {
		t.Fatalf("Down did not retry residual ledger while already down: %v", err)
	}
	if len(e.routed) != 0 || attempts != 4 {
		t.Fatalf("residual cleanup was not retried: attempts=%d routes=%v", attempts, e.routed)
	}
}

func TestDownAggregatesRouteAndPinCleanupFailures(t *testing.T) {
	route := netip.MustParsePrefix("100.64.0.9/32")
	endpoint := netip.MustParseAddr("203.0.113.9")
	e := &RealEngine{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		routed: []netip.Prefix{route},
		pinned: []netip.Addr{endpoint},
		routeDelFunc: func(netip.Prefix) error {
			return errors.New("route cleanup failed")
		},
		routeExistsFunc: func(netip.Prefix) (bool, error) {
			return true, nil
		},
		hostRouteDelFunc: func(netip.Addr) error {
			return errors.New("pin cleanup failed")
		},
		hostRouteExistsFunc: func(netip.Addr) (bool, error) {
			return true, nil
		},
	}
	err := e.Down()
	if err == nil || !strings.Contains(err.Error(), "route cleanup failed") || !strings.Contains(err.Error(), "pin cleanup failed") {
		t.Fatalf("Down did not aggregate cleanup failures: %v", err)
	}
}

func TestDarwinExactHostRouteQueryRequiresHostFlagAndDestination(t *testing.T) {
	addr := netip.MustParseAddr("100.64.0.3")
	exact := `route to: 100.64.0.3
destination: 100.64.0.3
flags: <UP,GATEWAY,HOST,DONE,STATIC>
`
	if !darwinLookupHasExactHostRoute(exact, addr) {
		t.Fatal("exact Darwin host route was not recognized")
	}
	defaultOnly := `route to: 100.64.0.3
destination: default
flags: <UP,GATEWAY,DONE,STATIC>
`
	if darwinLookupHasExactHostRoute(defaultOnly, addr) {
		t.Fatal("default route was mistaken for an exact host route")
	}
}

func TestDarwinNetworkRouteQueryRequiresPrefixAndOwnerPath(t *testing.T) {
	owner := unixManagedRoute{
		prefix:  netip.MustParsePrefix("192.168.0.0/16"),
		gateway: netip.MustParseAddr("192.0.2.1"),
		device:  "en0",
		kind:    unixRouteDirect,
	}
	exact := `destination: 192.168.0.0
mask: 0xffff0000
gateway: 192.0.2.1
interface: en0
flags: <UP,GATEWAY,DONE,STATIC>
`
	if !darwinLookupHasRouteOwner(exact, owner) {
		t.Fatal("exact Darwin network owner was not recognized")
	}
	otherOwner := strings.Replace(exact, "gateway: 192.0.2.1", "gateway: 192.0.2.99", 1)
	if darwinLookupHasRouteOwner(otherOwner, owner) {
		t.Fatal("same-prefix Darwin route on another gateway matched our owner")
	}
	broader := strings.Replace(exact, "mask: 0xffff0000", "mask: 0xff000000", 1)
	if darwinLookupHasRouteOwner(broader, owner) {
		t.Fatal("broader Darwin route was mistaken for the exact prefix")
	}
}
