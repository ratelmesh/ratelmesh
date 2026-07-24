//go:build wgreal

package wgengine

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
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
