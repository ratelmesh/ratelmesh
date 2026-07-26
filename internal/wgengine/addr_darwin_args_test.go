//go:build wgreal

package wgengine

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestDarwinRouteArgsSelectAddressFamily(t *testing.T) {
	if got, want := darwinRouteArgs("add", netip.MustParsePrefix("0.0.0.0/1")),
		[]string{"-n", "add", "-net", "0.0.0.0/1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv4 args = %v, want %v", got, want)
	}
	if got, want := darwinRouteArgs("add", netip.MustParsePrefix("::/1")),
		[]string{"-n", "add", "-inet6", "-net", "::/1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv6 args = %v, want %v", got, want)
	}
}

func TestDarwinHostRouteArgsSelectIPv6(t *testing.T) {
	got := darwinHostRouteArgs("delete", netip.MustParseAddr("2001:db8::1"))
	want := []string{"-n", "delete", "-inet6", "-host", "2001:db8::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
}

func TestDarwinRouteOnInterfaceArgsScopesCrashCleanup(t *testing.T) {
	got := darwinRouteOnInterfaceArgs(
		"delete",
		netip.MustParsePrefix("128.0.0.0/1"),
		"utun7",
	)
	want := []string{"-n", "delete", "-net", "128.0.0.0/1", "-interface", "utun7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
}

func TestDarwinTunnelMTUAvoidsNestedPathBlackholes(t *testing.T) {
	if darwinTunnelMTU != 1280 {
		t.Fatalf("darwin tunnel MTU = %d, want path-safe 1280", darwinTunnelMTU)
	}
}

func TestLinuxInterfaceUpSetsPathSafeMTU(t *testing.T) {
	commands := interfaceUpPlan("linux", "ratelmesh0")
	want := [][]string{
		{"link", "set", "dev", "ratelmesh0", "mtu", "1280"},
		{"link", "set", "dev", "ratelmesh0", "up"},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("Linux interface-up plan = %v, want %v", commands, want)
	}
}
