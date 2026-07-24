package daemon

import (
	"net"
	"net/netip"
	"testing"
)

func TestPhysicalNetworkFiltering(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"en0", true},
		{"eth0", true},
		{"utun4", false},
		{"wg0", false},
		{"awdl0", false},
	} {
		iface := net.Interface{Name: tc.name, Flags: net.FlagUp}
		if got := isPhysicalInterface(iface); got != tc.want {
			t.Errorf("isPhysicalInterface(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"172.20.10.2", true},
		{"192.168.68.60", true},
		{"100.64.0.3", false},
		{"127.0.0.1", false},
		{"fe80::1", false},
	} {
		if got := isPhysicalAddress(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("isPhysicalAddress(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestControlRecoverySignalIsConsumed(t *testing.T) {
	d := new(Daemon)
	d.markControlRecovered()
	if !d.consumeControlRecovered() {
		t.Fatal("successful registration did not reset retry state")
	}
	if d.consumeControlRecovered() {
		t.Fatal("control recovery signal was not consumed")
	}
}
