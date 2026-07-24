package main

import "testing"

func TestDefaultKillSwitch(t *testing.T) {
	if !defaultKillSwitch("darwin") {
		t.Fatal("macOS must default to fail-closed exit routing")
	}
	for _, goos := range []string{"linux", "windows", "freebsd"} {
		if defaultKillSwitch(goos) {
			t.Fatalf("%s kill switch default changed unexpectedly", goos)
		}
	}
}

func TestDefaultTunnelDNSRequiresDarwinMagicDNS(t *testing.T) {
	if got := defaultTunnelDNS("darwin", true); got != "1.1.1.1:53" {
		t.Fatalf("darwin MagicDNS default = %q", got)
	}
	for _, tc := range []struct {
		goos     string
		magicDNS bool
	}{
		{goos: "darwin", magicDNS: false},
		{goos: "linux", magicDNS: true},
		{goos: "windows", magicDNS: true},
	} {
		if got := defaultTunnelDNS(tc.goos, tc.magicDNS); got != "" {
			t.Fatalf("defaultTunnelDNS(%q, %v) = %q, want empty", tc.goos, tc.magicDNS, got)
		}
	}
}
