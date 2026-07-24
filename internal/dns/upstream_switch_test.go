package dns

import (
	"context"
	"testing"
)

// TestSetUpstreamsRedirectsForwarding proves the DNS server's out-of-zone
// forwarding target can be switched at runtime — the mechanism behind DNS-leak
// protection (force queries through the tunnel resolver while an exit is active).
func TestSetUpstreamsRedirectsForwarding(t *testing.T) {
	local := startFakeUpstream(t, "10.0.0.1")     // stands in for the ISP/local resolver
	tunnel := startFakeUpstream(t, "203.0.113.9") // stands in for the tunnel resolver

	z := NewZone("")
	srv, err := NewServer(z, "127.0.0.1:0", local)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	// Initially forwards to the local resolver.
	if ip := queryA(t, srv.LocalAddr().String(), "www.example.com."); ip != "10.0.0.1" {
		t.Fatalf("before switch = %q, want 10.0.0.1", ip)
	}

	// Switch to the tunnel resolver (as the daemon does when an exit activates).
	srv.SetUpstreams([]string{tunnel})
	if ip := queryA(t, srv.LocalAddr().String(), "www.example.com."); ip != "203.0.113.9" {
		t.Fatalf("after switch = %q, want 203.0.113.9 (queries must go through the tunnel resolver)", ip)
	}
}
