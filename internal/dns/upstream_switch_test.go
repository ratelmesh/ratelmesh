package dns

import (
	"context"
	"testing"
	"time"
)

// TestSetUpstreamsRedirectsForwarding proves the DNS server's out-of-zone
// forwarding target can be switched at runtime — the mechanism behind DNS-leak
// protection (force queries through the tunnel resolver while an exit is active).
func TestSetUpstreamsRedirectsForwarding(t *testing.T) {
	local, localTCP := startTruncatingUpstream(t, "10.0.0.1")
	tunnel, tunnelTCP := startTruncatingUpstream(t, "203.0.113.9")

	z := NewZone("")
	srv, err := NewServer(z, "127.0.0.1:0", local)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	// Initially forwards to the local resolver.
	if ip := queryA(t, srv.LocalAddr().String(), "rr.youtube.com."); ip != "10.0.0.1" {
		t.Fatalf("before switch = %q, want 10.0.0.1", ip)
	}
	waitForTCPFallback(t, localTCP)

	// Switch to the tunnel resolver (as the daemon does when an exit activates).
	srv.SetUpstreams([]string{tunnel})
	if ip := queryA(t, srv.LocalAddr().String(), "rr.youtube.com."); ip != "203.0.113.9" {
		t.Fatalf("after switch = %q, want 203.0.113.9 (queries must go through the tunnel resolver)", ip)
	}
	waitForTCPFallback(t, tunnelTCP)
	assertNoTCPFallback(t, localTCP)

	// Returning to DIRECT must restore the physical resolver, including its TCP
	// fallback path. This is the regression boundary for mode switches that
	// previously left browser pages reachable while media DNS failed.
	srv.SetUpstreams([]string{local})
	if ip := queryA(t, srv.LocalAddr().String(), "rr.youtube.com."); ip != "10.0.0.1" {
		t.Fatalf("after DIRECT restore = %q, want 10.0.0.1", ip)
	}
	waitForTCPFallback(t, localTCP)
}

func waitForTCPFallback(t *testing.T, seen <-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-seen:
	case <-timer.C:
		t.Fatal("truncated media DNS response did not use TCP")
	}
}

func assertNoTCPFallback(t *testing.T, seen <-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-seen:
		t.Fatal("EXIT media DNS leaked to the physical resolver")
	case <-timer.C:
	}
}
