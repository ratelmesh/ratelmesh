package magicsock

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/types"
)

func TestSTUNRoundTrip(t *testing.T) {
	srv, err := ListenSTUN("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	reflexive, err := DiscoverReflexive(ctx, srv.LocalAddr().String())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	// The STUN server sees our loopback source address.
	if !reflexive.Addr().IsLoopback() {
		t.Errorf("reflexive addr = %v, want loopback", reflexive.Addr())
	}
	if reflexive.Port() == 0 {
		t.Error("reflexive port should be non-zero")
	}
}

func TestSTUNRateLimiterIsBounded(t *testing.T) {
	srv := &STUNServer{sources: make(map[netip.Addr]stunRate)}
	now := time.Now()
	source := netip.MustParseAddr("198.51.100.1")
	for i := 0; i < maxSTUNPerSource; i++ {
		if !srv.allow(source, now) {
			t.Fatalf("request %d unexpectedly limited", i)
		}
	}
	if srv.allow(source, now) {
		t.Fatal("STUN reflector rate limit was not enforced")
	}
	for i := 1; i < maxSTUNSources; i++ {
		if !srv.allow(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), now) {
			t.Fatalf("source %d unexpectedly rejected", i)
		}
	}
	if srv.allow(netip.MustParseAddr("203.0.113.2"), now) {
		t.Fatal("STUN source tracking grew past its hard cap")
	}
	if !srv.allow(netip.MustParseAddr("203.0.113.2"), now.Add(stunRateLimitWindow)) {
		t.Fatal("expired STUN source entries were not pruned")
	}
}

func TestSTUNRequestRequiresMagicCookieAndExactLength(t *testing.T) {
	tx, _ := NewTxID()
	req := EncodeBindingRequest(tx)
	if _, ok := parseRequestTx(req); !ok {
		t.Fatal("valid STUN request rejected")
	}
	req[4] ^= 1
	if _, ok := parseRequestTx(req); ok {
		t.Fatal("request with invalid STUN cookie accepted")
	}
	if _, ok := parseRequestTx(append(EncodeBindingRequest(tx), 0)); ok {
		t.Fatal("request with inconsistent message length accepted")
	}
}

func TestSTUNEncodeParseSymmetry(t *testing.T) {
	tx, _ := NewTxID()
	want := netip.MustParseAddrPort("203.0.113.5:41641")
	resp := EncodeBindingResponse(tx, want)
	got, err := ParseBindingResponse(resp, tx)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round-trip = %v, want %v", got, want)
	}
}

func TestParseRejectsWrongTxID(t *testing.T) {
	tx, _ := NewTxID()
	other, _ := NewTxID()
	resp := EncodeBindingResponse(tx, netip.MustParseAddrPort("198.51.100.1:1234"))
	if _, err := ParseBindingResponse(resp, other); err == nil {
		t.Error("expected tx-id mismatch error")
	}
}

func TestPeerPathUpgradeAndFallback(t *testing.T) {
	var k types.Key
	pp := NewPeerPath(k)

	// Starts on the relay.
	if pt, _ := pp.Current(); pt != PathRelay {
		t.Fatalf("initial path = %s, want relay", pt)
	}

	ep := netip.MustParseAddrPort("100.64.0.9:51820")
	// Confirming an unknown candidate is refused.
	if pp.ConfirmDirect(ep) {
		t.Fatal("confirmed a non-candidate endpoint")
	}

	pp.SetCandidates([]netip.AddrPort{ep})
	if !pp.ConfirmDirect(ep) {
		t.Fatal("failed to confirm known candidate")
	}
	if pt, got := pp.Current(); pt != PathDirect || got != ep {
		t.Fatalf("path = %s/%v, want direct/%v", pt, got, ep)
	}

	// Losing the direct path falls back to relay.
	pp.LoseDirect()
	if pt, _ := pp.Current(); pt != PathRelay {
		t.Fatalf("after loss path = %s, want relay", pt)
	}

	// Re-confirm, then a candidate change that drops it should reset to relay.
	pp.ConfirmDirect(ep)
	pp.SetCandidates([]netip.AddrPort{netip.MustParseAddrPort("100.64.0.10:51820")})
	if pt, _ := pp.Current(); pt != PathRelay {
		t.Fatalf("after candidate change path = %s, want relay", pt)
	}
}

func TestDiscoProbeConfirmsDirectPath(t *testing.T) {
	resp, err := ListenDisco("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go resp.Serve(ctx)

	var k types.Key
	pp := NewPeerPath(k)
	pp.SetCandidates([]netip.AddrPort{resp.LocalAddr()})

	ep, err := ProbeAll(ctx, pp, time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if ep != resp.LocalAddr() {
		t.Fatalf("probed %v, want %v", ep, resp.LocalAddr())
	}
	if pt, _ := pp.Current(); pt != PathDirect {
		t.Fatalf("path after probe = %s, want direct", pt)
	}
}

func TestProbeUnreachableFails(t *testing.T) {
	var k types.Key
	pp := NewPeerPath(k)
	// Reserved TEST-NET address that won't answer.
	pp.SetCandidates([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:9")})
	ctx := context.Background()
	if _, err := ProbeAll(ctx, pp, 200*time.Millisecond); err == nil {
		t.Error("expected probe failure for unreachable candidate")
	}
}

// TestDiscoProbeDirectReachability exercises Probe — the STATE-FREE boolean
// reachability check that the relay→direct upgrade gate will use (NOT ProbeAll,
// which mutates PeerPath via ConfirmDirect and would record a disco address as a
// WG endpoint). Confirms success against a live responder and failure against an
// unreachable candidate, on a non-WG loopback port.
func TestDiscoProbeDirectReachability(t *testing.T) {
	resp, err := ListenDisco("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go resp.Serve(ctx)

	if err := Probe(ctx, resp.LocalAddr(), time.Second); err != nil {
		t.Fatalf("Probe of a live responder failed: %v", err)
	}
	// Reserved TEST-NET-1 address with no listener → must fail, AND fail fast
	// (the elapsed bound guards the deadline logic: a regression that dropped it
	// would otherwise hang until the whole-suite timeout instead of erroring).
	start := time.Now()
	err = Probe(ctx, netip.MustParseAddrPort("192.0.2.1:9"), 200*time.Millisecond)
	if err == nil {
		t.Error("Probe of an unreachable candidate should fail")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Probe took %v to fail, want it bounded by the ~200ms timeout", elapsed)
	}
}

// TestSTUNConnMapsOwnPort proves STUNConn discovers the reflexive mapping of the
// PASSED conn (not a separate ephemeral socket), so a disco socket learns its own
// external port — the property that makes disco endpoints work through NAT.
func TestSTUNConnMapsOwnPort(t *testing.T) {
	srv, err := ListenSTUN("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	localPort := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	reflexive, err := STUNConn(ctx, conn, srv.LocalAddr().String())
	if err != nil {
		t.Fatalf("STUNConn: %v", err)
	}
	// The reflexive port must be THIS conn's port (loopback => no NAT remap).
	if reflexive.Port() != localPort {
		t.Fatalf("reflexive port = %d, want this conn's port %d", reflexive.Port(), localPort)
	}
	// Deadline was cleared → the conn is usable for blocking reads afterward.
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Error("expected timeout on idle conn, got a read")
	}
}
