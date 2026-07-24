package dns

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestSlowForwardDoesNotBlockOtherQueries covers the macOS failure where the
// resolver issues several names/types in parallel. A filtered upstream query
// must not hold the server's read loop for its full three-second deadline and
// make unrelated, answerable queries time out behind it.
func TestSlowForwardDoesNotBlockOtherQueries(t *testing.T) {
	upstream, slowSeen := startSelectiveUpstream(t)
	srv, err := NewServer(NewZone(""), "127.0.0.1:0", upstream)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	slow, err := net.Dial("udp", srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	if _, err := slow.Write(buildQuery(t, "slow.example.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-slowSeen:
	case <-time.After(time.Second):
		t.Fatal("slow query never reached upstream")
	}

	started := time.Now()
	if ip := queryA(t, srv.LocalAddr().String(), "fast.example."); ip != "203.0.113.8" {
		t.Fatalf("fast query = %q", ip)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("fast query waited behind slow query for %v", elapsed)
	}
}

func TestInZoneQueryDoesNotNeedUpstreamSlot(t *testing.T) {
	z := NewZone("")
	z.Rebuild(testNode("laptop", "alice", "100.64.0.1"), nil)
	srv, err := NewServer(z, "127.0.0.1:0", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	for range cap(srv.querySlots) {
		srv.querySlots <- struct{}{}
	}

	resp, err := srv.respond(buildQuery(t, "laptop.alice.ratelmesh.net.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("in-zone query with saturated upstream slots = %v", hdr.RCode)
	}
}

func TestServeDropsQueriesWhenHandlerLimitIsFull(t *testing.T) {
	z := NewZone("")
	z.Rebuild(testNode("laptop", "alice", "100.64.0.1"), nil)
	srv, err := NewServer(z, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	for range cap(srv.serveSlots) {
		srv.serveSlots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := net.Dial("udp", srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := conn.Write(buildQuery(t, "laptop.alice.ratelmesh.net.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 512)); err == nil {
		t.Fatalf("saturated server unexpectedly answered %d bytes", n)
	}
	if got := len(srv.serveSlots); got != cap(srv.serveSlots) {
		t.Fatalf("handler slots changed under saturation: got %d want %d", got, cap(srv.serveSlots))
	}
}

func startSelectiveUpstream(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	slowSeen := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			go func() {
				var p dnsmessage.Parser
				hdr, err := p.Start(query)
				if err != nil {
					return
				}
				q, err := p.Question()
				if err != nil {
					return
				}
				if q.Name.String() == "slow.example." {
					select {
					case slowSeen <- struct{}{}:
					default:
					}
					return // simulate a filtered query that never receives a reply
				}
				b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RecursionAvailable: true})
				_ = b.StartQuestions()
				_ = b.Question(q)
				_ = b.StartAnswers()
				_ = b.AResource(
					dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.AResource{A: netip.MustParseAddr("203.0.113.8").As4()},
				)
				msg, _ := b.Finish()
				_, _ = conn.WriteToUDP(msg, from)
			}()
		}
	}()
	return conn.LocalAddr().String(), slowSeen
}
