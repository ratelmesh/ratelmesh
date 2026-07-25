package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/shan25519/ratelmesh/internal/types"
	"golang.org/x/net/dns/dnsmessage"
)

func testNode(name, user, ip string) types.Node {
	return types.Node{Name: name, User: user, MeshIPs: []netip.Addr{netip.MustParseAddr(ip)}}
}

func TestZoneRebuildAndLookup(t *testing.T) {
	z := NewZone("")
	z.Rebuild(
		testNode("laptop", "alice", "100.64.0.1"),
		[]types.Node{testNode("Phone Pro", "alice", "100.64.0.2")},
	)

	if ip, ok := z.LookupA("laptop.alice.ratelmesh.net"); !ok || ip.String() != "100.64.0.1" {
		t.Fatalf("laptop lookup = %v,%v", ip, ok)
	}
	// Name sanitization: "Phone Pro" -> "phone-pro".
	if ip, ok := z.LookupA("phone-pro.alice.ratelmesh.net."); !ok || ip.String() != "100.64.0.2" {
		t.Fatalf("phone lookup = %v,%v", ip, ok)
	}
	if _, ok := z.LookupA("nope.alice.ratelmesh.net"); ok {
		t.Fatal("unknown name should not resolve")
	}
}

func TestFQDNBoundsAndDisambiguatesLongIdentityLabels(t *testing.T) {
	z := NewZone("")
	prefix := strings.Repeat("very-long-identity-", 5)
	first := z.FQDN("laptop", prefix+"alice@example.com")
	second := z.FQDN("laptop", prefix+"bob@example.com")
	firstUser := strings.Split(first, ".")[1]
	secondUser := strings.Split(second, ".")[1]
	if len(firstUser) > 63 || len(secondUser) > 63 {
		t.Fatalf("long identity labels = %d, %d", len(firstUser), len(secondUser))
	}
	if firstUser == secondUser {
		t.Fatalf("long identities collided at %q", firstUser)
	}
	z.Rebuild(testNode("laptop", prefix+"alice@example.com", "100.64.0.1"), nil)
	if ip, ok := z.LookupA(first); !ok || ip.String() != "100.64.0.1" {
		t.Fatalf("bounded long-identity lookup = %v,%v name=%q", ip, ok, first)
	}
}

func TestInZone(t *testing.T) {
	z := NewZone("ratelmesh.net")
	if !z.InZone("x.alice.ratelmesh.net") {
		t.Error("name under suffix should be in zone")
	}
	if z.InZone("example.com") {
		t.Error("foreign name should not be in zone")
	}
}

func TestServerAnswersAQuery(t *testing.T) {
	z := NewZone("")
	z.Rebuild(testNode("laptop", "alice", "100.64.0.1"), nil)

	srv, err := NewServer(z, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	ip := queryA(t, srv.LocalAddr().String(), "laptop.alice.ratelmesh.net.")
	if ip != "100.64.0.1" {
		t.Fatalf("resolved %q, want 100.64.0.1", ip)
	}
}

func TestServerNXDOMAIN(t *testing.T) {
	z := NewZone("")
	srv, _ := NewServer(z, "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	rcode := queryRCode(t, srv.LocalAddr().String(), "ghost.alice.ratelmesh.net.")
	if rcode != dnsmessage.RCodeNameError {
		t.Fatalf("rcode = %v, want NXDOMAIN", rcode)
	}
}

// TestKnownNameWrongTypeIsNOERROR verifies an existing IPv4-only peer returns
// NOERROR (not NXDOMAIN) for an AAAA query, so stub resolvers don't fail the
// whole lookup.
func TestKnownNameWrongTypeIsNOERROR(t *testing.T) {
	z := NewZone("")
	z.Rebuild(testNode("laptop", "alice", "100.64.0.1"), nil) // IPv4 only
	srv, _ := NewServer(z, "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	resp := roundTrip(t, srv.LocalAddr().String(), buildQuery(t, "laptop.alice.ratelmesh.net.", dnsmessage.TypeAAAA))
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("AAAA of IPv4-only name = %v, want NOERROR", hdr.RCode)
	}
}

// TestServerForwardsOutOfZone verifies that a name outside the mesh zone is
// forwarded to an upstream resolver (so the server can own resolv.conf without
// breaking normal DNS), while a mesh name is still answered locally.
func TestServerForwardsOutOfZone(t *testing.T) {
	// A fake upstream that answers any A query with 203.0.113.7.
	upstream := startFakeUpstream(t, "203.0.113.7")

	z := NewZone("")
	z.Rebuild(testNode("laptop", "alice", "100.64.0.1"), nil)
	srv, err := NewServer(z, "127.0.0.1:0", upstream)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	// Mesh name: answered locally.
	if ip := queryA(t, srv.LocalAddr().String(), "laptop.alice.ratelmesh.net."); ip != "100.64.0.1" {
		t.Errorf("mesh name = %q, want 100.64.0.1", ip)
	}
	// Public name: forwarded to the upstream, which answers 203.0.113.7.
	if ip := queryA(t, srv.LocalAddr().String(), "www.example.com."); ip != "203.0.113.7" {
		t.Errorf("forwarded name = %q, want 203.0.113.7 (from upstream)", ip)
	}
}

// startFakeUpstream runs a UDP DNS server that answers every A query with ip.
func startFakeUpstream(t *testing.T, ip string) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			hdr, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RecursionAvailable: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			_ = b.AResource(
				dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()},
			)
			msg, _ := b.Finish()
			_, _ = conn.WriteToUDP(msg, from)
		}
	}()
	return conn.LocalAddr().String()
}

// --- helpers: build a query, send it, parse the answer ---

func buildQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	dn, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dn, Type: typ, Class: dnsmessage.ClassINET})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func roundTrip(t *testing.T, server string, query []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func queryA(t *testing.T, server, name string) string {
	resp := roundTrip(t, server, buildQuery(t, name, dnsmessage.TypeA))
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		t.Fatal(err)
	}
	_ = p.SkipAllQuestions()
	ans, err := p.Answer()
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	a, ok := ans.Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer not A: %T", ans.Body)
	}
	return netip.AddrFrom4(a.A).String()
}

func queryRCode(t *testing.T, server, name string) dnsmessage.RCode {
	resp := roundTrip(t, server, buildQuery(t, name, dnsmessage.TypeA))
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	return hdr.RCode
}
