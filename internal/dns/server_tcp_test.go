package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestEphemeralDNSBindRetriesCrossProtocolCollision(t *testing.T) {
	attempts := 0
	listenTCP := func(network, address string) (net.Listener, error) {
		attempts++
		if attempts == 1 {
			return nil, syscall.EADDRINUSE
		}
		return net.Listen(network, address)
	}

	conn, listener, err := listenDNS("127.0.0.1:0", listenTCP)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer listener.Close()
	if attempts != 2 {
		t.Fatalf("TCP bind attempts = %d, want 2", attempts)
	}
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("UDP address type = %T, want *net.UDPAddr", conn.LocalAddr())
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("TCP address type = %T, want *net.TCPAddr", listener.Addr())
	}
	if udpAddr.Port != tcpAddr.Port {
		t.Fatalf("dual-protocol ports = UDP %d / TCP %d, want equal", udpAddr.Port, tcpAddr.Port)
	}
}

func TestEphemeralDNSBindCapsAddressInUseRetries(t *testing.T) {
	attempts := 0
	_, _, err := listenDNS("127.0.0.1:0", func(_, _ string) (net.Listener, error) {
		attempts++
		return nil, syscall.EADDRINUSE
	})
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("ephemeral bind error = %v, want EADDRINUSE", err)
	}
	if attempts != maxEphemeralBindTries {
		t.Fatalf("TCP bind attempts = %d, want %d", attempts, maxEphemeralBindTries)
	}
}

func TestEphemeralDNSBindDoesNotRetryOtherErrors(t *testing.T) {
	sentinel := errors.New("TCP unavailable")
	attempts := 0
	_, _, err := listenDNS("127.0.0.1:0", func(_, _ string) (net.Listener, error) {
		attempts++
		return nil, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("ephemeral bind error = %v, want sentinel", err)
	}
	if attempts != 1 {
		t.Fatalf("TCP bind attempts = %d, want 1", attempts)
	}
}

func TestServerAnswersTCPQuery(t *testing.T) {
	z := NewZone("")
	z.Rebuild(testNode("laptop", "alice", "100.64.0.1"), nil)
	srv, err := NewServer(z, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	resp := roundTripTCP(t, srv.LocalAddr().String(), buildQuery(t, "laptop.alice.ratelmesh.net.", dnsmessage.TypeA))
	if ip := answerA(t, resp); ip != "100.64.0.1" {
		t.Fatalf("TCP mesh answer = %q, want 100.64.0.1", ip)
	}
}

func TestForwardRetriesTruncatedUDPOverTCP(t *testing.T) {
	upstream, tcpSeen := startTruncatingUpstream(t, "203.0.113.17")
	srv, err := NewServer(NewZone(""), "127.0.0.1:0", upstream)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	if ip := queryA(t, srv.LocalAddr().String(), "rr.youtube.com."); ip != "203.0.113.17" {
		t.Fatalf("truncated fallback answer = %q, want 203.0.113.17", ip)
	}
	select {
	case <-tcpSeen:
	case <-time.After(time.Second):
		t.Fatal("truncated UDP response did not trigger TCP fallback")
	}
}

func TestForwardPreservesLargeUDPResponse(t *testing.T) {
	upstream := startLargeUDPUpstream(t, "203.0.113.18")
	srv, err := NewServer(NewZone(""), "127.0.0.1:0", upstream)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	resp := roundTripUDPFull(t, srv.LocalAddr().String(), buildQuery(t, "media.youtube.com.", dnsmessage.TypeA))
	if len(resp) <= 1500 {
		t.Fatalf("forwarded response length = %d, want >1500", len(resp))
	}
	if ip := answerA(t, resp); ip != "203.0.113.18" {
		t.Fatalf("large UDP answer = %q, want 203.0.113.18", ip)
	}
}

func TestTCPClientDeadlineStartsAfterUpstreamFallback(t *testing.T) {
	const phaseDelay = 1600 * time.Millisecond
	upstream, tcpSeen := startDelayedTruncatingUpstream(t, "203.0.113.19", phaseDelay, phaseDelay)
	srv, err := NewServer(NewZone(""), "127.0.0.1:0", upstream)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	resp := roundTripTCPWithTimeout(
		t,
		srv.LocalAddr().String(),
		buildQuery(t, "slow-media.youtube.com.", dnsmessage.TypeA),
		8*time.Second,
	)
	if ip := answerA(t, resp); ip != "203.0.113.19" {
		t.Fatalf("slow fallback answer = %q, want 203.0.113.19", ip)
	}
	select {
	case <-tcpSeen:
	case <-time.After(time.Second):
		t.Fatal("slow truncated response did not use TCP upstream")
	}
}

func TestServeWaitsForTCPHandlersOnCancel(t *testing.T) {
	upstream, querySeen := startBlockingUDPUpstream(t)
	srv, err := NewServer(NewZone(""), "127.0.0.1:0", upstream)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx) }()

	conn, err := net.DialTimeout("tcp", srv.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := buildQuery(t, "blocked.example.", dnsmessage.TypeA)
	var sizeBuf [2]byte
	binary.BigEndian.PutUint16(sizeBuf[:], uint16(len(query)))
	if err := writeAll(conn, sizeBuf[:]); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(conn, query); err != nil {
		t.Fatal(err)
	}
	select {
	case <-querySeen:
	case <-time.After(time.Second):
		t.Fatal("TCP query never reached blocking upstream")
	}

	cancel()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("Serve did not wait for and cancel its TCP handler")
	}
	if got := len(srv.tcpSlots); got != 0 {
		t.Fatalf("TCP slots after Serve returned = %d, want 0", got)
	}
}

func TestTemporaryTCPAcceptErrorDoesNotStopDNS(t *testing.T) {
	z := NewZone("")
	z.Rebuild(testNode("laptop", "alice", "100.64.0.1"), nil)
	srv, err := NewServer(z, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.tcpListener = &temporaryOnceListener{Listener: srv.tcpListener}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	resp := roundTripTCP(t, srv.LocalAddr().String(), buildQuery(t, "laptop.alice.ratelmesh.net.", dnsmessage.TypeA))
	if ip := answerA(t, resp); ip != "100.64.0.1" {
		t.Fatalf("answer after temporary Accept error = %q, want 100.64.0.1", ip)
	}
}

func roundTripTCP(t *testing.T, server string, query []byte) []byte {
	return roundTripTCPWithTimeout(t, server, query, 2*time.Second)
}

func roundTripTCPWithTimeout(t *testing.T, server string, query []byte, timeout time.Duration) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", server, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var sizeBuf [2]byte
	binary.BigEndian.PutUint16(sizeBuf[:], uint16(len(query)))
	if err := writeAll(conn, sizeBuf[:]); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(conn, query); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, int(binary.BigEndian.Uint16(sizeBuf[:])))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func roundTripUDPFull(t *testing.T, server string, query []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("udp", server, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxDNSMessageSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func answerA(t *testing.T, response []byte) string {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(response); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	ans, err := p.Answer()
	if err != nil {
		t.Fatal(err)
	}
	a, ok := ans.Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer type = %T, want A", ans.Body)
	}
	return netip.AddrFrom4(a.A).String()
}

func startTruncatingUpstream(t *testing.T, ip string) (string, <-chan struct{}) {
	return startDelayedTruncatingUpstream(t, ip, 0, 0)
}

func startDelayedTruncatingUpstream(
	t *testing.T,
	ip string,
	udpDelay time.Duration,
	tcpDelay time.Duration,
) (string, <-chan struct{}) {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = udp.Close()
		_ = tcp.Close()
	})

	go func() {
		buf := make([]byte, maxDNSMessageSize)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := append([]byte(nil), buf[:n]...)
			if len(resp) >= 4 {
				resp[2] |= 0x82 // QR + TC
			}
			time.Sleep(udpDelay)
			_, _ = udp.WriteToUDP(resp, from)
		}
	}()

	tcpSeen := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var sizeBuf [2]byte
				if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
					return
				}
				query := make([]byte, int(binary.BigEndian.Uint16(sizeBuf[:])))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				resp, err := buildPaddedAResponse(query, ip, 0)
				if err != nil {
					return
				}
				time.Sleep(tcpDelay)
				select {
				case tcpSeen <- struct{}{}:
				default:
				}
				binary.BigEndian.PutUint16(sizeBuf[:], uint16(len(resp)))
				_ = writeAll(conn, sizeBuf[:])
				_ = writeAll(conn, resp)
			}()
		}
	}()
	return udp.LocalAddr().String(), tcpSeen
}

func startBlockingUDPUpstream(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	querySeen := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, maxDNSMessageSize)
		for {
			if _, _, err := conn.ReadFromUDP(buf); err != nil {
				return
			}
			select {
			case querySeen <- struct{}{}:
			default:
			}
		}
	}()
	return conn.LocalAddr().String(), querySeen
}

type temporaryOnceListener struct {
	net.Listener
	failed bool
}

func (l *temporaryOnceListener) Accept() (net.Conn, error) {
	if !l.failed {
		l.failed = true
		return nil, temporaryAcceptError{}
	}
	return l.Listener.Accept()
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

func startLargeUDPUpstream(t *testing.T, ip string) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, maxDNSMessageSize)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp, err := buildPaddedAResponse(buf[:n], ip, 10)
			if err != nil {
				continue
			}
			_, _ = conn.WriteToUDP(resp, from)
		}
	}()
	return conn.LocalAddr().String()
}

func buildPaddedAResponse(query []byte, ip string, paddingRecords int) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		RecursionAvailable: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if err := b.AResource(
		dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
		dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()},
	); err != nil {
		return nil, err
	}
	padding := strings.Repeat("x", 200)
	for range paddingRecords {
		if err := b.TXTResource(
			dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.TXTResource{TXT: []string{padding}},
		); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}
