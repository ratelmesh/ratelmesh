package dns

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Server is the MagicDNS resolver. It answers names in its Zone
// (device.user.ratelmesh.net) authoritatively from the mesh, and — when upstreams are
// configured — forwards every other query to a real resolver. That combination
// lets it safely take over the host's /etc/resolv.conf: mesh names resolve to
// peer mesh IPs, and normal DNS keeps working (DESIGN.md §3.1). With no upstream
// it stays authoritative-only (out-of-zone names return NXDOMAIN).
type Server struct {
	zone *Zone
	conn *net.UDPConn
	// serveSlots bounds all in-flight packet handlers, including malformed and
	// authoritative queries. querySlots below is a separate, smaller budget for
	// slow upstream waits, so mesh answers remain available during an upstream
	// flood without allowing a local/mesh UDP flood to spawn unbounded goroutines.
	serveSlots chan struct{}
	// querySlots bounds concurrent upstream waits. DNS clients routinely issue
	// A and AAAA (plus several hostnames) in parallel; processing them inline in
	// Serve caused one slow/blocked query to stall every resolver request behind
	// it, which surfaced as complete DNS failure on filtered networks.
	querySlots chan struct{}

	mu        sync.RWMutex
	upstreams []string // host:port resolvers for out-of-zone names
}

// NewServer binds a DNS server on addr (host:port, UDP) serving zone. Any
// upstreams (host:port) receive queries for names outside the zone.
func NewServer(zone *Zone, addr string, upstreams ...string) (*Server, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, err
	}
	return &Server{
		zone: zone, conn: conn,
		serveSlots: make(chan struct{}, 256),
		querySlots: make(chan struct{}, 64),
		upstreams:  upstreams,
	}, nil
}

// SetUpstreams atomically replaces the out-of-zone resolvers. The daemon uses
// this to force DNS through the tunnel resolver while an exit is active, so
// queries never leak to the local/ISP resolver (DESIGN.md §3.3).
func (s *Server) SetUpstreams(upstreams []string) {
	s.mu.Lock()
	s.upstreams = append([]string(nil), upstreams...)
	s.mu.Unlock()
}

func (s *Server) currentUpstreams() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.upstreams
}

// LocalAddr returns the bound address.
func (s *Server) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// Serve processes queries until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	go func() { <-ctx.Done(); s.conn.Close() }()
	buf := make([]byte, 512)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		select {
		case s.serveSlots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		default:
			// UDP permits loss under overload. Dropping here bounds memory and
			// goroutines while clients retry normally.
			continue
		}
		// Copy before dispatch: buf is reused by the next ReadFromUDP.
		q := make([]byte, n)
		copy(q, buf[:n])
		fromCopy := *from
		go func() {
			defer func() { <-s.serveSlots }()
			resp, err := s.respond(q)
			if err != nil {
				return
			}
			_, _ = s.conn.WriteToUDP(resp, &fromCopy)
		}()
	}
}

// Close stops the server.
func (s *Server) Close() error { return s.conn.Close() }

// respond builds a reply for a raw query message.
func (s *Server) respond(query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}

	name := q.Name.String()
	upstreams := s.currentUpstreams()

	// Out-of-zone names are forwarded to an upstream resolver when configured;
	// this is what lets the server own /etc/resolv.conf without breaking normal
	// DNS. Without an upstream we fall through to an authoritative NXDOMAIN.
	if !s.zone.InZone(name) && len(upstreams) > 0 {
		select {
		case s.querySlots <- struct{}{}:
			defer func() { <-s.querySlots }()
		default:
			// Bound concurrent upstream waits without starving authoritative
			// mesh answers, which never need an upstream slot.
			return servfail(query), nil
		}
		if resp, ok := s.forwardTo(upstreams, query); ok {
			return resp, nil
		}
		// Upstream failed: SERVFAIL rather than a wrong authoritative answer.
		return servfail(query), nil
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: len(upstreams) > 0,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}

	answered := false
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	switch q.Type {
	case dnsmessage.TypeA:
		if ip, ok := s.zone.LookupA(name); ok {
			_ = b.AResource(
				dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				dnsmessage.AResource{A: ip.As4()},
			)
			answered = true
		}
	case dnsmessage.TypeAAAA:
		if ip, ok := s.zone.LookupAAAA(name); ok {
			_ = b.AAAAResource(
				dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 300},
				dnsmessage.AAAAResource{AAAA: ip.As16()},
			)
			answered = true
		}
	}

	msg, err := b.Finish()
	if err != nil {
		return nil, err
	}
	// NXDOMAIN only when the name truly does not exist. A known name queried for
	// a type it lacks (e.g. AAAA of an IPv4-only peer) is NOERROR with no answer,
	// or musl/busybox resolvers fail the whole lookup.
	if !answered && !s.zone.Has(name) {
		setRCodeNameError(msg)
	}
	return msg, nil
}

// forwardTo relays a raw query to the first of the given upstreams that answers.
func (s *Server) forwardTo(upstreams []string, query []byte) ([]byte, bool) {
	for _, up := range upstreams {
		conn, err := net.Dial("udp", up)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			continue
		}
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		conn.Close()
		if err == nil && n > 0 {
			return buf[:n], true
		}
	}
	return nil, false
}

// setRCodeNameError sets the RCODE nibble of a DNS message header to NXDOMAIN(3).
func setRCodeNameError(msg []byte) {
	if len(msg) >= 4 {
		msg[3] = (msg[3] & 0xF0) | 0x03
	}
}

// servfail turns a query into a minimal SERVFAIL response (RCODE 2, QR set).
func servfail(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	if len(resp) >= 4 {
		resp[2] |= 0x80                   // QR = response
		resp[3] = (resp[3] & 0xF0) | 0x02 // RCODE = SERVFAIL
	}
	return resp
}
