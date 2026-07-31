package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
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
	zone        *Zone
	conn        *net.UDPConn
	tcpListener net.Listener
	// serveSlots bounds all in-flight packet handlers, including malformed and
	// authoritative queries. querySlots below is a separate, smaller budget for
	// slow upstream waits, so mesh answers remain available during an upstream
	// flood without allowing a local/mesh UDP flood to spawn unbounded goroutines.
	serveSlots chan struct{}
	// tcpSlots separately bounds long-lived DNS-over-TCP connections so a client
	// holding TCP sessions open cannot consume the UDP handler budget.
	tcpSlots chan struct{}
	// querySlots bounds concurrent upstream waits. DNS clients routinely issue
	// A and AAAA (plus several hostnames) in parallel; processing them inline in
	// Serve caused one slow/blocked query to stall every resolver request behind
	// it, which surfaced as complete DNS failure on filtered networks.
	querySlots chan struct{}

	mu        sync.RWMutex
	upstreams []string // host:port resolvers for out-of-zone names
}

const (
	maxDNSMessageSize     = 65535
	dnsIOTimeout          = 3 * time.Second
	maxEphemeralBindTries = 10
	temporaryAcceptDelay  = 10 * time.Millisecond
)

// NewServer binds a DNS server on addr (host:port, UDP and TCP) serving zone.
// Any upstreams (host:port) receive queries for names outside the zone.
func NewServer(zone *Zone, addr string, upstreams ...string) (*Server, error) {
	conn, tcpListener, err := listenDNS(addr, net.Listen)
	if err != nil {
		return nil, err
	}
	return &Server{
		zone:        zone,
		conn:        conn,
		tcpListener: tcpListener,
		serveSlots:  make(chan struct{}, 256),
		tcpSlots:    make(chan struct{}, 64),
		querySlots:  make(chan struct{}, 64),
		upstreams:   upstreams,
	}, nil
}

type tcpListenFunc func(network, address string) (net.Listener, error)

func listenDNS(addr string, listenTCP tcpListenFunc) (*net.UDPConn, net.Listener, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	attempts := 1
	if uaddr.Port == 0 {
		attempts = maxEphemeralBindTries
	}
	var tcpErr error
	for range attempts {
		conn, err := net.ListenUDP("udp", uaddr)
		if err != nil {
			return nil, nil, err
		}
		tcpListener, err := listenTCP("tcp", conn.LocalAddr().String())
		if err == nil {
			return conn, tcpListener, nil
		}
		_ = conn.Close()
		tcpErr = err
		if uaddr.Port != 0 || !errors.Is(err, syscall.EADDRINUSE) {
			return nil, nil, err
		}
	}
	return nil, nil, tcpErr
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
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make(chan error, 2)
	var handlers sync.WaitGroup
	go func() { errs <- s.serveUDP(serveCtx, &handlers) }()
	go func() { errs <- s.serveTCP(serveCtx, &handlers) }()

	stopWatcher := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-stopWatcher:
		}
	}()

	err := <-errs
	cancel()
	_ = s.Close()
	<-errs
	close(stopWatcher)
	<-watcherDone
	handlers.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (s *Server) serveUDP(ctx context.Context, handlers *sync.WaitGroup) error {
	buf := make([]byte, maxDNSMessageSize)
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
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() { <-s.serveSlots }()
			resp, err := s.respondContext(ctx, q)
			if err != nil {
				return
			}
			_, _ = s.conn.WriteToUDP(resp, &fromCopy)
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context, handlers *sync.WaitGroup) error {
	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(temporaryAcceptDelay):
					continue
				}
			}
			return err
		}
		select {
		case s.tcpSlots <- struct{}{}:
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { <-s.tcpSlots }()
				s.serveTCPConn(ctx, conn)
			}()
		case <-ctx.Done():
			_ = conn.Close()
			return ctx.Err()
		default:
			_ = conn.Close()
		}
	}
}

func (s *Server) serveTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	var sizeBuf [2]byte
	for {
		if err := conn.SetReadDeadline(time.Now().Add(dnsIOTimeout)); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(sizeBuf[:]))
		if size == 0 {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp, err := s.respondContext(ctx, query)
		if err != nil || len(resp) == 0 || len(resp) > maxDNSMessageSize {
			return
		}
		if err := conn.SetWriteDeadline(time.Now().Add(dnsIOTimeout)); err != nil {
			return
		}
		binary.BigEndian.PutUint16(sizeBuf[:], uint16(len(resp)))
		if err := writeAll(conn, sizeBuf[:]); err != nil {
			return
		}
		if err := writeAll(conn, resp); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// Close stops the server.
func (s *Server) Close() error {
	udpErr := s.conn.Close()
	tcpErr := s.tcpListener.Close()
	if udpErr != nil {
		return udpErr
	}
	return tcpErr
}

// respond builds a reply for a raw query message.
func (s *Server) respond(query []byte) ([]byte, error) {
	return s.respondContext(context.Background(), query)
}

func (s *Server) respondContext(ctx context.Context, query []byte) ([]byte, error) {
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
		if resp, ok := s.forwardTo(ctx, upstreams, query); ok {
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
func (s *Server) forwardTo(ctx context.Context, upstreams []string, query []byte) ([]byte, bool) {
	dialer := net.Dialer{Timeout: dnsIOTimeout}
	for _, up := range upstreams {
		conn, err := dialer.DialContext(ctx, "udp", up)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(dnsIOTimeout))
		stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
		if _, err := conn.Write(query); err != nil {
			stopCancel()
			_ = conn.Close()
			continue
		}
		buf := make([]byte, maxDNSMessageSize)
		n, err := conn.Read(buf)
		stopCancel()
		_ = conn.Close()
		if err != nil || n == 0 {
			continue
		}
		resp := buf[:n]
		truncated, ok := matchingResponse(query, resp)
		if !ok {
			continue
		}
		if !truncated {
			return resp, true
		}
		if resp, ok := forwardTCP(ctx, up, query); ok {
			if _, matches := matchingResponse(query, resp); matches {
				return resp, true
			}
		}
	}
	return nil, false
}

func forwardTCP(ctx context.Context, upstream string, query []byte) ([]byte, bool) {
	if len(query) == 0 || len(query) > maxDNSMessageSize {
		return nil, false
	}
	dialer := net.Dialer{Timeout: dnsIOTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsIOTimeout))
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	var sizeBuf [2]byte
	binary.BigEndian.PutUint16(sizeBuf[:], uint16(len(query)))
	if err := writeAll(conn, sizeBuf[:]); err != nil {
		return nil, false
	}
	if err := writeAll(conn, query); err != nil {
		return nil, false
	}
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		return nil, false
	}
	size := int(binary.BigEndian.Uint16(sizeBuf[:]))
	if size == 0 {
		return nil, false
	}
	resp := make([]byte, size)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, false
	}
	return resp, true
}

func matchingResponse(query, response []byte) (truncated, ok bool) {
	if len(query) < 2 {
		return false, false
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(response)
	if err != nil || !hdr.Response || hdr.ID != binary.BigEndian.Uint16(query[:2]) {
		return false, false
	}
	return hdr.Truncated, true
}

func writeAll(conn net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		buf = buf[n:]
	}
	return nil
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
