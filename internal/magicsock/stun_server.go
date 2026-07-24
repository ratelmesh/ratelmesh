package magicsock

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

// STUNServer is a minimal STUN server: it answers Binding requests with the
// sender's reflexive address. RatelMesh can run this alongside relays so clients
// discover their public endpoint without depending on third-party STUN.
type STUNServer struct {
	conn    *net.UDPConn
	mu      sync.Mutex
	sources map[netip.Addr]stunRate
}

type stunRate struct {
	window time.Time
	count  int
}

// ListenSTUN starts a STUN server on addr (host:port, UDP).
func ListenSTUN(addr string) (*STUNServer, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, err
	}
	return &STUNServer{conn: conn, sources: make(map[netip.Addr]stunRate)}, nil
}

// LocalAddr returns the bound address.
func (s *STUNServer) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// Serve processes requests until ctx is cancelled or the socket closes.
func (s *STUNServer) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.conn.Close()
	}()
	buf := make([]byte, 1280)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		tx, ok := parseRequestTx(buf[:n])
		if !ok || !s.allow(from.AddrPort().Addr().Unmap(), time.Now()) {
			continue
		}
		ap := from.AddrPort()
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		_, _ = s.conn.WriteToUDP(EncodeBindingResponse(tx, ap), from)
	}
}

const (
	maxSTUNSources      = 4096
	maxSTUNPerSource    = 30
	stunRateLimitWindow = time.Second
)

func (s *STUNServer) allow(source netip.Addr, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rate, known := s.sources[source]
	if !known {
		if len(s.sources) >= maxSTUNSources {
			for addr, candidate := range s.sources {
				if now.Sub(candidate.window) >= stunRateLimitWindow {
					delete(s.sources, addr)
				}
			}
		}
		if len(s.sources) >= maxSTUNSources {
			return false
		}
		rate.window = now
	}
	if now.Sub(rate.window) >= stunRateLimitWindow {
		rate = stunRate{window: now}
	}
	if rate.count >= maxSTUNPerSource {
		return false
	}
	rate.count++
	s.sources[source] = rate
	return true
}

// Close stops the server.
func (s *STUNServer) Close() error { return s.conn.Close() }

func parseRequestTx(buf []byte) (TxID, bool) {
	if len(buf) < stunHeaderLen {
		return TxID{}, false
	}
	if int(buf[0])<<8|int(buf[1]) != stunBindingRequest {
		return TxID{}, false
	}
	if binary.BigEndian.Uint32(buf[4:8]) != stunMagicCookie || int(binary.BigEndian.Uint16(buf[2:4])) != len(buf)-stunHeaderLen {
		return TxID{}, false
	}
	var tx TxID
	copy(tx[:], buf[8:20])
	return tx, true
}
