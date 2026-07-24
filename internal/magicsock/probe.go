package magicsock

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Disco is the tiny out-of-band protocol used to hole-punch and confirm a
// direct path to a peer (DESIGN.md §3.2): both sides send ping probes to each
// other's candidate endpoints; a returned pong proves bidirectional
// reachability, at which point the path upgrades from relay to direct.

var discoMagic = [8]byte{'H', 'B', 'M', 'D', 'I', 'S', 'C', 'O'}

const (
	discoPing byte = 1
	discoPong byte = 2
	discoLen       = 8 + 1 + 8 // magic + type + nonce
)

func encodeDisco(t byte, nonce [8]byte) []byte {
	b := make([]byte, discoLen)
	copy(b[0:8], discoMagic[:])
	b[8] = t
	copy(b[9:17], nonce[:])
	return b
}

func decodeDisco(b []byte) (typ byte, nonce [8]byte, ok bool) {
	if len(b) < discoLen {
		return 0, nonce, false
	}
	if [8]byte(b[0:8]) != discoMagic {
		return 0, nonce, false
	}
	copy(nonce[:], b[9:17])
	return b[8], nonce, true
}

// NewDiscoNonce returns a cryptographically-random nonce for an endpoint
// reachability check. It is exported so a WireGuard Bind can multiplex disco
// packets on the exact UDP socket that owns the peer's NAT mapping.
func NewDiscoNonce() ([8]byte, error) {
	var nonce [8]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}

// EncodeDiscoPing and EncodeDiscoPong build the tiny reachability packets used
// by both the standalone responder and a WireGuard-socket multiplexer.
func EncodeDiscoPing(nonce [8]byte) []byte { return encodeDisco(discoPing, nonce) }
func EncodeDiscoPong(nonce [8]byte) []byte { return encodeDisco(discoPong, nonce) }

// DecodeDisco classifies a reachability packet. ping and pong are mutually
// exclusive; ok is false for ordinary WireGuard/STUN traffic.
func DecodeDisco(b []byte) (ping, pong bool, nonce [8]byte, ok bool) {
	typ, nonce, ok := decodeDisco(b)
	if !ok {
		return false, false, nonce, false
	}
	return typ == discoPing, typ == discoPong, nonce, true
}

// DiscoResponder listens on a UDP socket and answers disco pings with pongs.
// Each peer runs one so others can confirm a direct path to it.
type DiscoResponder struct {
	conn *net.UDPConn
}

// ListenDisco binds a disco responder. Pass ":0" for an ephemeral port.
func ListenDisco(addr string) (*DiscoResponder, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, err
	}
	return NewDiscoResponder(conn), nil
}

// NewDiscoResponder wraps an already-bound UDP conn as a disco responder, so the
// caller can operate on the socket first (e.g. STUN it) before Serve starts
// reading. The responder takes ownership: Serve/Close manage the conn.
func NewDiscoResponder(conn *net.UDPConn) *DiscoResponder {
	return &DiscoResponder{conn: conn}
}

// STUNConn performs a STUN binding request/response on an EXISTING UDP conn to
// discover its reflexive (NAT-mapped) address. Unlike DiscoverReflexive (which
// dials its own ephemeral socket), this maps the port of the passed conn — so a
// disco socket learns its own external mapping, not a different one. Must be
// called before a DiscoResponder starts reading the same conn (single reader).
// The read deadline is cleared before returning so a subsequent Serve can block.
func STUNConn(ctx context.Context, conn *net.UDPConn, stunAddr string) (netip.AddrPort, error) {
	raddr, err := net.ResolveUDPAddr("udp", stunAddr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	tx, err := NewTxID()
	if err != nil {
		return netip.AddrPort{}, err
	}
	deadline := time.Now().Add(3 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{}) // let a later Serve block-read
	if _, err := conn.WriteToUDP(EncodeBindingRequest(tx), raddr); err != nil {
		return netip.AddrPort{}, err
	}
	buf := make([]byte, 1280)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("magicsock: STUN read: %w", err)
		}
		// Ignore non-STUN traffic (e.g. a stray disco ping) until our response.
		if ap, perr := ParseBindingResponse(buf[:n], tx); perr == nil {
			return ap, nil
		}
	}
}

// LocalAddr returns the bound address.
func (d *DiscoResponder) LocalAddr() netip.AddrPort {
	return d.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Serve answers pings until ctx is cancelled.
func (d *DiscoResponder) Serve(ctx context.Context) error {
	go func() { <-ctx.Done(); d.conn.Close() }()
	buf := make([]byte, 64)
	for {
		n, from, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		typ, nonce, ok := decodeDisco(buf[:n])
		if !ok || typ != discoPing {
			continue
		}
		_, _ = d.conn.WriteToUDP(encodeDisco(discoPong, nonce), from)
	}
}

// Close stops the responder.
func (d *DiscoResponder) Close() error { return d.conn.Close() }

// Probe sends a disco ping to candidate and waits for a matching pong, proving a
// direct path is usable. Returns nil on success.
func Probe(ctx context.Context, candidate netip.AddrPort, timeout time.Duration) error {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(candidate))
	if err != nil {
		return err
	}
	defer conn.Close()

	nonce, err := NewDiscoNonce()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(EncodeDiscoPing(nonce)); err != nil {
		return err
	}
	buf := make([]byte, 64)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		typ, got, ok := decodeDisco(buf[:n])
		if ok && typ == discoPong && got == nonce {
			return nil
		}
	}
}

var errNoDirectPath = errors.New("magicsock: no direct path confirmed")

// ProbeAll tries each candidate in order and returns the first that answers,
// upgrading the PeerPath to direct. Returns errNoDirectPath if none succeed.
func ProbeAll(ctx context.Context, pp *PeerPath, timeout time.Duration) (netip.AddrPort, error) {
	for _, c := range pp.Candidates() {
		if err := Probe(ctx, c, timeout); err == nil {
			pp.ConfirmDirect(c)
			return c, nil
		}
	}
	return netip.AddrPort{}, errNoDirectPath
}
