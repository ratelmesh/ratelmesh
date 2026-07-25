//go:build wgreal

package wgengine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/shan25519/ratelmesh/internal/magicsock"
	"golang.zx2c4.com/wireguard/conn"
)

// stunBind wraps wireguard-go's real UDP bind. STUN packets use the exact same
// socket and NAT mapping as WireGuard; responses are intercepted before the WG
// packet parser sees them. One outstanding discovery is enough because the
// mapping belongs to the shared bind, not to a peer.
type stunBind struct {
	base conn.Bind

	discoverMu sync.Mutex
	mu         sync.Mutex
	wait       *stunWait
	probes     map[[8]byte]*endpointProbeWait
}

type stunWait struct {
	tx magicsock.TxID
	ch chan netip.AddrPort
}

type endpointProbeWait struct {
	target netip.AddrPort
	ch     chan struct{}
}

func newSTUNBind(base conn.Bind) *stunBind {
	return &stunBind{base: base, probes: make(map[[8]byte]*endpointProbeWait)}
}

func (b *stunBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.base.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, receive := range fns {
		wrapped[i] = b.wrapReceive(receive)
	}
	return wrapped, actual, nil
}

func (b *stunBind) wrapReceive(receive conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := receive(packets, sizes, eps)
		if err != nil {
			return n, err
		}
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			packet := packets[i][:sizes[i]]
			b.mu.Lock()
			wait := b.wait
			b.mu.Unlock()
			if wait != nil {
				if mapped, parseErr := magicsock.ParseBindingResponse(packet, wait.tx); parseErr == nil {
					sizes[i] = 0
					select {
					case wait.ch <- mapped:
					default:
					}
					continue
				}
			}
			ping, pong, nonce, disco := magicsock.DecodeDisco(packet)
			if !disco {
				continue
			}
			// Disco packets are control traffic for path establishment, not
			// WireGuard packets. Always consume them before the device parser.
			sizes[i] = 0
			if ping && eps[i] != nil {
				_ = b.base.Send([][]byte{magicsock.EncodeDiscoPong(nonce)}, eps[i])
				continue
			}
			if pong && eps[i] != nil {
				from, parseErr := netip.ParseAddrPort(eps[i].DstToString())
				b.mu.Lock()
				probe := b.probes[nonce]
				b.mu.Unlock()
				if parseErr == nil && probe != nil && from == probe.target {
					select {
					case probe.ch <- struct{}{}:
					default:
					}
				}
			}
		}
		return n, nil
	}
}

func (b *stunBind) Discover(ctx context.Context, stunAddr string) (netip.AddrPort, error) {
	b.discoverMu.Lock()
	defer b.discoverMu.Unlock()
	tx, err := magicsock.NewTxID()
	if err != nil {
		return netip.AddrPort{}, err
	}
	resolved, err := resolveSTUNEndpoint(ctx, stunAddr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ep, err := b.base.ParseEndpoint(resolved.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse STUN endpoint: %w", err)
	}
	wait := &stunWait{tx: tx, ch: make(chan netip.AddrPort, 1)}
	b.mu.Lock()
	b.wait = wait
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if b.wait == wait {
			b.wait = nil
		}
		b.mu.Unlock()
	}()
	if err := b.base.Send([][]byte{magicsock.EncodeBindingRequest(tx)}, ep); err != nil {
		return netip.AddrPort{}, fmt.Errorf("send STUN request: %w", err)
	}
	select {
	case mapped := <-wait.ch:
		return mapped, nil
	case <-ctx.Done():
		return netip.AddrPort{}, fmt.Errorf("STUN discovery: %w", ctx.Err())
	}
}

// Probe checks a peer candidate through WireGuard's persistent socket. It
// retransmits while waiting because the first packet commonly creates the NAT
// permission that allows the peer's simultaneous probe or pong back through.
func (b *stunBind) Probe(ctx context.Context, target netip.AddrPort) error {
	if !target.IsValid() {
		return fmt.Errorf("probe endpoint is invalid")
	}
	ep, err := b.base.ParseEndpoint(target.String())
	if err != nil {
		return fmt.Errorf("parse probe endpoint: %w", err)
	}
	nonce, err := magicsock.NewDiscoNonce()
	if err != nil {
		return fmt.Errorf("create probe nonce: %w", err)
	}
	wait := &endpointProbeWait{target: target, ch: make(chan struct{}, 1)}
	b.mu.Lock()
	b.probes[nonce] = wait
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.probes, nonce)
		b.mu.Unlock()
	}()

	packet := magicsock.EncodeDiscoPing(nonce)
	retry := time.NewTicker(200 * time.Millisecond)
	defer retry.Stop()
	for {
		if err := b.base.Send([][]byte{packet}, ep); err != nil {
			return fmt.Errorf("send endpoint probe: %w", err)
		}
		select {
		case <-wait.ch:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("endpoint probe: %w", ctx.Err())
		case <-retry.C:
		}
	}
}

// wireguard-go's standard Bind deliberately accepts numeric endpoints only.
// Resolve a configured hostname here before handing it to ParseEndpoint. Prefer
// IPv4 because this discovery is primarily used to learn an IPv4 NAT mapping;
// fall back to IPv6-only networks when no IPv4 answer exists.
func resolveSTUNEndpoint(ctx context.Context, addr string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap, nil
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse STUN address: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("parse STUN port %q", portText)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve STUN host %q: %w", host, err)
	}
	for _, ip := range addrs {
		if ip.Is4() {
			return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
		}
	}
	for _, ip := range addrs {
		if ip.Is6() {
			return netip.AddrPortFrom(ip, uint16(port)), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("resolve STUN host %q: no IP addresses", host)
}

func (b *stunBind) Close() error                                  { return b.base.Close() }
func (b *stunBind) SetMark(mark uint32) error                     { return b.base.SetMark(mark) }
func (b *stunBind) Send(bufs [][]byte, ep conn.Endpoint) error    { return b.base.Send(bufs, ep) }
func (b *stunBind) ParseEndpoint(s string) (conn.Endpoint, error) { return b.base.ParseEndpoint(s) }
func (b *stunBind) BatchSize() int                                { return b.base.BatchSize() }

var _ conn.Bind = (*stunBind)(nil)
