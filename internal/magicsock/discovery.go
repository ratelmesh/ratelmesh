package magicsock

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// DiscoverReflexive sends a STUN Binding request to stunAddr over a UDP socket
// and returns the public (server-reflexive) ip:port the STUN server observed.
// This is one candidate endpoint; local interface addresses are the others.
func DiscoverReflexive(ctx context.Context, stunAddr string) (netip.AddrPort, error) {
	raddr, err := net.ResolveUDPAddr("udp", stunAddr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer conn.Close()

	tx, err := NewTxID()
	if err != nil {
		return netip.AddrPort{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	}

	if _, err := conn.Write(EncodeBindingRequest(tx)); err != nil {
		return netip.AddrPort{}, err
	}
	buf := make([]byte, 1280)
	n, err := conn.Read(buf)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("magicsock: STUN read: %w", err)
	}
	return ParseBindingResponse(buf[:n], tx)
}

// DiscoverReflexiveFromPort learns the NAT mapping created for a specific UDP
// source port. It is used immediately before kernel WireGuard opens the same
// port on Linux/Windows, where STUN cannot share the live kernel socket. Common
// cone and restricted NATs preserve/reuse this mapping when WireGuard takes
// over; symmetric NATs may still require a relay.
func DiscoverReflexiveFromPort(ctx context.Context, listenPort uint16, stunAddr string) (netip.AddrPort, error) {
	if listenPort == 0 {
		return netip.AddrPort{}, fmt.Errorf("magicsock: stable listen port is required")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(listenPort)})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("magicsock: bind discovery port %d: %w", listenPort, err)
	}
	defer conn.Close()
	return STUNConn(ctx, conn, stunAddr)
}

// GatherEndpoints assembles this host's candidate endpoints: every non-loopback
// local address at listenPort, plus (if reachable) the STUN reflexive address.
// Duplicates are removed; order is local-first (cheapest to try).
func GatherEndpoints(ctx context.Context, listenPort uint16, stunAddr string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ap netip.AddrPort) {
		s := ap.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			add(netip.AddrPortFrom(ip, listenPort))
		}
	}

	if stunAddr != "" {
		if reflexive, err := DiscoverReflexive(ctx, stunAddr); err == nil {
			add(reflexive)
		}
	}
	return out
}
