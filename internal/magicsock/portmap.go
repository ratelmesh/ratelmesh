package magicsock

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	portMapPort     = 5351
	portMapLifetime = 2 * time.Hour
)

// PortMapping is a best-effort UDP mapping created on the physical default
// gateway. External may be globally routable or an upstream RFC1918 address in
// a double-NAT layout; both are useful connectivity candidates.
type PortMapping struct {
	External     netip.AddrPort
	Gateway      netip.Addr
	InternalPort uint16
	Protocol     string
	Lifetime     time.Duration
}

// MapUDPPort asks the physical default gateway for a stable UDP mapping. PCP is
// preferred because it is the current standard; NAT-PMP remains a useful
// fallback on Apple and older consumer routers.
func MapUDPPort(ctx context.Context, internalPort uint16) (PortMapping, error) {
	if internalPort == 0 {
		return PortMapping{}, errors.New("magicsock: port mapping requires a stable internal port")
	}
	gateway, err := defaultGateway(ctx)
	if err != nil {
		return PortMapping{}, err
	}
	local, err := localAddressForGateway(gateway)
	if err != nil {
		return PortMapping{}, err
	}
	pcpCtx, pcpCancel := boundedAttempt(ctx, time.Second)
	mapped, pcpErr := mapPCP(pcpCtx, gateway, local, internalPort, uint32(portMapLifetime/time.Second))
	pcpCancel()
	if pcpErr == nil {
		return mapped, nil
	}
	if gateway.Is4() {
		pmpCtx, pmpCancel := boundedAttempt(ctx, time.Second)
		mapped, pmpErr := mapNATPMP(pmpCtx, gateway, internalPort, uint32(portMapLifetime/time.Second))
		pmpCancel()
		if pmpErr == nil {
			return mapped, nil
		}
	}
	if mapped, err := mapUPnP(ctx, gateway, local, internalPort, portMapLifetime); err == nil {
		return mapped, nil
	}
	return PortMapping{}, errors.New("magicsock: gateway supports none of PCP, NAT-PMP, or UPnP IGD UDP mapping")
}

func boundedAttempt(parent context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := parent.Deadline(); ok && time.Until(deadline) <= duration {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, duration)
}

func localAddressForGateway(gateway netip.Addr) (netip.Addr, error) {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(gateway, portMapPort)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("magicsock: resolve port-mapping interface: %w", err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	if !local.IsValid() || local.IsUnspecified() {
		return netip.Addr{}, errors.New("magicsock: port-mapping interface has no usable address")
	}
	return local, nil
}

func mapPCP(ctx context.Context, gateway, local netip.Addr, internalPort uint16, lifetime uint32) (PortMapping, error) {
	return mapPCPAt(ctx, netip.AddrPortFrom(gateway, portMapPort), local, internalPort, lifetime)
}

func mapPCPAt(ctx context.Context, service netip.AddrPort, local netip.Addr, internalPort uint16, lifetime uint32) (PortMapping, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return PortMapping{}, err
	}
	req := make([]byte, 60)
	req[0] = 2
	req[1] = 1 // MAP
	binary.BigEndian.PutUint32(req[4:8], lifetime)
	putPCPAddress(req[8:24], local)
	copy(req[24:36], nonce[:])
	req[36] = 17 // UDP
	binary.BigEndian.PutUint16(req[40:42], internalPort)
	binary.BigEndian.PutUint16(req[42:44], internalPort)

	resp, err := portMapExchange(ctx, service, req, 60)
	if err != nil {
		return PortMapping{}, fmt.Errorf("magicsock: PCP MAP: %w", err)
	}
	if resp[0] != 2 || resp[1] != 0x81 || resp[3] != 0 || !equalBytes(resp[24:36], nonce[:]) || resp[36] != 17 {
		return PortMapping{}, errors.New("magicsock: PCP MAP rejected or mismatched")
	}
	externalPort := binary.BigEndian.Uint16(resp[42:44])
	externalAddr, ok := parsePCPAddress(resp[44:60])
	if !ok || externalPort == 0 {
		return PortMapping{}, errors.New("magicsock: PCP returned an invalid external endpoint")
	}
	granted := binary.BigEndian.Uint32(resp[4:8])
	return PortMapping{
		External:     netip.AddrPortFrom(externalAddr, externalPort),
		Gateway:      service.Addr(),
		InternalPort: internalPort,
		Protocol:     "pcp",
		Lifetime:     time.Duration(granted) * time.Second,
	}, nil
}

func mapNATPMP(ctx context.Context, gateway netip.Addr, internalPort uint16, lifetime uint32) (PortMapping, error) {
	return mapNATPMPAt(ctx, netip.AddrPortFrom(gateway, portMapPort), internalPort, lifetime)
}

func mapNATPMPAt(ctx context.Context, service netip.AddrPort, internalPort uint16, lifetime uint32) (PortMapping, error) {
	publicResp, err := portMapExchange(ctx, service, []byte{0, 0}, 12)
	if err != nil {
		return PortMapping{}, fmt.Errorf("magicsock: NAT-PMP public address: %w", err)
	}
	if publicResp[0] != 0 || publicResp[1] != 128 || binary.BigEndian.Uint16(publicResp[2:4]) != 0 {
		return PortMapping{}, errors.New("magicsock: NAT-PMP public-address request rejected")
	}
	externalAddr := netip.AddrFrom4([4]byte(publicResp[8:12]))
	req := make([]byte, 12)
	req[1] = 1 // UDP mapping
	binary.BigEndian.PutUint16(req[4:6], internalPort)
	binary.BigEndian.PutUint16(req[6:8], internalPort)
	binary.BigEndian.PutUint32(req[8:12], lifetime)
	mapResp, err := portMapExchange(ctx, service, req, 16)
	if err != nil {
		return PortMapping{}, fmt.Errorf("magicsock: NAT-PMP UDP mapping: %w", err)
	}
	if mapResp[0] != 0 || mapResp[1] != 129 || binary.BigEndian.Uint16(mapResp[2:4]) != 0 || binary.BigEndian.Uint16(mapResp[8:10]) != internalPort {
		return PortMapping{}, errors.New("magicsock: NAT-PMP UDP mapping rejected or mismatched")
	}
	externalPort := binary.BigEndian.Uint16(mapResp[10:12])
	granted := binary.BigEndian.Uint32(mapResp[12:16])
	if !externalAddr.IsValid() || externalAddr.IsUnspecified() || externalPort == 0 {
		return PortMapping{}, errors.New("magicsock: NAT-PMP returned an invalid external endpoint")
	}
	return PortMapping{
		External:     netip.AddrPortFrom(externalAddr, externalPort),
		Gateway:      service.Addr(),
		InternalPort: internalPort,
		Protocol:     "nat-pmp",
		Lifetime:     time.Duration(granted) * time.Second,
	}, nil
}

func portMapExchange(ctx context.Context, service netip.AddrPort, request []byte, minimumResponse int) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(service))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(750 * time.Millisecond)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = conn.SetDeadline(deadline)
	buf := make([]byte, 128)
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := conn.Write(request); err != nil {
			return nil, err
		}
		n, err := conn.Read(buf)
		if err == nil {
			if n < minimumResponse {
				return nil, errors.New("short response")
			}
			return append([]byte(nil), buf[:n]...), nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() || attempt == 2 {
			return nil, err
		}
		deadline = time.Now().Add(time.Duration(attempt+2) * 750 * time.Millisecond)
		if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
			deadline = value
		}
		_ = conn.SetDeadline(deadline)
	}
	return nil, errors.New("no response")
}

func putPCPAddress(dst []byte, addr netip.Addr) {
	clear(dst)
	addr = addr.Unmap()
	if addr.Is4() {
		dst[10], dst[11] = 0xff, 0xff
		copy(dst[12:16], addr.AsSlice())
		return
	}
	copy(dst, addr.AsSlice())
}

func parsePCPAddress(src []byte) (netip.Addr, bool) {
	if len(src) != 16 {
		return netip.Addr{}, false
	}
	var raw [16]byte
	copy(raw[:], src)
	addr := netip.AddrFrom16(raw).Unmap()
	return addr, addr.IsValid() && !addr.IsUnspecified()
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
