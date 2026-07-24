package daemon

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

var errPhysicalNetworkChanged = errors.New("physical network address changed")

// networkPathLoop detects Wi-Fi, Ethernet and phone-hotspot roaming without
// depending on a WireGuard send failing first. A changed physical source
// address invalidates both the persistent UDP socket and any long-lived control
// TCP connection that was bound to the former interface.
func (d *Daemon) networkPathLoop(ctx context.Context) {
	const interval = 2 * time.Second
	last := physicalNetworkSignature()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		current := physicalNetworkSignature()
		if current == "" {
			continue
		}
		if last == "" {
			last = current
			continue
		}
		if current == last {
			continue
		}
		last = current
		d.log.Warn("physical network address changed; resetting control and data paths")
		d.client.ResetNetwork()
		d.recoverNetworkPath(errPhysicalNetworkChanged)
	}
}

func physicalNetworkSignature() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var entries []string
	for _, iface := range ifaces {
		if !isPhysicalInterface(iface) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil || !isPhysicalAddress(prefix.Addr()) {
				continue
			}
			entries = append(entries, iface.Name+"="+prefix.Addr().String())
		}
	}
	sort.Strings(entries)
	return strings.Join(entries, ",")
}

func isPhysicalInterface(iface net.Interface) bool {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	name := strings.ToLower(iface.Name)
	for _, prefix := range []string{"utun", "tun", "tap", "wg", "awdl", "llw", "bridge"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

func isPhysicalAddress(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if mesh, err := netip.ParsePrefix(meshCIDR); err == nil && mesh.Contains(addr) {
		return false
	}
	return true
}
