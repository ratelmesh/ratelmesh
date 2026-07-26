//go:build wgreal

package wgengine

import "net/netip"

type windowsManagedRoute struct {
	prefix         netip.Prefix
	interfaceIndex string
	nextHop        string
}

func peerHasDefaultRoute(peer Peer) bool {
	for _, allowed := range peer.AllowedIPs {
		if allowed.Bits() == 0 {
			return true
		}
	}
	return false
}
