//go:build !darwin && !linux && !windows

package magicsock

import (
	"context"
	"fmt"
	"net/netip"
)

func defaultGateway(context.Context) (netip.Addr, error) {
	return netip.Addr{}, fmt.Errorf("magicsock: automatic port mapping is unsupported on this platform")
}
