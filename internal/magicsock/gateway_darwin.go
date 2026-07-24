//go:build darwin

package magicsock

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

func defaultGateway(ctx context.Context) (netip.Addr, error) {
	out, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("magicsock: read default gateway: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "gateway:" {
			gateway, err := netip.ParseAddr(fields[1])
			if err == nil && gateway.IsValid() && !gateway.IsUnspecified() {
				return gateway.Unmap(), nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("magicsock: default gateway not found")
}
