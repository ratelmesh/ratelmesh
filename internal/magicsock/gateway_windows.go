//go:build windows

package magicsock

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

func defaultGateway(ctx context.Context) (netip.Addr, error) {
	out, err := exec.CommandContext(ctx, "route.exe", "PRINT", "-4", "0.0.0.0").Output()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("magicsock: read default gateway: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		gateway, err := netip.ParseAddr(fields[2])
		if err == nil && gateway.Is4() && !gateway.IsUnspecified() {
			return gateway, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("magicsock: default gateway not found")
}
