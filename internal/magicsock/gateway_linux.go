//go:build linux

package magicsock

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

func defaultGateway(context.Context) (netip.Addr, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("magicsock: read default gateway: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		gateway := netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
		if gateway.IsValid() && !gateway.IsUnspecified() {
			return gateway, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return netip.Addr{}, fmt.Errorf("magicsock: scan default gateway: %w", err)
	}
	return netip.Addr{}, fmt.Errorf("magicsock: default gateway not found")
}
