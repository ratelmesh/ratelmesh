//go:build wgreal

package wgengine

import (
	"errors"
	"fmt"
	"log/slog"
	"math/bits"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const windowsPowerShellPath = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

// Platform primitives for the real engine. Linux uses `ip` + kernel WireGuard;
// macOS uses `route`/`ifconfig` + the wireguard-go userspace binary on a
// kernel-assigned utunN. Windows delegates tunnel ownership to the official
// WireGuard for Windows tunnel service. These will eventually migrate into
// internal/platform (§10.1).

// createInterface brings up the WireGuard device and returns its name.
func createInterface(log *slog.Logger) (string, error) {
	switch runtime.GOOS {
	case "linux":
		const name = "ratelmesh0"
		if err := run(log, "ip", "link", "add", "dev", name, "type", "wireguard"); err == nil {
			return name, nil
		}
		if _, err := exec.LookPath("wireguard-go"); err != nil {
			return "", fmt.Errorf("wgengine: kernel wireguard unavailable and wireguard-go not found: %w", err)
		}
		if err := run(log, "wireguard-go", name); err != nil {
			return "", err
		}
		return name, nil
	case "darwin":
		return createUtunDarwin(log)
	case "windows":
		if _, err := wireGuardWindowsPath(); err != nil {
			return "", err
		}
		// The adapter is created when Reconfigure installs the tunnel service.
		// Its name is derived by WireGuard from the configuration file name.
		return WindowsTunnelName, nil
	default:
		return "", fmt.Errorf("wgengine: unsupported OS %s", runtime.GOOS)
	}
}

// createUtunDarwin starts wireguard-go on a fresh utun and reads the kernel-
// assigned name (utun3, utun8, …) that wireguard-go writes to WG_TUN_NAME_FILE.
func createUtunDarwin(log *slog.Logger) (string, error) {
	name, process, done, err := createUtunDarwinManaged(log)
	if err != nil {
		return "", err
	}
	// Legacy callers do not own the returned process. Keep it alive; RealEngine
	// uses createUtunDarwinManaged directly and retains the lifecycle handles.
	_ = process
	_ = done
	return name, nil
}

// createUtunDarwinManaged keeps wireguard-go in the foreground and returns its
// process lifecycle alongside the kernel-assigned utun name. This is required
// for reliable teardown and in-process recovery after sleep/roaming failures.
func createUtunDarwinManaged(log *slog.Logger) (string, *os.Process, <-chan error, error) {
	if _, err := exec.LookPath("wireguard-go"); err != nil {
		return "", nil, nil, fmt.Errorf("wgengine: wireguard-go not found on PATH (brew install wireguard-go): %w", err)
	}
	nameFile := filepath.Join(os.TempDir(), "ratelmesh-utun-name")
	_ = os.Remove(nameFile)

	cmd := exec.Command("wireguard-go", "utun")
	cmd.Env = append(os.Environ(), "WG_TUN_NAME_FILE="+nameFile, "WG_PROCESS_FOREGROUND=1")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return "", nil, nil, fmt.Errorf("wgengine: start wireguard-go: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
		close(done)
	}()

	// The foreground process writes the chosen name; poll briefly for it while
	// also detecting an early process exit.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			return "", nil, nil, fmt.Errorf("wgengine: wireguard-go exited before creating utun: %w", err)
		default:
		}
		if b, err := os.ReadFile(nameFile); err == nil {
			if name := strings.TrimSpace(string(b)); name != "" {
				log.Info("wg: created utun", "iface", name)
				return name, cmd.Process, done, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	<-done
	return "", nil, nil, fmt.Errorf("wgengine: timed out waiting for utun name")
}

func deleteInterface(log *slog.Logger, iface string) error {
	switch runtime.GOOS {
	case "linux":
		if err := run(log, "ip", "link", "del", iface); err != nil {
			return fmt.Errorf("wgengine: delete Linux interface %q: %w", iface, err)
		}
	case "darwin":
		// The utun disappears when the wireguard-go process exits; best-effort
		// down here. (Process lifecycle teardown is handled by the daemon.)
		if err := exec.Command("ifconfig", iface, "down").Run(); err != nil {
			return fmt.Errorf("wgengine: bring macOS interface %q down: %w", iface, err)
		}
	case "windows":
		path, err := wireGuardWindowsPath()
		if err != nil {
			return err
		}
		uninstallErr := run(log, path, "/uninstalltunnelservice", iface)
		script := fmt.Sprintf(
			"$s=Get-Service -Name 'WireGuardTunnel$%s' -ErrorAction SilentlyContinue; "+
				"$a=Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue; "+
				"if ($null -ne $s -or $null -ne $a) { exit 1 }",
			iface, iface,
		)
		if out, err := exec.Command(windowsPowerShellPath, "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
			return errors.Join(
				uninstallErr,
				fmt.Errorf("wgengine: Windows tunnel service %q still present after uninstall: %v: %s", iface, err, strings.TrimSpace(string(out))),
			)
		}
		// A non-zero manager result is benign only when the service and adapter
		// are both proven absent (the normal first-install case).
		return nil
	}
	return nil
}

func ifaceUp(iface string) error {
	switch runtime.GOOS {
	case "linux":
		for _, args := range interfaceUpPlan(runtime.GOOS, iface) {
			if err := ipCmd(args...); err != nil {
				return err
			}
		}
		return nil
	case "darwin":
		return exec.Command("ifconfig", iface, "up").Run()
	case "windows":
		// The WireGuard tunnel service owns adapter state.
		return nil
	}
	return nil
}

func interfaceUpPlan(goos, iface string) [][]string {
	if goos != "linux" {
		return nil
	}
	return [][]string{
		{"link", "set", "dev", iface, "mtu", strconv.Itoa(pathSafeTunnelMTU)},
		{"link", "set", "dev", iface, "up"},
	}
}

// applyInterfaceAddresses assigns mesh addresses to the interface.
func applyInterfaceAddresses(iface string, addrs []netip.Prefix) error {
	for _, a := range addrs {
		ip := a.Addr().String()
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "linux":
			cmd = exec.Command("ip", "address", "replace", a.String(), "dev", iface)
		case "darwin":
			// utun is point-to-point; set local == remote for a /32 mesh address.
			cmd = exec.Command("ifconfig", iface, "inet", ip, ip, "alias")
		case "windows":
			// Address is part of the tunnel-service configuration.
			continue
		default:
			return fmt.Errorf("wgengine: address programming unsupported on %s", runtime.GOOS)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("wgengine: assign %s: %v: %s", a, err, out)
		}
	}
	return nil
}

// --- routing (dispatches ip vs route) ---
//
// These helpers back the Unix applyRoutes path only. Windows routes are
// created and torn down exactly through windowsCreateRoute /
// windowsRemoveExactRoute in reconfigureWindowsLocked, because the tunnel
// service owns the AllowedIPs routes and we must track only our own additions.

type unixRouteKind uint8

const (
	unixRouteTunnel unixRouteKind = iota
	unixRouteDirect
	unixRouteBlackhole
	unixRoutePin
)

type unixManagedRoute struct {
	prefix  netip.Prefix
	gateway netip.Addr
	device  string
	kind    unixRouteKind
}

func routeAdd(p netip.Prefix, dev string) error {
	switch runtime.GOOS {
	case "linux":
		return ipCmd("route", "add", p.String(), "dev", dev)
	case "darwin":
		args := darwinRouteArgs("add", p)
		args = append(args, "-interface", dev)
		return runQuiet("route", args...)
	}
	return nil
}

// routeVia adds a route through a gateway/dev (split-tunnel "direct" bypass).
func routeVia(p netip.Prefix, gw netip.Addr, dev string) error {
	if !gw.IsValid() && dev == "" {
		return fmt.Errorf("wgengine: no physical path for route %s", p)
	}
	switch runtime.GOOS {
	case "linux":
		args := []string{"route", "add", p.String()}
		if gw.IsValid() {
			args = append(args, "via", gw.String())
		}
		if dev != "" {
			args = append(args, "dev", dev)
		}
		return ipCmd(args...)
	case "darwin":
		args := darwinRouteArgs("add", p)
		if gw.IsValid() && gw.Is6() == p.Addr().Is6() {
			return runQuiet("route", append(args, gw.String())...)
		}
		if dev != "" {
			return runQuiet("route", append(args, "-interface", dev)...)
		}
	}
	return nil
}

// unixPhysicalDefaultPath resolves the policy-selected physical path when that
// path does not use a tunnel. If an active EXIT makes the destination lookup
// select RatelMesh's /1, Linux falls back to the physical main-table /0 instead
// of creating a tunnel self-loop.
func unixPhysicalDefaultPath(target netip.Addr, tunnelInterface string) (netip.Addr, string) {
	switch runtime.GOOS {
	case "linux":
		family := "-4"
		if target.Is6() {
			family = "-6"
		}
		// Let the kernel resolve policy rules and ECMP first. While an EXIT is
		// active this may select our split default, which is deliberately rejected
		// below before falling back to the physical main-table /0.
		if out, err := exec.Command("ip", family, "route", "get", target.String()).Output(); err == nil {
			if gateway, device, ok := parseLinuxPhysicalRouteGet(string(out), tunnelInterface); ok {
				return gateway, device
			}
		}
		out, err := exec.Command("ip", family, "route", "show", "default").Output()
		if err != nil {
			return netip.Addr{}, ""
		}
		return parseLinuxDefaultRoute(string(out), tunnelInterface)
	case "darwin":
		args := []string{"-n", "get"}
		if target.Is6() {
			args = append(args, "-inet6")
		}
		args = append(args, "default")
		out, err := exec.Command("route", args...).Output()
		if err != nil {
			return netip.Addr{}, ""
		}
		return parseDarwinDefaultRoute(string(out))
	default:
		return netip.Addr{}, ""
	}
}

type linuxDefaultCandidate struct {
	gateway netip.Addr
	device  string
	metric  uint64
	order   int
}

func parseLinuxPhysicalRouteGet(output, tunnelInterface string) (netip.Addr, string, bool) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		gateway, device, ok := parseLinuxRoutePath(fields)
		if !ok || device == tunnelInterface || linuxTunnelLikeInterface(device) {
			return netip.Addr{}, "", false
		}
		return gateway, device, true
	}
	return netip.Addr{}, "", false
}

func parseLinuxDefaultRoute(output, tunnelInterface string) (netip.Addr, string) {
	var candidates []linuxDefaultCandidate
	var multipathMetric uint64
	inMultipathDefault := false
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "default" {
			metric, ok := parseLinuxRouteMetric(fields)
			if !ok {
				inMultipathDefault = false
				continue
			}
			multipathMetric = metric
			inMultipathDefault = true
			if gateway, device, ok := parseLinuxRoutePath(fields); ok {
				candidates = appendLinuxDefaultCandidate(candidates, gateway, device, metric, tunnelInterface)
			}
			continue
		}
		if inMultipathDefault && fields[0] == "nexthop" {
			if gateway, device, ok := parseLinuxRoutePath(fields); ok {
				candidates = appendLinuxDefaultCandidate(candidates, gateway, device, multipathMetric, tunnelInterface)
			}
			continue
		}
		// The route-get path above resolves policy rules, classic ECMP, and modern
		// nexthop objects. If an active EXIT hides that result and the /0 fallback
		// contains only an unresolved "nhid", selecting a guessed member would be
		// unsafe; leave the path unresolved instead.
		inMultipathDefault = false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].metric != candidates[j].metric {
			return candidates[i].metric < candidates[j].metric
		}
		return candidates[i].order < candidates[j].order
	})
	if len(candidates) > 0 {
		return candidates[0].gateway, candidates[0].device
	}
	return netip.Addr{}, ""
}

func parseLinuxRouteMetric(fields []string) (uint64, bool) {
	for i := 0; i < len(fields); i++ {
		if fields[i] != "metric" {
			continue
		}
		if i+1 >= len(fields) {
			return 0, false
		}
		metric, err := strconv.ParseUint(fields[i+1], 10, 64)
		return metric, err == nil
	}
	return 0, true
}

func parseLinuxRoutePath(fields []string) (netip.Addr, string, bool) {
	var gateway netip.Addr
	var device string
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "via":
			if i+1 >= len(fields) {
				return netip.Addr{}, "", false
			}
			parsed, err := netip.ParseAddr(fields[i+1])
			if err != nil {
				return netip.Addr{}, "", false
			}
			gateway = parsed.Unmap()
		case "dev":
			if i+1 >= len(fields) || fields[i+1] == "" {
				return netip.Addr{}, "", false
			}
			device = fields[i+1]
		}
	}
	return gateway, device, gateway.IsValid() || device != ""
}

func appendLinuxDefaultCandidate(candidates []linuxDefaultCandidate, gateway netip.Addr, device string, metric uint64, tunnelInterface string) []linuxDefaultCandidate {
	if device == tunnelInterface || linuxTunnelLikeInterface(device) ||
		(!gateway.IsValid() && device == "") {
		return candidates
	}
	return append(candidates, linuxDefaultCandidate{
		gateway: gateway.Unmap(),
		device:  device,
		metric:  metric,
		order:   len(candidates),
	})
}

func linuxTunnelLikeInterface(device string) bool {
	name := strings.ToLower(strings.TrimSpace(device))
	for _, prefix := range []string{
		"ratelmesh", "tailscale", "utun", "tun", "tap", "wg", "vpn", "zt",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func parseDarwinDefaultRoute(output string) (netip.Addr, string) {
	var gateway netip.Addr
	var device string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "gateway:":
			gateway, _ = netip.ParseAddr(fields[1])
		case "interface:":
			device = fields[1]
		}
	}
	if gateway.IsValid() || device != "" {
		return gateway.Unmap(), device
	}
	return netip.Addr{}, ""
}

// routeBlackhole drops all traffic to a CIDR (split-tunnel "block").
func routeBlackhole(p netip.Prefix) error {
	switch runtime.GOOS {
	case "linux":
		return ipCmd("route", "add", "blackhole", p.String())
	case "darwin":
		args := darwinRouteArgs("add", p)
		blackhole := "127.0.0.1"
		if p.Addr().Is6() {
			blackhole = "::1"
		}
		return runQuiet("route", append(args, blackhole, "-blackhole")...)
	}
	return nil
}

// scrubStaleDefaultRoutes removes only split-default routes scoped to the
// current RatelMesh interface. It deliberately does not delete another VPN's
// identical prefixes on a different utun.
func scrubStaleDefaultRoutes(iface string) {
	if iface == "" {
		return
	}
	for _, prefix := range append(defaultRouteHalves(false), defaultRouteHalves(true)...) {
		switch runtime.GOOS {
		case "linux":
			_ = ipCmd("route", "del", prefix.String(), "dev", iface)
		case "darwin":
			_ = runQuiet("route", darwinRouteOnInterfaceArgs("delete", prefix, iface)...)
		}
	}
}

func darwinRouteOnInterfaceArgs(action string, prefix netip.Prefix, iface string) []string {
	return append(darwinRouteArgs(action, prefix), "-interface", iface)
}

func routeDeleteNotFound(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "not in table") ||
		strings.Contains(message, "rtnetlink answers: no such process") ||
		strings.Contains(message, "route has not been found")
}

func deleteUnixManagedRoute(route unixManagedRoute) error {
	switch runtime.GOOS {
	case "linux":
		return ipCmd(linuxManagedRouteDeleteArgs(route)...)
	case "darwin":
		var args []string
		if route.kind == unixRoutePin {
			args = darwinHostRouteArgs("delete", route.prefix.Addr())
		} else {
			args = darwinRouteArgs("delete", route.prefix)
		}
		if route.kind == unixRouteBlackhole {
			gateway := "127.0.0.1"
			if route.prefix.Addr().Is6() {
				gateway = "::1"
			}
			return runQuiet("route", append(args, gateway, "-blackhole")...)
		}
		if route.gateway.IsValid() {
			return runQuiet("route", append(args, route.gateway.String())...)
		}
		if route.device != "" {
			return runQuiet("route", append(args, "-interface", route.device)...)
		}
		return fmt.Errorf("wgengine: managed route %s has no deletion identity", route.prefix)
	}
	return nil
}

func linuxManagedRouteDeleteArgs(route unixManagedRoute) []string {
	args := []string{"route", "del"}
	if route.kind == unixRouteBlackhole {
		args = append(args, "blackhole")
	}
	args = append(args, route.prefix.String())
	if route.gateway.IsValid() {
		args = append(args, "via", route.gateway.String())
	}
	if route.device != "" {
		args = append(args, "dev", route.device)
	}
	return args
}

func unixManagedRouteExists(route unixManagedRoute) (bool, error) {
	if runtime.GOOS == "linux" {
		out, err := exec.Command("ip", "route", "show", "exact", route.prefix.String()).CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("ip route show exact %s: %w: %s", route.prefix, err, strings.TrimSpace(string(out)))
		}
		return linuxRouteOutputHasOwner(string(out), route), nil
	}
	if runtime.GOOS == "darwin" {
		family := "inet"
		if route.prefix.Addr().Is6() {
			family = "inet6"
		}
		out, err := exec.Command("netstat", "-rn", "-f", family).CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("netstat route table for managed %s: %w: %s", route.prefix, err, strings.TrimSpace(string(out)))
		}
		return darwinRouteTableHasOwner(string(out), route)
	}
	return false, nil
}

func linuxRouteOutputHasOwner(output string, route unixManagedRoute) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		kindMatches := route.kind != unixRouteBlackhole || fields[0] == "blackhole"
		deviceMatches := route.device == "" || fieldAfter(fields, "dev") == route.device
		gatewayMatches := !route.gateway.IsValid() || fieldAfter(fields, "via") == route.gateway.String()
		if kindMatches && deviceMatches && gatewayMatches {
			return true
		}
	}
	return false
}

func fieldAfter(fields []string, key string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == key {
			return fields[i+1]
		}
	}
	return ""
}

func darwinRouteTableHasOwner(output string, route unixManagedRoute) (bool, error) {
	headerSeen := false
	parsedRows := 0
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if !headerSeen {
			if len(fields) >= 4 &&
				fields[0] == "Destination" &&
				fields[1] == "Gateway" &&
				fields[2] == "Flags" &&
				fields[3] == "Netif" {
				headerSeen = true
			}
			continue
		}
		if len(fields) < 4 {
			return false, fmt.Errorf("wgengine: unrecognized macOS route-table row %q", line)
		}
		prefix, ok := parseDarwinNetstatPrefix(fields[0], route.prefix.Addr().BitLen())
		if !ok {
			return false, fmt.Errorf("wgengine: unrecognized macOS route destination %q", fields[0])
		}
		parsedRows++
		if prefix != route.prefix.Masked() {
			continue
		}
		gateway := strings.TrimSuffix(fields[1], "%"+zoneOf(fields[1]))
		flags := fields[2]
		device := fields[3]
		if route.gateway.IsValid() {
			got, err := netip.ParseAddr(gateway)
			if err != nil || unzonedAddr(got) != unzonedAddr(route.gateway) {
				continue
			}
		}
		if route.device != "" && device != route.device {
			continue
		}
		if route.kind == unixRouteBlackhole {
			wantGateway := netip.MustParseAddr("127.0.0.1")
			if route.prefix.Addr().Is6() {
				wantGateway = netip.MustParseAddr("::1")
			}
			got, err := netip.ParseAddr(gateway)
			if err != nil || got.Unmap() != wantGateway || !strings.Contains(flags, "B") {
				continue
			}
		}
		if route.kind != unixRouteBlackhole && strings.Contains(flags, "B") {
			continue
		}
		return true, nil
	}
	if !headerSeen {
		return false, fmt.Errorf("wgengine: macOS route-table header was not recognized")
	}
	if parsedRows == 0 {
		return false, fmt.Errorf("wgengine: macOS route table contained no recognized routes")
	}
	return false, nil
}

func unzonedAddr(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Is6() {
		return addr.WithZone("")
	}
	return addr
}

func parseDarwinNetstatPrefix(destination string, bitLen int) (netip.Prefix, bool) {
	if destination == "default" {
		if bitLen == 32 {
			return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
		}
		if bitLen == 128 {
			return netip.PrefixFrom(netip.IPv6Unspecified(), 0), true
		}
		return netip.Prefix{}, false
	}
	if percent := strings.IndexByte(destination, '%'); percent >= 0 {
		if slash := strings.IndexByte(destination[percent:], '/'); slash >= 0 {
			destination = destination[:percent] + destination[percent+slash:]
		} else {
			destination = destination[:percent]
		}
	}
	if prefix, err := netip.ParsePrefix(destination); err == nil && prefix.Addr().BitLen() == bitLen {
		return prefix.Masked(), true
	}
	if bitLen != 32 {
		if addr, err := netip.ParseAddr(destination); err == nil && addr.Is6() {
			return netip.PrefixFrom(addr, 128), true
		}
		return netip.Prefix{}, false
	}

	address, bitsText, hasBits := strings.Cut(destination, "/")
	octets := strings.Split(address, ".")
	if len(octets) == 0 || len(octets) > 4 {
		return netip.Prefix{}, false
	}
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	addr, err := netip.ParseAddr(strings.Join(octets, "."))
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, false
	}
	bits := len(strings.Split(address, ".")) * 8
	if hasBits {
		bits, err = strconv.Atoi(bitsText)
		if err != nil || bits < 0 || bits > 32 {
			return netip.Prefix{}, false
		}
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

func darwinLookupHasRouteOwner(output string, route unixManagedRoute) bool {
	var destination, mask, gateway, device, flags string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "destination":
			destination = strings.TrimSuffix(fields[1], "%"+zoneOf(fields[1]))
		case "mask":
			mask = fields[1]
		case "gateway":
			gateway = strings.TrimSuffix(fields[1], "%"+zoneOf(fields[1]))
		case "interface":
			device = fields[1]
		case "flags":
			flags = strings.ToUpper(strings.Join(fields[1:], " "))
		}
	}
	if !darwinDestinationMatchesPrefix(destination, mask, route.prefix) {
		return false
	}
	if route.prefix.Bits() == route.prefix.Addr().BitLen() && !strings.Contains(flags, "HOST") {
		return false
	}
	if route.gateway.IsValid() {
		got, err := netip.ParseAddr(gateway)
		if err != nil || got.Unmap() != route.gateway.Unmap() {
			return false
		}
	}
	if route.device != "" && device != route.device {
		return false
	}
	if route.kind == unixRouteBlackhole && !strings.Contains(flags, "BLACKHOLE") {
		return false
	}
	return true
}

func darwinDestinationMatchesPrefix(destination, mask string, want netip.Prefix) bool {
	if parsed, err := netip.ParsePrefix(destination); err == nil {
		return parsed.Masked() == want.Masked()
	}
	if destination == "default" {
		return want.Bits() == 0
	}
	addr, err := netip.ParseAddr(destination)
	if err != nil || addr.Unmap() != want.Addr().Unmap() {
		return false
	}
	if want.Bits() == want.Addr().BitLen() {
		return true
	}
	maskBits, ok := darwinMaskBits(mask, want.Addr().BitLen())
	return ok && maskBits == want.Bits()
}

func darwinMaskBits(mask string, bitLen int) (int, bool) {
	if bitLen == 32 && strings.HasPrefix(mask, "0x") {
		value, err := strconv.ParseUint(strings.TrimPrefix(mask, "0x"), 16, 32)
		if err != nil {
			return 0, false
		}
		raw := uint32(value)
		ones := bits.LeadingZeros32(^raw)
		expected := uint32(0)
		if ones > 0 {
			expected = ^uint32(0) << (32 - ones)
		}
		return ones, raw == expected
	}
	addr, err := netip.ParseAddr(mask)
	if err != nil || addr.BitLen() != bitLen {
		return 0, false
	}
	raw := addr.AsSlice()
	ones := 0
	seenZero := false
	for _, value := range raw {
		for bit := 7; bit >= 0; bit-- {
			set := value&(1<<bit) != 0
			if seenZero && set {
				return 0, false
			}
			if set {
				ones++
			} else {
				seenZero = true
			}
		}
	}
	return ones, true
}

func darwinLookupHasExactHostRoute(output string, addr netip.Addr) bool {
	return darwinLookupHasRouteOwner(output, unixManagedRoute{
		prefix: netip.PrefixFrom(addr, addr.BitLen()),
		kind:   unixRoutePin,
	})
}

func zoneOf(addr string) string {
	if _, zone, found := strings.Cut(addr, "%"); found {
		return zone
	}
	return ""
}

func darwinRouteArgs(action string, prefix netip.Prefix) []string {
	args := []string{"-n", action}
	if prefix.Addr().Is6() {
		args = append(args, "-inet6")
	}
	return append(args, "-net", prefix.String())
}

func darwinHostRouteArgs(action string, addr netip.Addr) []string {
	args := []string{"-n", action}
	if addr.Is6() {
		args = append(args, "-inet6")
	}
	return append(args, "-host", addr.String())
}

func windowsPhysicalDefaultPathFor(ipv6 bool) (netip.Addr, string) {
	if runtime.GOOS != "windows" {
		return netip.Addr{}, ""
	}
	family, destination := "IPv4", "0.0.0.0/0"
	if ipv6 {
		family, destination = "IPv6", "::/0"
	}
	script := windowsPhysicalDefaultScript(family, destination)
	out, err := exec.Command(windowsPowerShellPath, "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return netip.Addr{}, ""
	}
	gateway, device, ok := selectWindowsPhysicalDefault(string(out))
	if !ok {
		return netip.Addr{}, ""
	}
	return gateway, device
}

func windowsPhysicalDefaultScript(family, destination string) string {
	return fmt.Sprintf(
		"$routes = Get-NetRoute -AddressFamily %s -DestinationPrefix '%s' -ErrorAction Stop | Where-Object { $_.InterfaceAlias -ne '%s' }; foreach ($r in $routes) { $i = Get-NetIPInterface -AddressFamily %s -InterfaceIndex $r.InterfaceIndex -ErrorAction Stop | Select-Object -First 1; if ($null -ne $i) { Write-Output ($r.InterfaceIndex.ToString() + '|' + $r.NextHop + '|' + $r.RouteMetric.ToString() + '|' + $i.InterfaceMetric.ToString() + '|' + ([int]$i.ConnectionState).ToString()) } }",
		family, destination, WindowsTunnelName, family,
	)
}

// ipCmd runs `ip <args>` capturing output for real error messages.
func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %v: %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runQuiet runs a command capturing output for the error message only.
func runQuiet(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// findWindowsWireGuardBinary locates a WireGuard for Windows binary
// ("wireguard" manager or "wg"). Prefer the canonical, administrator-owned
// install directory before consulting PATH, which may contain user-writable
// entries in a misconfigured service environment.
func findWindowsWireGuardBinary(name string) (string, error) {
	if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
		path := filepath.Join(programFiles, "WireGuard", name+".exe")
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}
	if path, err := exec.LookPath(name + ".exe"); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("wgengine: %s.exe was not found in PATH or Program Files\\WireGuard (install WireGuard for Windows)", name)
}

func wireGuardWindowsPath() (string, error) { return findWindowsWireGuardBinary("wireguard") }
func wgWindowsPath() (string, error)        { return findWindowsWireGuardBinary("wg") }

func windowsCreateRoute(p netip.Prefix, gw netip.Addr, interfaceIndex string, blackhole bool) (bool, error) {
	if interfaceIndex == "" {
		return false, fmt.Errorf("wgengine: no Windows interface index for route %s", p)
	}
	index, err := strconv.ParseUint(interfaceIndex, 10, 64)
	if err != nil || index == 0 {
		return false, fmt.Errorf("wgengine: invalid Windows interface index %q", interfaceIndex)
	}
	nextHop := windowsRouteNextHop(p, gw)
	metric := 1
	if blackhole {
		// Interface index 1 is Windows' software loopback. A more-specific
		// on-link route through it reliably makes the destination unreachable.
		metric = 0
	}
	script := fmt.Sprintf("$r = Get-NetRoute -DestinationPrefix '%s' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -ne $r) { Write-Error 'route conflict'; exit 2 }; New-NetRoute -DestinationPrefix '%s' -InterfaceIndex %s -NextHop '%s' -RouteMetric %d -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; Write-Output 'created'", p.String(), p.String(), interfaceIndex, nextHop, metric)
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("powershell.exe create route %s: %w: %s", p, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)) == "created", nil
}

func windowsRouteNextHop(p netip.Prefix, gw netip.Addr) string {
	if gw.IsValid() {
		return gw.String()
	}
	if p.Addr().Is6() {
		return "::"
	}
	return "0.0.0.0"
}

func windowsRemoveExactRoute(route windowsManagedRoute) error {
	index, err := strconv.ParseUint(route.interfaceIndex, 10, 64)
	if err != nil || index == 0 {
		return fmt.Errorf("wgengine: invalid Windows interface index %q", route.interfaceIndex)
	}
	// An empty exact query is idempotent success. Any matching route that fails
	// removal must make PowerShell exit non-zero so the ownership ledger retains
	// it for bounded retry instead of silently forgetting a permanent residual.
	script := windowsRemoveExactRouteScript(route)
	return runQuiet("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
}

func windowsRemoveExactRouteScript(route windowsManagedRoute) string {
	return fmt.Sprintf("$routes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq '%s' -and $_.InterfaceIndex -eq %s -and $_.NextHop -eq '%s' }); if ($routes.Count -gt 0) { $routes | Remove-NetRoute -Confirm:$false -ErrorAction Stop }", route.prefix.String(), route.interfaceIndex, route.nextHop)
}
