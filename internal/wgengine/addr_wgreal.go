//go:build wgreal

package wgengine

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func deleteInterface(log *slog.Logger, iface string) {
	switch runtime.GOOS {
	case "linux":
		_ = run(log, "ip", "link", "del", iface)
	case "darwin":
		// The utun disappears when the wireguard-go process exits; best-effort
		// down here. (Process lifecycle teardown is handled by the daemon.)
		_ = exec.Command("ifconfig", iface, "down").Run()
	case "windows":
		path, err := wireGuardWindowsPath()
		if err == nil {
			_ = run(log, path, "/uninstalltunnelservice", iface)
		}
	}
}

func ifaceUp(iface string) error {
	switch runtime.GOOS {
	case "linux":
		return ipCmd("link", "set", iface, "up")
	case "darwin":
		return exec.Command("ifconfig", iface, "up").Run()
	case "windows":
		// The WireGuard tunnel service owns adapter state.
		return nil
	}
	return nil
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

func routeAdd(p netip.Prefix, dev string) error {
	switch runtime.GOOS {
	case "linux":
		return ipCmd("route", "replace", p.String(), "dev", dev)
	case "darwin":
		// macOS can retain scoped duplicates for the same prefix. Removing only
		// one left an old LAN-gateway host route competing with the utun /32.
		routeDelAll(p)
		args := darwinRouteArgs("add", p)
		args = append(args, "-interface", dev)
		return runQuiet("route", args...)
	}
	return nil
}

// routeVia adds a route through a gateway/dev (split-tunnel "direct" bypass).
func routeVia(p netip.Prefix, gw netip.Addr, dev string) error {
	switch runtime.GOOS {
	case "linux":
		args := []string{"route", "replace", p.String()}
		if gw.IsValid() {
			args = append(args, "via", gw.String())
		}
		if dev != "" {
			args = append(args, "dev", dev)
		}
		return ipCmd(args...)
	case "darwin":
		routeDelAll(p)
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

// routeBlackhole drops all traffic to a CIDR (split-tunnel "block").
func routeBlackhole(p netip.Prefix) error {
	switch runtime.GOOS {
	case "linux":
		return ipCmd("route", "replace", "blackhole", p.String())
	case "darwin":
		routeDelAll(p)
		args := darwinRouteArgs("add", p)
		blackhole := "127.0.0.1"
		if p.Addr().Is6() {
			blackhole = "::1"
		}
		return runQuiet("route", append(args, blackhole, "-blackhole")...)
	}
	return nil
}

func routeDelAny(p netip.Prefix) error {
	switch runtime.GOOS {
	case "linux":
		return ipCmd("route", "del", p.String())
	case "darwin":
		return runQuiet("route", darwinRouteArgs("delete", p)...)
	}
	return nil
}

func routeDelAll(p netip.Prefix) {
	// Bound the loop defensively; in practice macOS has at most a small number
	// of scoped duplicates for an exact prefix.
	for range 8 {
		if routeDelAny(p) != nil {
			return
		}
	}
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

// pinEndpoint host-routes the exit's endpoint to its current physical path so
// tunnel-to-exit packets don't loop back into the tunnel.
func pinEndpoint(addr netip.Addr) error {
	dev, via, ok := routeGet(addr)
	if !ok {
		return fmt.Errorf("wgengine: cannot resolve path to %s", addr)
	}
	switch runtime.GOOS {
	case "linux":
		args := []string{"route", "replace", netip.PrefixFrom(addr, addr.BitLen()).String()}
		if via.IsValid() {
			args = append(args, "via", via.String())
		}
		if dev != "" {
			args = append(args, "dev", dev)
		}
		return ipCmd(args...)
	case "darwin":
		_ = hostRouteDel(addr)
		args := darwinHostRouteArgs("add", addr)
		if via.IsValid() {
			return runQuiet("route", append(args, via.String())...)
		}
		if dev != "" {
			return runQuiet("route", append(args, "-interface", dev)...)
		}
	}
	return nil
}

func hostRouteDel(addr netip.Addr) error {
	switch runtime.GOOS {
	case "linux":
		return ipCmd("route", "del", netip.PrefixFrom(addr, addr.BitLen()).String())
	case "darwin":
		return runQuiet("route", darwinHostRouteArgs("delete", addr)...)
	}
	return nil
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

// routeGet returns how the kernel currently reaches addr: (dev, via, ok).
func routeGet(addr netip.Addr) (dev string, via netip.Addr, ok bool) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "get", addr.String()).Output()
		if err != nil {
			return "", netip.Addr{}, false
		}
		fields := strings.Fields(string(out))
		for i := 0; i < len(fields)-1; i++ {
			switch fields[i] {
			case "via":
				via, _ = netip.ParseAddr(fields[i+1])
			case "dev":
				dev = fields[i+1]
			}
		}
		return dev, via, dev != ""
	case "darwin":
		args := []string{"-n", "get"}
		if addr.Is6() {
			args = append(args, "-inet6")
		}
		out, err := exec.Command("route", append(args, addr.String())...).Output()
		if err != nil {
			return "", netip.Addr{}, false
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			switch f[0] {
			case "gateway:":
				via, _ = netip.ParseAddr(f[1])
			case "interface:":
				dev = f[1]
			}
		}
		return dev, via, dev != ""
	case "windows":
		// Find-NetRoute returns the winning route and interface after accounting
		// for both route and interface metrics. Emit a deliberately tiny,
		// locale-independent record for Go to parse.
		script := fmt.Sprintf("$r = Find-NetRoute -RemoteIPAddress '%s' | Select-Object -First 1; if ($null -eq $r) { exit 1 }; Write-Output ($r.InterfaceIndex.ToString() + '|' + $r.NextHop)", addr.String())
		out, err := exec.Command(windowsPowerShellPath, "-NoProfile", "-NonInteractive", "-Command", script).Output()
		if err != nil {
			return "", netip.Addr{}, false
		}
		fields := strings.Split(strings.TrimSpace(string(out)), "|")
		if len(fields) != 2 || fields[0] == "" {
			return "", netip.Addr{}, false
		}
		via, _ = netip.ParseAddr(strings.TrimSpace(fields[1]))
		return strings.TrimSpace(fields[0]), via, true
	}
	return "", netip.Addr{}, false
}

// routeDefaultPath returns the current default egress (gateway, dev).
func routeDefaultPath() (netip.Addr, string) {
	if runtime.GOOS == "windows" {
		return windowsPhysicalDefaultPath()
	}
	dev, via, ok := routeGet(netip.MustParseAddr("1.1.1.1"))
	if !ok {
		return netip.Addr{}, ""
	}
	return via, dev
}

func windowsPhysicalDefaultPath() (netip.Addr, string) {
	if runtime.GOOS != "windows" {
		return netip.Addr{}, ""
	}
	script := fmt.Sprintf(
		"$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne '%s' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; if ($null -eq $r) { exit 1 }; Write-Output ($r.InterfaceIndex.ToString() + '|' + $r.NextHop)",
		WindowsTunnelName,
	)
	out, err := exec.Command(windowsPowerShellPath, "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return netip.Addr{}, ""
	}
	fields := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(fields) != 2 || fields[0] == "" {
		return netip.Addr{}, ""
	}
	gateway, _ := netip.ParseAddr(strings.TrimSpace(fields[1]))
	return gateway.Unmap(), strings.TrimSpace(fields[0])
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
	if _, err := strconv.Atoi(interfaceIndex); err != nil {
		return false, fmt.Errorf("wgengine: invalid Windows interface index %q", interfaceIndex)
	}
	nextHop := windowsRouteNextHop(p, gw)
	metric := 1
	if blackhole {
		// Interface index 1 is Windows' software loopback. A more-specific
		// on-link route through it reliably makes the destination unreachable.
		metric = 0
	}
	script := fmt.Sprintf("$r = Get-NetRoute -DestinationPrefix '%s' -InterfaceIndex %s -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq '%s' } | Select-Object -First 1; if ($null -ne $r) { Write-Output 'existing'; exit 0 }; New-NetRoute -DestinationPrefix '%s' -InterfaceIndex %s -NextHop '%s' -RouteMetric %d -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; Write-Output 'created'", p.String(), interfaceIndex, nextHop, p.String(), interfaceIndex, nextHop, metric)
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
	if _, err := strconv.Atoi(route.interfaceIndex); err != nil {
		return fmt.Errorf("wgengine: invalid Windows interface index %q", route.interfaceIndex)
	}
	script := fmt.Sprintf("Get-NetRoute -DestinationPrefix '%s' -InterfaceIndex %s -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq '%s' } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue", route.prefix.String(), route.interfaceIndex, route.nextHop)
	return runQuiet("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
}
