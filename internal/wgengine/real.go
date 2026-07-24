//go:build wgreal

// RealEngine is the production WireGuard data plane, selected with `-tags wgreal`.
// It drives a real interface (Linux: kernel WireGuard or the wireguard-go binary
// on "ratelmesh0"; macOS: a kernel-assigned utunN via wireguard-go; Windows: the
// official WireGuard tunnel service), applies the peer set, and programs
// addresses and routes — including
// full-tunnel default routing through the chosen exit with the exit's endpoint
// pinned to its physical path so the tunnel does not route over itself. Route and
// address helpers dispatch to `ip` (Linux) or `route`/`ifconfig` (macOS). Without
// the tag the rootless StubEngine is used instead.
package wgengine

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ratelmesh/ratelmesh/internal/atomicfile"
	"github.com/ratelmesh/ratelmesh/internal/types"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// darwinTunnelMTU uses IPv6's guaranteed minimum link MTU. The former
// wireguard-go default of 1420 assumes an outer path close to Ethernet's 1500
// bytes; cross-border access, phone hotspots and relay encapsulation can offer
// less and silently black-hole full-sized HTTPS/QUIC packets even while small
// WireGuard packets make the EXIT look healthy.
const darwinTunnelMTU = 1280

type RealEngine struct {
	log *slog.Logger

	mu             sync.Mutex
	up             bool
	iface          string // actual interface name (ratelmesh0 on Linux/Windows, utunN on macOS)
	cfg            Config
	confDir        string
	routed         []netip.Prefix        // Unix routes currently programmed, for teardown
	pinned         []netip.Addr          // Unix endpoint host-routes pinned to the physical path
	windowsRoutes  []windowsManagedRoute // Windows routes created by us (not pre-existing routes)
	windowsPins    []windowsManagedRoute // subset of windowsRoutes that pins physical transports
	routeAddFunc   func(netip.Prefix, string) error
	routeDelFunc   func(netip.Prefix) error
	routeScrubFunc func(string)
	routesScrubbed bool
	routesApplied  bool

	// windowsApplied records that the tunnel service is installed and e.cfg is
	// what it runs, enabling the unchanged/syncconf fast paths that avoid a
	// full service reinstall (and its data-plane blackout) on every netmap.
	windowsApplied bool
	// confDirSecured avoids re-running icacls on the config directory for
	// every reconfigure; the ACL only needs to be applied once per process.
	confDirSecured bool

	// wireguard-go runs in the foreground on macOS so ratelmeshd owns its lifecycle.
	// Keeping the process handle lets automatic recovery terminate a wedged
	// userspace tunnel cleanly instead of leaking an old utun on every rebuild.
	darwinProcess *os.Process
	darwinDone    <-chan error
	// macOS runs wireguard-go in-process so STUN can share the exact WireGuard
	// UDP socket. A separate STUN socket discovers the wrong NAT mapping.
	darwinDevice *wgdevice.Device
	darwinTun    tun.Device
	stunBind     *stunBind
}

// InterfaceName returns the WireGuard interface name (implements InterfaceNamer),
// so the daemon can allow traffic out it in the kill switch (Grok #1).
func (e *RealEngine) InterfaceName() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.iface
}

// RequiresExitHandshake tells the daemon to stage an exit peer without default
// routes until WireGuard reports a recent successful handshake.
func (e *RealEngine) RequiresExitHandshake() bool { return true }

// New selects the real engine when built with -tags wgreal.
func New(log *slog.Logger) Engine {
	if log == nil {
		log = slog.Default()
	}
	confDir := filepath.Join(os.TempDir(), "ratelmesh")
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = os.TempDir()
		}
		confDir = filepath.Join(base, "RatelMesh")
	}
	return &RealEngine{log: log, confDir: confDir}
}

// OwnsListenPort reports that the real engine binds the WireGuard ListenPort
// itself, so the daemon must not run a separate disco socket on it.
func OwnsListenPort() bool { return true }

func (e *RealEngine) Up() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.up {
		return nil
	}
	var iface string
	var err error
	if runtime.GOOS == "darwin" {
		iface, err = e.startDarwinDeviceLocked()
	} else {
		iface, err = createInterface(e.log)
	}
	if err != nil {
		return err
	}
	e.iface = iface
	e.up = true
	e.log.Info("wg: interface up", "iface", e.iface)
	return nil
}

func (e *RealEngine) Reconfigure(cfg Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if runtime.GOOS == "windows" && (!e.up || e.iface == "") {
		return fmt.Errorf("wgengine: interface is not up")
	}
	if runtime.GOOS == "windows" {
		return e.reconfigureWindowsLocked(cfg)
	}
	if runtime.GOOS == "darwin" && e.darwinDevice != nil {
		return e.reconfigureDarwinLocked(cfg)
	}

	return e.reconfigureUnixLocked(cfg)
}

func (e *RealEngine) startDarwinDeviceLocked() (string, error) {
	tdev, err := tun.CreateTUN("utun", darwinTunnelMTU)
	if err != nil {
		return "", fmt.Errorf("wgengine: create utun: %w", err)
	}
	name, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return "", fmt.Errorf("wgengine: read utun name: %w", err)
	}
	bind := newSTUNBind(conn.NewDefaultBind())
	logger := &wgdevice.Logger{
		Verbosef: func(format string, args ...any) { e.log.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { e.log.Error(fmt.Sprintf(format, args...)) },
	}
	dev := wgdevice.NewDevice(tdev, bind, logger)
	if err := dev.Up(); err != nil {
		dev.Close()
		return "", fmt.Errorf("wgengine: start in-process wireguard-go: %w", err)
	}
	e.darwinTun = tdev
	e.darwinDevice = dev
	e.stunBind = bind
	e.log.Info("wg: created in-process utun", "iface", name, "mtu", darwinTunnelMTU)
	return name, nil
}

func (e *RealEngine) reconfigureDarwinLocked(cfg Config) error {
	if !e.up || e.iface == "" || e.darwinDevice == nil {
		return fmt.Errorf("wgengine: macOS interface is not up")
	}
	uapi := UAPIConfigUpdate(cfg, e.cfg)
	if len(e.cfg.Peers) == 0 {
		uapi = UAPIConfig(cfg)
	}
	if err := e.darwinDevice.IpcSet(uapi); err != nil {
		return fmt.Errorf("wgengine: in-process UAPI configure: %w", err)
	}
	if err := applyInterfaceAddresses(e.iface, cfg.Addresses); err != nil {
		return err
	}
	if err := ifaceUp(e.iface); err != nil {
		return err
	}
	if err := e.applyRoutes(cfg); err != nil {
		return err
	}
	e.cfg = cfg
	e.log.Info("wg: reconfigured", "peers", len(cfg.Peers))
	return nil
}

// PrepareEndpointDiscovery opens macOS wireguard-go's persistent UDP socket
// before the first control-plane registration. The full addresses, peers and
// routes are still applied by Reconfigure after the initial netmap arrives.
func (e *RealEngine) PrepareEndpointDiscovery(cfg Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if runtime.GOOS != "darwin" {
		return nil
	}
	if !e.up || e.darwinDevice == nil {
		return fmt.Errorf("wgengine: macOS device is not up")
	}
	bootstrap := Config{PrivateKey: cfg.PrivateKey, ListenPort: cfg.ListenPort}
	if err := e.darwinDevice.IpcSet(UAPIConfig(bootstrap)); err != nil {
		return fmt.Errorf("wgengine: prepare endpoint discovery: %w", err)
	}
	return nil
}

func (e *RealEngine) reconfigureUnixLocked(cfg Config) error {
	if !e.up || e.iface == "" {
		return fmt.Errorf("wgengine: interface is not up")
	}
	if err := os.MkdirAll(e.confDir, 0o700); err != nil {
		return err
	}
	confPath := filepath.Join(e.confDir, e.iface+".conf")
	if err := os.WriteFile(confPath, []byte(WgSetConf(cfg)), 0o600); err != nil {
		return err
	}
	if err := run(e.log, "wg", "setconf", e.iface, confPath); err != nil {
		return fmt.Errorf("wgengine: wg setconf: %w", err)
	}
	if err := applyInterfaceAddresses(e.iface, cfg.Addresses); err != nil {
		return err
	}
	if err := ifaceUp(e.iface); err != nil {
		return err
	}
	if err := e.applyRoutes(cfg); err != nil {
		return err
	}
	e.cfg = cfg
	e.log.Info("wg: reconfigured", "peers", len(cfg.Peers))
	return nil
}

// reconfigureWindowsLocked hands a complete wg-quick style configuration to
// the official WireGuard for Windows tunnel service. The service owns the
// Wintun adapter, key material, addresses, peer routes, and firewall
// integration; ratelmeshd must run elevated, as required by WireGuard's service CLI.
// A full snapshot is applied by reinstalling the service, but that tears the
// adapter down (a multi-second data-plane blackout), so netmaps that change
// nothing are skipped and endpoint/keepalive-only changes go through
// `wg syncconf` against the live adapter instead.
func (e *RealEngine) reconfigureWindowsLocked(cfg Config) error {
	if cfg.KillSwitch && len(cfg.DirectRoutes) > 0 {
		return fmt.Errorf("wgengine: Windows direct routes are incompatible with the WireGuard /0 kill switch")
	}
	manager, err := wireGuardWindowsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(e.confDir, 0o700); err != nil {
		return fmt.Errorf("wgengine: create Windows config directory: %w", err)
	}
	if !e.confDirSecured {
		if err := secureWindowsConfigDir(e.confDir); err != nil {
			return err
		}
		e.confDirSecured = true
	}

	confPath := filepath.Join(e.confDir, WindowsTunnelName+".conf")
	if e.windowsApplied {
		if windowsReconfigureUnchanged(e.cfg, cfg) {
			e.cfg = cfg
			return nil
		}
		if windowsSyncconfSufficient(e.cfg, cfg) {
			cleanupPins, pinErr := e.stageWindowsPinsLocked(cfg)
			if pinErr != nil {
				e.log.Warn("wg: Windows endpoint pin refresh failed; reinstalling the tunnel service", "err", pinErr)
			} else if err := e.syncconfWindowsLocked(cfg, confPath); err == nil {
				cleanupPins()
				e.cfg = cfg
				e.log.Info("wg: Windows tunnel updated in place", "iface", e.iface, "peers", len(cfg.Peers))
				return nil
			} else {
				e.log.Warn("wg: syncconf failed; reinstalling the tunnel service", "err", err)
			}
		}
	}
	e.windowsApplied = false

	// Tear down the previous service before resolving the physical default
	// path. Otherwise a previous full-tunnel route can be mistaken for the LAN
	// route and endpoint/direct-route exceptions will point back into ratelmesh0.
	e.clearRoutesLocked()
	// A missing service is expected on the first configuration, so do not emit
	// an error-level command log for that case.
	_ = exec.Command(manager, "/uninstalltunnelservice", e.iface).Run()
	gwAddr, gwDev := routeDefaultPath()

	plan := planWindowsRoutes(cfg)
	if plan.hasDefault && (len(plan.pins) > 0 || len(plan.direct) > 0) && !gwAddr.IsValid() && gwDev == "" {
		return fmt.Errorf("wgengine: cannot resolve the physical Windows path for the exit endpoint / direct routes")
	}
	// Pin the exit endpoints to the physical path BEFORE the service installs
	// the /1 halves, so packets to the exit never route into the tunnel itself
	// (the Unix path does the same via pinEndpoint).
	for _, addr := range plan.pins {
		p := netip.PrefixFrom(addr, addr.BitLen())
		created, err := windowsCreateRoute(p, gwAddr, gwDev, false)
		if err != nil {
			e.clearRoutesLocked()
			return fmt.Errorf("wgengine: pin Windows exit endpoint %s: %w", addr, err)
		}
		if created {
			managed := windowsManagedRoute{
				prefix: p, interfaceIndex: gwDev, nextHop: windowsRouteNextHop(p, gwAddr),
			}
			e.windowsRoutes = append(e.windowsRoutes, managed)
			e.windowsPins = append(e.windowsPins, managed)
		}
	}

	if err := atomicfile.WriteFile(confPath, []byte(windowsTunnelConfig(cfg))); err != nil {
		e.clearRoutesLocked()
		return fmt.Errorf("wgengine: write Windows tunnel config: %w", err)
	}
	if err := secureWindowsConfig(confPath); err != nil {
		e.clearRoutesLocked()
		return err
	}
	if err := run(e.log, manager, "/installtunnelservice", confPath); err != nil {
		e.clearRoutesLocked()
		return fmt.Errorf("wgengine: install Windows tunnel service (run ratelmeshd as Administrator): %w", err)
	}
	if err := waitWindowsTunnel(e.iface, 10*time.Second); err != nil {
		e.clearRoutesLocked()
		_ = run(e.log, manager, "/uninstalltunnelservice", e.iface)
		return err
	}

	if plan.hasDefault {
		for _, p := range plan.direct {
			created, err := windowsCreateRoute(p, gwAddr, gwDev, false)
			if err != nil {
				e.clearRoutesLocked()
				_ = run(e.log, manager, "/uninstalltunnelservice", e.iface)
				return fmt.Errorf("wgengine: add Windows direct route %s: %w", p, err)
			}
			if created {
				e.windowsRoutes = append(e.windowsRoutes, windowsManagedRoute{
					prefix: p, interfaceIndex: gwDev, nextHop: windowsRouteNextHop(p, gwAddr),
				})
			}
		}
		for _, p := range plan.block {
			created, err := windowsCreateRoute(p, netip.Addr{}, "1", true)
			if err != nil {
				e.clearRoutesLocked()
				_ = run(e.log, manager, "/uninstalltunnelservice", e.iface)
				return fmt.Errorf("wgengine: add Windows block route %s: %w", p, err)
			}
			if created {
				e.windowsRoutes = append(e.windowsRoutes, windowsManagedRoute{
					prefix: p, interfaceIndex: "1", nextHop: windowsRouteNextHop(p, netip.Addr{}),
				})
			}
		}
	}

	e.cfg = cfg
	e.windowsApplied = true
	e.log.Info("wg: Windows tunnel service reconfigured", "iface", e.iface, "peers", len(cfg.Peers))
	return nil
}

// syncconfWindowsLocked applies an endpoint/keepalive-only change to the live
// adapter via `wg syncconf`, avoiding a service reinstall. It also refreshes
// the on-disk service config so a service restart (crash, reboot) comes back
// with the current peers rather than the ones from the last full install.
func (e *RealEngine) syncconfWindowsLocked(cfg Config, confPath string) error {
	wgBin, err := wgWindowsPath()
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(confPath, []byte(windowsTunnelConfig(cfg))); err != nil {
		return fmt.Errorf("wgengine: write Windows tunnel config: %w", err)
	}
	if err := secureWindowsConfig(confPath); err != nil {
		return err
	}
	// wg syncconf needs a setconf document (no wg-quick Address/DNS lines),
	// rendered from the same split-defaults view the service was installed with.
	syncPath := filepath.Join(e.confDir, WindowsTunnelName+".sync.conf")
	if err := atomicfile.WriteFile(syncPath, []byte(WgSetConf(windowsSplitDefaults(cfg)))); err != nil {
		return fmt.Errorf("wgengine: write Windows syncconf document: %w", err)
	}
	defer os.Remove(syncPath)
	if err := secureWindowsConfig(syncPath); err != nil {
		return err
	}
	if err := run(e.log, wgBin, "syncconf", e.iface, syncPath); err != nil {
		return fmt.Errorf("wgengine: wg syncconf: %w", err)
	}
	return nil
}

func (e *RealEngine) stageWindowsPinsLocked(cfg Config) (func(), error) {
	plan := planWindowsRoutes(cfg)
	if !plan.hasDefault {
		return func() {}, nil
	}
	gwAddr, gwDev := windowsPhysicalDefaultPath()
	if (len(plan.pins) > 0 || len(plan.direct) > 0) && !gwAddr.IsValid() && gwDev == "" {
		return func() {}, fmt.Errorf("wgengine: cannot resolve the live physical Windows path")
	}

	desired := make(map[windowsManagedRoute]bool, len(plan.pins))
	for _, addr := range plan.pins {
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		route := windowsManagedRoute{
			prefix: prefix, interfaceIndex: gwDev, nextHop: windowsRouteNextHop(prefix, gwAddr),
		}
		desired[route] = true
		if slices.Contains(e.windowsPins, route) {
			continue
		}
		created, err := windowsCreateRoute(prefix, gwAddr, gwDev, false)
		if err != nil {
			return func() {}, fmt.Errorf("wgengine: stage Windows endpoint pin %s: %w", addr, err)
		}
		if created {
			e.windowsRoutes = append(e.windowsRoutes, route)
			e.windowsPins = append(e.windowsPins, route)
		}
	}

	return func() {
		for _, route := range append([]windowsManagedRoute(nil), e.windowsPins...) {
			if desired[route] {
				continue
			}
			if err := windowsRemoveExactRoute(route); err != nil {
				e.log.Warn("wg: remove obsolete Windows endpoint pin failed", "route", route.prefix, "err", err)
				continue
			}
			e.windowsPins = slices.DeleteFunc(e.windowsPins, func(candidate windowsManagedRoute) bool {
				return candidate == route
			})
			e.windowsRoutes = slices.DeleteFunc(e.windowsRoutes, func(candidate windowsManagedRoute) bool {
				return candidate == route
			})
		}
	}, nil
}

func secureWindowsConfig(path string) error {
	// Numeric SIDs keep this locale-independent. Disabling inherited ACLs and
	// granting only LocalSystem and the built-in Administrators group protects
	// the private key even though Windows ignores Unix file modes.
	out, err := exec.Command("icacls.exe", path,
		"/inheritance:r",
		"/grant:r", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wgengine: secure Windows tunnel config ACL: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func secureWindowsConfigDir(path string) error {
	// Protect temporary files as soon as they are created, rather than leaving
	// a brief inherited-ACL window before the final config file is secured.
	out, err := exec.Command("icacls.exe", path,
		"/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)(F)", "*S-1-5-32-544:(OI)(CI)(F)",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wgengine: secure Windows config directory ACL: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func waitWindowsTunnel(name string, timeout time.Duration) error {
	// One PowerShell process polls internally: spawning a fresh powershell.exe
	// per 100ms check costs a ~300ms cold start each, i.e. dozens of processes
	// per reconfigure for nothing.
	seconds := max(int(timeout/time.Second), 1)
	script := fmt.Sprintf(
		"$deadline = (Get-Date).AddSeconds(%d); while ((Get-Date) -lt $deadline) { if (Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue) { exit 0 }; Start-Sleep -Milliseconds 250 }; exit 1",
		seconds, name)
	if exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Run() != nil {
		return fmt.Errorf("wgengine: timed out waiting for Windows tunnel adapter %q", name)
	}
	return nil
}

// applyRoutes programs a route for every peer AllowedIP. IPv4 and IPv6 defaults
// are installed as /1 pairs (which win over the physical defaults without
// deleting them), and the exit peer's endpoint is
// host-routed to its physical path so tunnel packets to the exit do not loop
// back into the tunnel. Works on Linux (`ip`) and macOS (`route`).
func (e *RealEngine) applyRoutes(cfg Config) error {
	// A previous daemon can be killed after installing split defaults but
	// before recording/clearing them. A fresh process has an empty in-memory
	// route ledger, so reconcile only RatelMesh's current interface once before
	// applying desired state. This avoids stranding 0/1 and 128/1 in DIRECT.
	if !e.routesScrubbed {
		if e.routeScrubFunc != nil {
			e.routeScrubFunc(e.iface)
		} else {
			scrubStaleDefaultRoutes(e.iface)
		}
		e.routesScrubbed = true
	}
	// Netmap refreshes and path probes routinely change transport candidates
	// without changing any tunnel/direct/block route. Removing the live /1
	// defaults for those updates creates a brief physical-gateway window on
	// macOS and stalls active streams. Reconcile endpoint host-route pins in
	// place, but leave the tunnel route plan untouched.
	if e.routesApplied && unixTunnelRouteInputsEqual(e.cfg, cfg) {
		e.reconcilePinnedRoutes(cfg)
		return nil
	}
	e.clearRoutesLocked()
	failRoute := func(kind string, prefix netip.Prefix, err error) error {
		e.clearRoutesLocked()
		return fmt.Errorf("wgengine: install %s route %s: %w", kind, prefix, err)
	}

	// Capture the pre-hijack default path so split-tunnel "direct" routes and the
	// exit endpoint can bypass the tunnel.
	gwAddr, gwDev := routeDefaultPath()
	hasDefault := false
	for _, p := range cfg.Peers {
		if peerHasDefaultRoute(p) {
			hasDefault = true
			break
		}
	}

	// Pin the live control and relay sockets before installing either /1. In a
	// relay-backed path the WireGuard endpoint is 127.0.0.1, so pinning only the
	// peer endpoint is insufficient: the bridge's real TCP/WSS connection would
	// otherwise be captured by the exit it is trying to establish.
	pinned := make(map[netip.Addr]bool)
	pin := func(addr netip.Addr) {
		addr = addr.Unmap()
		if !hasDefault || !addr.IsValid() || pinned[addr] {
			return
		}
		if err := pinEndpoint(addr); err == nil {
			pinned[addr] = true
			e.pinned = append(e.pinned, addr)
		}
	}
	for _, addr := range cfg.PhysicalEndpoints {
		pin(addr)
	}

	for _, p := range cfg.Peers {
		var hasIPv4Default, hasIPv6Default bool
		for _, a := range p.AllowedIPs {
			if a.Bits() == 0 {
				if a.Addr().Is4() {
					hasIPv4Default = true
				} else {
					hasIPv6Default = true
				}
				continue // install defaults as /1 pairs below
			}
			if err := e.addRoute(a); err != nil {
				return failRoute("tunnel", a, err)
			}
			e.routed = append(e.routed, a)
		}
		if hasIPv4Default || hasIPv6Default {
			// Pin the exit's endpoint to its current physical path first, so
			// tunnel-to-exit packets don't loop back into the tunnel.
			if len(p.Endpoints) > 0 {
				if ap, err := netip.ParseAddrPort(p.Endpoints[0]); err == nil {
					pin(ap.Addr())
				}
			}
			installDefault := func(is6 bool) error {
				for _, half := range defaultRouteHalves(is6) {
					if err := e.addRoute(half); err != nil {
						return failRoute("default", half, err)
					}
					e.routed = append(e.routed, half)
				}
				return nil
			}
			if !cfg.KillSwitch && hasIPv6Default {
				// Without a firewall, capture IPv6 first and fail the entire apply if
				// that is impossible. Keeping only IPv4 would leak IPv6 indefinitely.
				if err := installDefault(true); err != nil {
					return err
				}
			}
			if hasIPv4Default {
				if err := installDefault(false); err != nil {
					return err
				}
			}
			if cfg.KillSwitch && hasIPv6Default {
				// With the external firewall already armed, tolerate kernels where
				// IPv6 routing is disabled: cleartext IPv6 remains blocked.
				start := len(e.routed)
				for _, half := range defaultRouteHalves(true) {
					if err := e.addRoute(half); err != nil {
						// Roll back a partially installed IPv6 pair, but retain the
						// working IPv4 tunnel routes.
						for _, added := range e.routed[start:] {
							_ = e.delRoute(added)
						}
						e.routed = e.routed[:start]
						e.log.Warn("wg: IPv6 default route unavailable; continuing with fail-closed IPv4 tunnel", "route", half, "err", err)
						break
					}
					e.routed = append(e.routed, half)
				}
			}
			// Split tunnel: "direct" CIDRs bypass the tunnel via the physical
			// gateway; "block" CIDRs are blackholed. These are more specific than
			// the /1 halves, so they win (DESIGN.md §8.4).
			if gwAddr.IsValid() || gwDev != "" {
				for _, d := range cfg.DirectRoutes {
					if err := routeVia(d, gwAddr, gwDev); err != nil {
						return failRoute("direct", d, err)
					}
					e.routed = append(e.routed, d)
				}
			}
			for _, b := range cfg.BlockRoutes {
				if err := routeBlackhole(b); err != nil {
					return failRoute("blackhole", b, err)
				}
				e.routed = append(e.routed, b)
			}
		}
	}
	e.routesApplied = true
	return nil
}

func unixTunnelRouteInputsEqual(prev, next Config) bool {
	if prev.KillSwitch != next.KillSwitch ||
		!slices.Equal(prev.DirectRoutes, next.DirectRoutes) ||
		!slices.Equal(prev.BlockRoutes, next.BlockRoutes) ||
		len(prev.Peers) != len(next.Peers) {
		return false
	}
	for i := range prev.Peers {
		if prev.Peers[i].PublicKey != next.Peers[i].PublicKey ||
			!slices.Equal(prev.Peers[i].AllowedIPs, next.Peers[i].AllowedIPs) {
			return false
		}
	}
	return true
}

func desiredPinnedEndpoints(cfg Config) []netip.Addr {
	hasDefault := false
	for _, peer := range cfg.Peers {
		if peerHasDefaultRoute(peer) {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		return nil
	}
	seen := make(map[netip.Addr]bool)
	var desired []netip.Addr
	add := func(addr netip.Addr) {
		addr = addr.Unmap()
		if addr.IsValid() && !seen[addr] {
			seen[addr] = true
			desired = append(desired, addr)
		}
	}
	for _, addr := range cfg.PhysicalEndpoints {
		add(addr)
	}
	for _, peer := range cfg.Peers {
		if !peerHasDefaultRoute(peer) || len(peer.Endpoints) == 0 {
			continue
		}
		if endpoint, err := netip.ParseAddrPort(peer.Endpoints[0]); err == nil {
			add(endpoint.Addr())
		}
	}
	return desired
}

func (e *RealEngine) reconcilePinnedRoutes(cfg Config) {
	desired := desiredPinnedEndpoints(cfg)
	if len(desired) == 0 && len(e.pinned) == 0 {
		return
	}
	current := make(map[netip.Addr]bool, len(e.pinned))
	for _, addr := range e.pinned {
		current[addr] = true
	}

	gwAddr, gwDev := routeDefaultPath()
	kept := make([]netip.Addr, 0, len(desired))
	wanted := make(map[netip.Addr]bool, len(desired))
	for _, addr := range desired {
		wanted[addr] = true
		if current[addr] {
			kept = append(kept, addr)
			continue
		}
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		if err := routeVia(prefix, gwAddr, gwDev); err != nil {
			e.log.Warn("wg: cannot pin refreshed physical endpoint", "endpoint", addr, "err", err)
			continue
		}
		kept = append(kept, addr)
	}
	// Add replacements first, then remove obsolete pins so a roaming peer never
	// loses every physical transport route during the refresh.
	for _, addr := range e.pinned {
		if !wanted[addr] {
			_ = hostRouteDel(addr)
		}
	}
	e.pinned = kept
}

func (e *RealEngine) clearRoutesLocked() {
	e.routesApplied = false
	if runtime.GOOS == "windows" {
		for _, route := range e.windowsRoutes {
			_ = windowsRemoveExactRoute(route)
		}
		e.windowsRoutes = nil
		e.windowsPins = nil
		e.routed = nil
		e.pinned = nil
		return
	}
	for _, r := range e.routed {
		_ = e.delRoute(r) // matches tunnel, direct-via-gw and blackhole routes
	}
	for _, a := range e.pinned {
		_ = hostRouteDel(a)
	}
	e.routed = nil
	e.pinned = nil
}

func (e *RealEngine) addRoute(prefix netip.Prefix) error {
	if e.routeAddFunc != nil {
		return e.routeAddFunc(prefix, e.iface)
	}
	return routeAdd(prefix, e.iface)
}

func (e *RealEngine) delRoute(prefix netip.Prefix) error {
	if e.routeDelFunc != nil {
		return e.routeDelFunc(prefix)
	}
	return routeDelAny(prefix)
}

func (e *RealEngine) Peers() []types.Key {
	e.mu.Lock()
	defer e.mu.Unlock()
	keys := make([]types.Key, 0, len(e.cfg.Peers))
	for _, p := range e.cfg.Peers {
		keys = append(keys, p.PublicKey)
	}
	return keys
}

func (e *RealEngine) Down() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.up {
		return nil
	}
	e.clearRoutesLocked()
	if runtime.GOOS == "darwin" && e.darwinDevice != nil {
		e.stopDarwinDeviceLocked()
	} else {
		e.stopDarwinProcessLocked()
		deleteInterface(e.log, e.iface)
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(filepath.Join(e.confDir, WindowsTunnelName+".conf"))
		e.windowsApplied = false
	}
	e.up = false
	e.log.Info("wg: interface down", "iface", e.iface)
	return nil
}

func (e *RealEngine) Close() error { return e.Down() }

// DataPlaneRecoveryEnabled limits in-process rebuilds to macOS for now. Linux
// kernel WireGuard and the Windows tunnel service have different ownership and
// supervision semantics; their existing service managers remain authoritative.
func (e *RealEngine) DataPlaneRecoveryEnabled() bool { return runtime.GOOS == "darwin" }

// RecoverDataPlane tears down a failed macOS wireguard-go process, creates a
// fresh utun, and reapplies the last complete configuration. It is intentionally
// idempotent: if the interface has recovered before the watchdog fires, no
// routes or processes are touched.
func (e *RealEngine) RecoverDataPlane() error {
	return e.recoverDataPlane(false)
}

// RecoverNetworkPath forces a macOS socket/utun rebuild after the persistent
// WireGuard bind reports that its former physical source path no longer exists.
// IPC health alone cannot detect this state after Wi-Fi/hotspot roaming.
func (e *RealEngine) RecoverNetworkPath() error {
	return e.recoverDataPlane(true)
}

func (e *RealEngine) recoverDataPlane(force bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("wgengine: automatic data-plane recovery is unsupported on %s", runtime.GOOS)
	}
	if !force && e.interfaceHealthyLocked() {
		return nil
	}

	cfg := e.cfg
	oldIface := e.iface
	legacyExternal := e.darwinDevice == nil && e.darwinProcess != nil
	e.log.Warn("wg: rebuilding macOS data plane", "iface", oldIface, "networkPathReset", force)
	e.clearRoutesLocked()
	if e.darwinDevice != nil {
		e.stopDarwinDeviceLocked()
	} else {
		e.stopDarwinProcessLocked()
		deleteInterface(e.log, oldIface)
	}
	e.up = false
	e.iface = ""

	if legacyExternal {
		iface, process, done, err := createUtunDarwinManaged(e.log)
		if err != nil {
			return fmt.Errorf("wgengine: recover interface: %w", err)
		}
		e.iface, e.darwinProcess, e.darwinDone, e.up = iface, process, done, true
		if err := e.reconfigureUnixLocked(cfg); err != nil {
			e.stopDarwinProcessLocked()
			deleteInterface(e.log, e.iface)
			e.up, e.iface = false, ""
			return fmt.Errorf("wgengine: recover configuration: %w", err)
		}
		e.log.Info("wg: macOS data plane recovered", "oldIface", oldIface, "iface", iface, "peers", len(cfg.Peers))
		return nil
	}

	iface, err := e.startDarwinDeviceLocked()
	if err != nil {
		return fmt.Errorf("wgengine: recover interface: %w", err)
	}
	e.iface = iface
	e.up = true
	if err := e.reconfigureDarwinLocked(cfg); err != nil {
		e.stopDarwinDeviceLocked()
		e.up = false
		e.iface = ""
		return fmt.Errorf("wgengine: recover configuration: %w", err)
	}
	e.log.Info("wg: macOS data plane recovered", "oldIface", oldIface, "iface", iface, "peers", len(cfg.Peers))
	return nil
}

func (e *RealEngine) interfaceHealthyLocked() bool {
	if !e.up || e.iface == "" {
		return false
	}
	if runtime.GOOS == "darwin" && e.darwinDevice != nil {
		_, err := e.darwinDevice.IpcGet()
		return err == nil
	}
	return exec.Command("wg", "show", e.iface, "dump").Run() == nil
}

func (e *RealEngine) stopDarwinDeviceLocked() {
	if e.darwinDevice != nil {
		e.darwinDevice.Close()
	}
	e.darwinDevice = nil
	e.darwinTun = nil
	e.stunBind = nil
}

func (e *RealEngine) stopDarwinProcessLocked() {
	if runtime.GOOS != "darwin" || e.darwinProcess == nil {
		return
	}
	process, done := e.darwinProcess, e.darwinDone
	e.darwinProcess = nil
	e.darwinDone = nil
	_ = process.Signal(os.Interrupt)
	if done != nil {
		select {
		case <-done:
			return
		case <-time.After(2 * time.Second):
		}
	}
	_ = process.Kill()
	if done != nil {
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}

// PeerStats implements PeerStatsReporter by parsing `wg show <iface> dump`. The
// per-peer line is: pubkey, psk, endpoint, allowed-ips, last-handshake(unix),
// rx-bytes, tx-bytes, keepalive (tab-separated); the first line is the interface.
func (e *RealEngine) PeerStats() (map[types.Key]PeerStat, error) {
	e.mu.Lock()
	iface := e.iface
	dev := e.darwinDevice
	e.mu.Unlock()
	if iface == "" {
		return nil, nil
	}
	if runtime.GOOS == "darwin" && dev != nil {
		out, err := dev.IpcGet()
		if err != nil {
			return nil, err
		}
		return parseUAPIPeerStats(out), nil
	}
	wgCommand := "wg"
	if runtime.GOOS == "windows" {
		path, err := wgWindowsPath()
		if err != nil {
			return nil, err
		}
		wgCommand = path
	}
	out, err := exec.Command(wgCommand, "show", iface, "dump").Output()
	if err != nil {
		return nil, err
	}
	res := make(map[types.Key]PeerStat)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue // interface line or malformed
		}
		key, err := types.ParseKey(f[0])
		if err != nil {
			continue // the interface line's first field is the private key
		}
		var st PeerStat
		if endpoint, err := netip.ParseAddrPort(f[2]); err == nil {
			st.Endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
		}
		if secs, err := strconv.ParseInt(f[4], 10, 64); err == nil && secs != 0 {
			st.LatestHandshake = time.Unix(secs, 0)
		}
		if rx, err := strconv.ParseInt(f[5], 10, 64); err == nil {
			st.RxBytes = rx
		}
		if tx, err := strconv.ParseInt(f[6], 10, 64); err == nil {
			st.TxBytes = tx
		}
		res[key] = st
	}
	return res, nil
}

func parseUAPIPeerStats(out string) map[types.Key]PeerStat {
	res := make(map[types.Key]PeerStat)
	var key types.Key
	var haveKey bool
	var stat PeerStat
	commit := func() {
		if haveKey {
			res[key] = stat
		}
	}
	for _, line := range strings.Split(out, "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch name {
		case "public_key":
			commit()
			raw, err := hex.DecodeString(value)
			haveKey = err == nil && len(raw) == len(key)
			key, stat = types.Key{}, PeerStat{}
			if haveKey {
				copy(key[:], raw)
			}
		case "last_handshake_time_sec":
			if secs, err := strconv.ParseInt(value, 10, 64); err == nil && secs != 0 {
				stat.LatestHandshake = time.Unix(secs, 0)
			}
		case "last_handshake_time_nsec":
			if nanos, err := strconv.ParseInt(value, 10, 64); err == nil && !stat.LatestHandshake.IsZero() {
				stat.LatestHandshake = stat.LatestHandshake.Add(time.Duration(nanos))
			}
		case "rx_bytes":
			if rx, err := strconv.ParseInt(value, 10, 64); err == nil {
				stat.RxBytes = rx
			}
		case "tx_bytes":
			if tx, err := strconv.ParseInt(value, 10, 64); err == nil {
				stat.TxBytes = tx
			}
		case "endpoint":
			if endpoint, err := netip.ParseAddrPort(value); err == nil {
				stat.Endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
			}
		}
	}
	commit()
	return res
}

func run(log *slog.Logger, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("command failed", "cmd", name, "args", args, "output", string(out))
	}
	return err
}
