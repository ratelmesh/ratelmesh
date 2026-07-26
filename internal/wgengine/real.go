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
	"errors"
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
const darwinTunnelMTU = pathSafeTunnelMTU

type RealEngine struct {
	log *slog.Logger

	mu                     sync.Mutex
	up                     bool
	iface                  string // actual interface name (ratelmesh0 on Linux/Windows, utunN on macOS)
	cfg                    Config
	confDir                string
	routeLedgerPath        string
	routed                 []netip.Prefix // Unix routes currently programmed, for teardown
	pinned                 []netip.Addr   // Unix endpoint host-routes pinned to the physical path
	residualRoutes         []netip.Prefix // failed rollback routes retried without dismantling the active plan
	routeOwners            map[netip.Prefix]unixManagedRoute
	pinOwners              map[netip.Addr]unixManagedRoute
	windowsRoutes          []windowsManagedRoute // Windows routes created by us (not pre-existing routes)
	windowsPins            []windowsManagedRoute // subset of windowsRoutes that pins physical transports
	windowsRouteRemoveFunc func(windowsManagedRoute) error
	interfaceDeleteFunc    func(string) error
	routeAddFunc           func(netip.Prefix, string) error
	routeDelFunc           func(netip.Prefix) error
	routeExistsFunc        func(netip.Prefix) (bool, error)
	routeScrubFunc         func(string)
	// physicalDefaultFunc is intentionally distinct from routeDefaultPath:
	// once the EXIT /1 routes are live, a normal destination lookup resolves
	// through the tunnel. Endpoint-pin refreshes must instead read the physical
	// /0 route or they can pin the new coordinator/relay address back to utun.
	physicalDefaultFunc func(netip.Addr) (netip.Addr, string)
	routeViaFunc        func(netip.Prefix, netip.Addr, string) error
	hostRouteDelFunc    func(netip.Addr) error
	hostRouteExistsFunc func(netip.Addr) (bool, error)
	routesScrubbed      bool
	routesApplied       bool

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
// so the daemon can allow traffic out it in the kill switch.
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
	addedPins, err := e.stageEndpointPinsLocked(cfg)
	if err != nil {
		return err
	}
	keepPins := false
	defer func() {
		if !keepPins {
			e.rollbackStagedPinsLocked(addedPins)
		}
	}()
	uapi := UAPIConfigUpdate(cfg, e.cfg)
	if len(e.cfg.Peers) == 0 {
		uapi = UAPIConfig(cfg)
	}
	if err := e.darwinDevice.IpcSet(uapi); err != nil {
		return fmt.Errorf("wgengine: in-process UAPI configure: %w", err)
	}
	// From this point the new endpoint is live, so its successfully staged pin
	// must survive any unrelated address/route error and the next call can retry
	// deterministically without mistaking an old pin for the new endpoint.
	keepPins = true
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
	addedPins, err := e.stageEndpointPinsLocked(cfg)
	if err != nil {
		return err
	}
	keepPins := false
	defer func() {
		if !keepPins {
			e.rollbackStagedPinsLocked(addedPins)
		}
	}()
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
	keepPins = true
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
	// Tear down the previous service before resolving the physical default
	// path. Otherwise a previous full-tunnel route can be mistaken for the LAN
	// route and endpoint/direct-route exceptions will point back into ratelmesh0.
	if err := e.clearRoutesWithRetriesLocked(2); err != nil {
		return fmt.Errorf("wgengine: cannot clear previous Windows route plan: %w", err)
	}
	// A missing service is expected on the first configuration, so do not emit
	// an error-level command log for that case.
	if err := deleteInterface(e.log, e.iface); err != nil {
		return fmt.Errorf("wgengine: remove previous Windows tunnel before reconfigure: %w", err)
	}
	e.windowsApplied = false

	plan := planWindowsRoutes(cfg)
	// Pin the exit endpoints to the physical path BEFORE the service installs
	// the /1 halves, so packets to the exit never route into the tunnel itself
	// (the Unix path does the same via pinEndpoint).
	for _, addr := range plan.pins {
		p := netip.PrefixFrom(addr, addr.BitLen())
		gwAddr, gwDev := windowsPhysicalDefaultPathFor(addr.Is6())
		if !gwAddr.IsValid() && gwDev == "" {
			return errors.Join(
				fmt.Errorf("wgengine: cannot resolve the physical Windows path for exit endpoint %s", addr),
				e.clearRoutesWithRetriesLocked(2),
			)
		}
		managed := windowsManagedRoute{
			prefix: p, interfaceIndex: gwDev, nextHop: windowsRouteNextHop(p, gwAddr),
		}
		if err := e.installWindowsRoute(managed, true, func() (bool, error) {
			return windowsCreateRoute(p, gwAddr, gwDev, false)
		}); err != nil {
			return errors.Join(
				fmt.Errorf("wgengine: pin Windows exit endpoint %s: %w", addr, err),
				e.clearRoutesWithRetriesLocked(2),
			)
		}
	}

	if err := atomicfile.WriteFile(confPath, []byte(windowsTunnelConfig(cfg))); err != nil {
		return errors.Join(
			fmt.Errorf("wgengine: write Windows tunnel config: %w", err),
			e.clearRoutesWithRetriesLocked(2),
		)
	}
	if err := secureWindowsConfig(confPath); err != nil {
		return errors.Join(err, e.clearRoutesWithRetriesLocked(2))
	}
	if err := run(e.log, manager, "/installtunnelservice", confPath); err != nil {
		return errors.Join(
			fmt.Errorf("wgengine: install Windows tunnel service (run ratelmeshd as Administrator): %w", err),
			e.clearRoutesWithRetriesLocked(2),
		)
	}
	if err := waitWindowsTunnel(e.iface, 10*time.Second); err != nil {
		cleanupErr := e.clearRoutesWithRetriesLocked(2)
		_ = run(e.log, manager, "/uninstalltunnelservice", e.iface)
		return errors.Join(err, cleanupErr)
	}

	if plan.hasDefault {
		for _, p := range plan.direct {
			gwAddr, gwDev := windowsPhysicalDefaultPathFor(p.Addr().Is6())
			if !gwAddr.IsValid() && gwDev == "" {
				cleanupErr := e.clearRoutesWithRetriesLocked(2)
				_ = run(e.log, manager, "/uninstalltunnelservice", e.iface)
				return errors.Join(
					fmt.Errorf("wgengine: cannot resolve the physical Windows path for direct route %s", p),
					cleanupErr,
				)
			}
			managed := windowsManagedRoute{
				prefix: p, interfaceIndex: gwDev, nextHop: windowsRouteNextHop(p, gwAddr),
			}
			if err := e.installWindowsRoute(managed, false, func() (bool, error) {
				return windowsCreateRoute(p, gwAddr, gwDev, false)
			}); err != nil {
				cleanupErr := e.clearRoutesWithRetriesLocked(2)
				_ = run(e.log, manager, "/uninstalltunnelservice", e.iface)
				return errors.Join(
					fmt.Errorf("wgengine: add Windows direct route %s: %w", p, err),
					cleanupErr,
				)
			}
		}
		for _, p := range plan.block {
			managed := windowsManagedRoute{
				prefix: p, interfaceIndex: "1", nextHop: windowsRouteNextHop(p, netip.Addr{}),
			}
			if err := e.installWindowsRoute(managed, false, func() (bool, error) {
				return windowsCreateRoute(p, netip.Addr{}, "1", true)
			}); err != nil {
				cleanupErr := e.clearRoutesWithRetriesLocked(2)
				_ = run(e.log, manager, "/uninstalltunnelservice", e.iface)
				return errors.Join(
					fmt.Errorf("wgengine: add Windows block route %s: %w", p, err),
					cleanupErr,
				)
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
	desired := make(map[windowsManagedRoute]bool, len(plan.pins))
	for _, addr := range plan.pins {
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		gwAddr, gwDev := windowsPhysicalDefaultPathFor(addr.Is6())
		if !gwAddr.IsValid() && gwDev == "" {
			return func() {}, fmt.Errorf("wgengine: cannot resolve the live physical Windows path for %s", addr)
		}
		route := windowsManagedRoute{
			prefix: prefix, interfaceIndex: gwDev, nextHop: windowsRouteNextHop(prefix, gwAddr),
		}
		desired[route] = true
		if slices.Contains(e.windowsPins, route) {
			continue
		}
		if err := e.installWindowsRoute(route, true, func() (bool, error) {
			return windowsCreateRoute(prefix, gwAddr, gwDev, false)
		}); err != nil {
			return func() {}, fmt.Errorf("wgengine: stage Windows endpoint pin %s: %w", addr, err)
		}
	}

	return func() {
		for _, route := range append([]windowsManagedRoute(nil), e.windowsPins...) {
			if desired[route] {
				continue
			}
			if err := e.removeWindowsRoute(route); err != nil {
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
	residualErr := e.removeResidualRoutesLocked()
	// Netmap refreshes and path probes routinely change transport candidates
	// without changing any tunnel/direct/block route. Removing the live /1
	// defaults for those updates creates a brief physical-gateway window on
	// macOS and stalls active streams. Reconcile endpoint host-route pins in
	// place, but leave the tunnel route plan untouched.
	if e.routesApplied && unixTunnelRouteInputsEqual(e.cfg, cfg) {
		e.reconcilePinnedRoutes(cfg)
		if residualErr != nil {
			e.log.Warn("wg: deferred route rollback still pending", "err", residualErr)
		}
		return nil
	}
	if residualErr != nil {
		return fmt.Errorf("wgengine: clear deferred rollback before changing route plan: %w", residualErr)
	}
	if err := e.clearRoutesPreservingPinsLocked(desiredPinnedEndpointSet(cfg)); err != nil {
		return fmt.Errorf("wgengine: clear previous route plan: %w", err)
	}
	failRoute := func(kind string, prefix netip.Prefix, err error) error {
		// WireGuard already accepted cfg before route programming. Preserve the
		// desired endpoint pins so the now-live endpoint remains reachable; mark
		// routes unapplied and let the next Reconfigure retry deterministically.
		cleanupErr := e.clearRoutesPreservingPinsLocked(desiredPinnedEndpointSet(cfg))
		return errors.Join(
			fmt.Errorf("wgengine: install %s route %s: %w", kind, prefix, err),
			cleanupErr,
		)
	}

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
	pinned := make(map[netip.Addr]bool, len(e.pinned))
	for _, addr := range e.pinned {
		pinned[addr.Unmap()] = true
	}
	pin := func(addr netip.Addr) {
		addr = addr.Unmap()
		if !hasDefault || !addr.IsValid() || pinned[addr] {
			return
		}
		gateway, device := e.physicalDefaultPath(addr)
		if !gateway.IsValid() && device == "" {
			return
		}
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		owner := unixManagedRoute{prefix: prefix, gateway: gateway, device: device, kind: unixRoutePin}
		if err := e.installManagedPin(addr, owner, func() error {
			return e.routeVia(prefix, gateway, device)
		}); err == nil {
			pinned[addr] = true
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
			owner := unixManagedRoute{prefix: a, device: e.iface, kind: unixRouteTunnel}
			if err := e.installManagedRoute(owner, func() error { return e.addRoute(a) }); err != nil {
				return failRoute("tunnel", a, err)
			}
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
					owner := unixManagedRoute{prefix: half, device: e.iface, kind: unixRouteTunnel}
					if err := e.installManagedRoute(owner, func() error { return e.addRoute(half) }); err != nil {
						return failRoute("default", half, err)
					}
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
					owner := unixManagedRoute{prefix: half, device: e.iface, kind: unixRouteTunnel}
					if err := e.installManagedRoute(owner, func() error { return e.addRoute(half) }); err != nil {
						// Roll back a partially installed IPv6 pair, but retain the
						// working IPv4 tunnel routes.
						if cleanupErr := e.removeRoutedFromLocked(start); cleanupErr != nil {
							e.deferFailedRollbackLocked(start)
							e.log.Warn("wg: IPv6 partial rollback retained routes for retry", "err", cleanupErr)
						}
						e.log.Warn("wg: IPv6 default route unavailable; continuing with fail-closed IPv4 tunnel", "route", half, "err", err)
						break
					}
				}
			}
			// Split tunnel: "direct" CIDRs bypass the tunnel via the physical
			// gateway; "block" CIDRs are blackholed. These are more specific than
			// the /1 halves, so they win (DESIGN.md §8.4).
			for _, d := range cfg.DirectRoutes {
				gwAddr, gwDev := e.physicalDefaultPath(d.Addr())
				if gwAddr.IsValid() || gwDev != "" {
					owner := unixManagedRoute{prefix: d, gateway: gwAddr, device: gwDev, kind: unixRouteDirect}
					if err := e.installManagedRoute(owner, func() error {
						return e.routeVia(d, gwAddr, gwDev)
					}); err != nil {
						return failRoute("direct", d, err)
					}
				}
			}
			for _, b := range cfg.BlockRoutes {
				owner := unixManagedRoute{prefix: b, kind: unixRouteBlackhole}
				if err := e.installManagedRoute(owner, func() error { return routeBlackhole(b) }); err != nil {
					return failRoute("blackhole", b, err)
				}
			}
		}
	}
	// A fail-closed IPv6 partial rollback may leave a harmless tunnel route in
	// the residual ledger. Keep the working IPv4 plan active; later refreshes
	// retry only the residual route instead of dismantling the live plan.
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
	var default4, default6 bool
	for _, peer := range cfg.Peers {
		for _, allowed := range peer.AllowedIPs {
			if allowed.Bits() != 0 {
				continue
			}
			if allowed.Addr().Is4() {
				default4 = true
			} else {
				default6 = true
			}
		}
	}
	if !default4 && !default6 {
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
		if addr.Is4() && default4 || addr.Is6() && default6 {
			add(addr)
		}
	}
	for _, peer := range cfg.Peers {
		var peerDefault4, peerDefault6 bool
		for _, allowed := range peer.AllowedIPs {
			if allowed.Bits() == 0 {
				peerDefault4 = peerDefault4 || allowed.Addr().Is4()
				peerDefault6 = peerDefault6 || allowed.Addr().Is6()
			}
		}
		if !peerDefault4 && !peerDefault6 {
			continue
		}
		if endpoint, err := netip.ParseAddrPort(FirstRenderableEndpoint(peer.Endpoints)); err == nil {
			if endpoint.Addr().Is4() && peerDefault4 || endpoint.Addr().Is6() && peerDefault6 {
				add(endpoint.Addr())
			}
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

	kept := make([]netip.Addr, 0, len(desired))
	wanted := make(map[netip.Addr]bool, len(desired))
	refreshComplete := true
	for _, addr := range desired {
		wanted[addr] = true
		if current[addr] {
			kept = append(kept, addr)
			continue
		}
		gwAddr, gwDev := e.physicalDefaultPath(addr)
		if !gwAddr.IsValid() && gwDev == "" {
			e.log.Warn("wg: cannot resolve physical default for endpoint refresh", "endpoint", addr)
			refreshComplete = false
			continue
		}
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		owner := unixManagedRoute{prefix: prefix, gateway: gwAddr, device: gwDev, kind: unixRoutePin}
		if err := e.installManagedPin(addr, owner, func() error {
			return e.routeVia(prefix, gwAddr, gwDev)
		}); err != nil {
			e.log.Warn("wg: cannot pin refreshed physical endpoint", "endpoint", addr, "err", err)
			refreshComplete = false
			continue
		}
		kept = append(kept, addr)
	}
	// Add replacements first, then remove obsolete pins so a roaming peer never
	// loses every physical transport route during the refresh.
	for _, addr := range e.pinned {
		if !wanted[addr] {
			if refreshComplete {
				if err := e.delHostRoute(addr); err != nil {
					e.log.Warn("wg: remove replaced endpoint pin failed", "endpoint", addr, "err", err)
					kept = append(kept, addr)
				}
			} else {
				// A failed replacement is retried on the next refresh. Keep the
				// last known recovery path until every new pin is established.
				kept = append(kept, addr)
			}
		}
	}
	e.pinned = kept
}

func (e *RealEngine) physicalDefaultPath(target netip.Addr) (netip.Addr, string) {
	if e.physicalDefaultFunc != nil {
		return e.physicalDefaultFunc(target)
	}
	return unixPhysicalDefaultPath(target, e.iface)
}

func (e *RealEngine) routeVia(prefix netip.Prefix, gateway netip.Addr, device string) error {
	if e.routeViaFunc != nil {
		return e.routeViaFunc(prefix, gateway, device)
	}
	return routeVia(prefix, gateway, device)
}

func (e *RealEngine) delHostRoute(addr netip.Addr) error {
	var err error
	if e.hostRouteDelFunc != nil {
		err = e.hostRouteDelFunc(addr)
	} else {
		owner, ok := e.pinOwners[addr.Unmap()]
		if !ok {
			return fmt.Errorf("wgengine: no ownership identity for endpoint pin %s", addr)
		}
		err = deleteUnixManagedRoute(owner)
	}
	if err == nil {
		delete(e.pinOwners, addr.Unmap())
		return e.persistRouteLedgerLocked()
	}
	if routeDeleteNotFound(err) {
		delete(e.pinOwners, addr.Unmap())
		return e.persistRouteLedgerLocked()
	}
	// Route deletion tools return an error both when the exact host route is
	// already absent and when a real kernel failure leaves it behind. Query the
	// exact route before retaining ownership: phantom ledger entries otherwise
	// block a later pin from being rebuilt after roaming.
	var (
		exists    bool
		verifyErr error
	)
	if e.hostRouteExistsFunc != nil {
		exists, verifyErr = e.hostRouteExistsFunc(addr)
	} else if e.hostRouteDelFunc != nil {
		// Test/embedded deletion hooks predate exact-query injection. Preserve
		// their conservative semantics unless the caller supplies a verifier.
		exists = true
	} else {
		exists, verifyErr = unixManagedRouteExists(e.pinOwners[addr.Unmap()])
	}
	if verifyErr != nil {
		return errors.Join(err, fmt.Errorf("verify host route %s after delete: %w", addr, verifyErr))
	}
	if !exists {
		delete(e.pinOwners, addr.Unmap())
		return e.persistRouteLedgerLocked()
	}
	return err
}

// stageEndpointPinsLocked is the first phase of an endpoint update. Every new
// physical transport address is host-routed before WireGuard sees the new UAPI
// endpoint. If any pin cannot be established, all pins from this attempt are
// rolled back and the caller leaves the old UAPI configuration committed.
func (e *RealEngine) stageEndpointPinsLocked(cfg Config) ([]netip.Addr, error) {
	desired := desiredPinnedEndpoints(cfg)
	current := make(map[netip.Addr]bool, len(e.pinned))
	for _, addr := range e.pinned {
		current[addr.Unmap()] = true
	}
	var added []netip.Addr
	for _, addr := range desired {
		addr = addr.Unmap()
		if current[addr] {
			continue
		}
		gateway, device := e.physicalDefaultPath(addr)
		if !gateway.IsValid() && device == "" {
			e.rollbackStagedPinsLocked(added)
			return nil, fmt.Errorf("wgengine: cannot resolve physical path for endpoint %s", addr)
		}
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		owner := unixManagedRoute{prefix: prefix, gateway: gateway, device: device, kind: unixRoutePin}
		if err := e.installManagedPin(addr, owner, func() error {
			return e.routeVia(prefix, gateway, device)
		}); err != nil {
			e.rollbackStagedPinsLocked(added)
			return nil, fmt.Errorf("wgengine: pin endpoint %s before configuration switch: %w", addr, err)
		}
		current[addr] = true
		added = append(added, addr)
	}
	return added, nil
}

func (e *RealEngine) rollbackStagedPinsLocked(added []netip.Addr) {
	if len(added) == 0 {
		return
	}
	remove := make(map[netip.Addr]bool, len(added))
	for _, addr := range added {
		if err := e.delHostRoute(addr); err != nil {
			// The route still exists in the kernel. Retain it in the ownership
			// ledger so shutdown or a later reconcile retries cleanup.
			e.log.Warn("wg: rollback staged endpoint pin failed", "endpoint", addr, "err", err)
			continue
		}
		remove[addr] = true
	}
	kept := e.pinned[:0]
	for _, addr := range e.pinned {
		if !remove[addr] {
			kept = append(kept, addr)
		}
	}
	e.pinned = kept
}

func desiredPinnedEndpointSet(cfg Config) map[netip.Addr]bool {
	desired := desiredPinnedEndpoints(cfg)
	set := make(map[netip.Addr]bool, len(desired))
	for _, addr := range desired {
		set[addr.Unmap()] = true
	}
	return set
}

func (e *RealEngine) removeRoutedFromLocked(start int) error {
	if start < 0 || start > len(e.routed) {
		return fmt.Errorf("wgengine: invalid route cleanup boundary %d of %d", start, len(e.routed))
	}
	kept := append([]netip.Prefix(nil), e.routed[:start]...)
	var errs []error
	for _, route := range e.routed[start:] {
		if err := e.delRoute(route); err != nil {
			e.log.Warn("wg: remove managed route failed", "route", route, "err", err)
			kept = append(kept, route)
			errs = append(errs, fmt.Errorf("remove managed route %s: %w", route, err))
		}
	}
	e.routed = kept
	return errors.Join(errs...)
}

func (e *RealEngine) installManagedRoute(owner unixManagedRoute, install func() error) error {
	if e.routeOwners == nil {
		e.routeOwners = make(map[netip.Prefix]unixManagedRoute)
	}
	e.routeOwners[owner.prefix] = owner
	if err := e.persistRouteLedgerLocked(); err != nil {
		delete(e.routeOwners, owner.prefix)
		return fmt.Errorf("wgengine: persist route cleanup intent for %s: %w", owner.prefix, err)
	}
	if err := install(); err != nil {
		delete(e.routeOwners, owner.prefix)
		return errors.Join(err, e.persistRouteLedgerLocked())
	}
	if !slices.Contains(e.routed, owner.prefix) {
		e.routed = append(e.routed, owner.prefix)
	}
	return nil
}

func (e *RealEngine) installManagedPin(addr netip.Addr, owner unixManagedRoute, install func() error) error {
	addr = addr.Unmap()
	if e.pinOwners == nil {
		e.pinOwners = make(map[netip.Addr]unixManagedRoute)
	}
	e.pinOwners[addr] = owner
	if err := e.persistRouteLedgerLocked(); err != nil {
		delete(e.pinOwners, addr)
		return fmt.Errorf("wgengine: persist endpoint cleanup intent for %s: %w", addr, err)
	}
	if err := install(); err != nil {
		delete(e.pinOwners, addr)
		return errors.Join(err, e.persistRouteLedgerLocked())
	}
	if !slices.Contains(e.pinned, addr) {
		e.pinned = append(e.pinned, addr)
	}
	return nil
}

func (e *RealEngine) deferFailedRollbackLocked(start int) {
	if start < 0 || start > len(e.routed) {
		return
	}
	for _, prefix := range e.routed[start:] {
		if !slices.Contains(e.residualRoutes, prefix) {
			e.residualRoutes = append(e.residualRoutes, prefix)
		}
	}
	e.routed = e.routed[:start]
}

func (e *RealEngine) removeResidualRoutesLocked() error {
	kept := e.residualRoutes[:0]
	var errs []error
	for _, prefix := range e.residualRoutes {
		if err := e.delRoute(prefix); err != nil {
			kept = append(kept, prefix)
			errs = append(errs, fmt.Errorf("remove deferred route %s: %w", prefix, err))
		}
	}
	e.residualRoutes = kept
	return errors.Join(errs...)
}

func (e *RealEngine) clearRoutesPreservingPinsLocked(preserve map[netip.Addr]bool) error {
	e.routesApplied = false
	var errs []error
	if err := e.removeRoutedFromLocked(0); err != nil {
		errs = append(errs, err)
	}
	if err := e.removeResidualRoutesLocked(); err != nil {
		errs = append(errs, err)
	}
	kept := e.pinned[:0]
	for _, addr := range e.pinned {
		if preserve[addr.Unmap()] {
			kept = append(kept, addr)
		} else {
			if err := e.delHostRoute(addr); err != nil {
				e.log.Warn("wg: remove obsolete endpoint pin failed", "endpoint", addr, "err", err)
				kept = append(kept, addr)
				errs = append(errs, fmt.Errorf("remove endpoint pin %s: %w", addr, err))
			}
		}
	}
	e.pinned = kept
	return errors.Join(errs...)
}

func (e *RealEngine) clearRoutesLocked() error {
	e.routesApplied = false
	if runtime.GOOS == "windows" {
		return e.clearWindowsRoutesLocked()
	}
	var errs []error
	if err := e.removeRoutedFromLocked(0); err != nil {
		errs = append(errs, err)
	}
	if err := e.removeResidualRoutesLocked(); err != nil {
		errs = append(errs, err)
	}
	keptPins := e.pinned[:0]
	for _, addr := range e.pinned {
		if err := e.delHostRoute(addr); err != nil {
			e.log.Warn("wg: remove endpoint pin failed", "endpoint", addr, "err", err)
			keptPins = append(keptPins, addr)
			errs = append(errs, fmt.Errorf("remove endpoint pin %s: %w", addr, err))
		}
	}
	e.pinned = keptPins
	return errors.Join(errs...)
}

func (e *RealEngine) clearWindowsRoutesLocked() error {
	var errs []error
	keptRoutes := e.windowsRoutes[:0]
	for _, route := range e.windowsRoutes {
		if err := e.removeWindowsRoute(route); err != nil {
			e.log.Warn("wg: remove managed Windows route failed", "route", route.prefix, "err", err)
			keptRoutes = append(keptRoutes, route)
			errs = append(errs, fmt.Errorf("remove managed Windows route %s: %w", route.prefix, err))
		}
	}
	e.windowsRoutes = keptRoutes
	e.windowsPins = slices.DeleteFunc(e.windowsPins, func(pin windowsManagedRoute) bool {
		return !slices.Contains(e.windowsRoutes, pin)
	})
	e.routed = nil
	e.pinned = nil
	return errors.Join(errors.Join(errs...), e.persistRouteLedgerLocked())
}

func (e *RealEngine) addRoute(prefix netip.Prefix) error {
	if e.routeAddFunc != nil {
		return e.routeAddFunc(prefix, e.iface)
	}
	return routeAdd(prefix, e.iface)
}

func (e *RealEngine) delRoute(prefix netip.Prefix) error {
	var err error
	if e.routeDelFunc != nil {
		err = e.routeDelFunc(prefix)
	} else {
		owner, ok := e.routeOwners[prefix]
		if !ok {
			return fmt.Errorf("wgengine: no ownership identity for managed route %s", prefix)
		}
		err = deleteUnixManagedRoute(owner)
	}
	if err == nil {
		delete(e.routeOwners, prefix)
		return e.persistRouteLedgerLocked()
	}
	if routeDeleteNotFound(err) {
		delete(e.routeOwners, prefix)
		return e.persistRouteLedgerLocked()
	}
	var (
		exists    bool
		verifyErr error
	)
	if e.routeExistsFunc != nil {
		exists, verifyErr = e.routeExistsFunc(prefix)
	} else if e.routeDelFunc != nil {
		exists = true
	} else {
		exists, verifyErr = unixManagedRouteExists(e.routeOwners[prefix])
	}
	if verifyErr != nil {
		return errors.Join(err, fmt.Errorf("verify route %s after delete: %w", prefix, verifyErr))
	}
	if !exists {
		delete(e.routeOwners, prefix)
		return e.persistRouteLedgerLocked()
	}
	return err
}

func (e *RealEngine) removeWindowsRoute(route windowsManagedRoute) error {
	if e.windowsRouteRemoveFunc != nil {
		return e.windowsRouteRemoveFunc(route)
	}
	return windowsRemoveExactRoute(route)
}

func (e *RealEngine) installWindowsRoute(route windowsManagedRoute, pin bool, install func() (bool, error)) error {
	e.windowsRoutes = append(e.windowsRoutes, route)
	if pin {
		e.windowsPins = append(e.windowsPins, route)
	}
	if err := e.persistRouteLedgerLocked(); err != nil {
		e.windowsRoutes = e.windowsRoutes[:len(e.windowsRoutes)-1]
		if pin {
			e.windowsPins = e.windowsPins[:len(e.windowsPins)-1]
		}
		return fmt.Errorf("wgengine: persist Windows route cleanup intent for %s: %w", route.prefix, err)
	}
	created, err := install()
	if err == nil && !created {
		err = fmt.Errorf("wgengine: route %s conflicts with a pre-existing route", route.prefix)
	}
	if err != nil {
		e.windowsRoutes = e.windowsRoutes[:len(e.windowsRoutes)-1]
		if pin {
			e.windowsPins = e.windowsPins[:len(e.windowsPins)-1]
		}
		return errors.Join(err, e.persistRouteLedgerLocked())
	}
	return nil
}

func (e *RealEngine) clearRoutesWithRetriesLocked(attempts int) error {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for range attempts {
		err = e.clearRoutesLocked()
		if err == nil {
			return nil
		}
	}
	return err
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
	cleanupErr := e.clearRoutesWithRetriesLocked(3)
	if !e.up {
		return cleanupErr
	}
	var interfaceErr error
	if runtime.GOOS == "darwin" && e.darwinDevice != nil {
		e.stopDarwinDeviceLocked()
	} else {
		e.stopDarwinProcessLocked()
		if e.interfaceDeleteFunc != nil {
			interfaceErr = e.interfaceDeleteFunc(e.iface)
		} else {
			interfaceErr = deleteInterface(e.log, e.iface)
		}
	}
	if runtime.GOOS == "windows" && interfaceErr == nil {
		_ = os.Remove(filepath.Join(e.confDir, WindowsTunnelName+".conf"))
		e.windowsApplied = false
	}
	if interfaceErr == nil {
		e.up = false
	}
	e.log.Info("wg: interface down", "iface", e.iface)
	if cleanupErr != nil || interfaceErr != nil {
		err := errors.Join(cleanupErr, interfaceErr)
		e.log.Error("wg: interface down incomplete", "err", err)
		return fmt.Errorf("wgengine: incomplete data-plane teardown: %w", err)
	}
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
	if err := e.clearRoutesWithRetriesLocked(2); err != nil {
		return fmt.Errorf("wgengine: recover data plane: clear old route plan: %w", err)
	}
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
