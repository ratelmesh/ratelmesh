// Package exitstack makes a node a working VPN exit (the NordVPN data path,
// DESIGN.md §3.3): it enables IP forwarding and masquerades (source-NATs) mesh
// traffic onto the node's uplink, so packets that arrive over WireGuard leave to
// the internet wearing the exit's address and replies come back. The default is
// a no-op so unprivileged/stub builds do nothing; the Linux implementation
// shells out to sysctl + nftables and requires root + NET_ADMIN.
package exitstack

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// NAT programs (and tears down) the exit forwarding/masquerade rules.
type NAT interface {
	Enable(meshCIDR, wgIface string) error
	Disable() error
}

// New returns a platform NAT when enabled (Linux: nftables; macOS: pf;
// Windows: WinNAT),
// otherwise a no-op so unprivileged/stub builds and unsupported OSes do nothing.
func New(enable bool, log *slog.Logger) NAT {
	if log == nil {
		log = slog.Default()
	}
	if enable {
		switch runtime.GOOS {
		case "linux":
			return &linuxNAT{log: log}
		case "darwin":
			return &darwinNAT{log: log}
		case "windows":
			return &windowsNAT{log: log}
		}
	}
	return noop{}
}

type noop struct{}

func (noop) Enable(_, _ string) error { return nil }
func (noop) Disable() error           { return nil }

type windowsNAT struct {
	log   *slog.Logger
	iface string
}

const windowsNATName = "RatelMesh"

func (n *windowsNAT) Enable(meshCIDR, wgIface string) error {
	script := windowsNATEnableScript(meshCIDR, wgIface)
	if err := sh("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script); err != nil {
		return fmt.Errorf("exitstack: enable Windows NAT: %w", err)
	}
	n.iface = wgIface
	n.log.Info("exit NAT enabled (Windows/WinNAT)", "meshCIDR", meshCIDR, "iface", wgIface)
	return nil
}

func (n *windowsNAT) Disable() error {
	if n.iface == "" {
		return nil
	}
	script := windowsNATDisableScript(n.iface)
	n.iface = ""
	if err := sh("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script); err != nil {
		return fmt.Errorf("exitstack: disable Windows NAT: %w", err)
	}
	return nil
}

func windowsNATEnableScript(meshCIDR, wgIface string) string {
	cidr := psSingleQuote(meshCIDR)
	iface := psSingleQuote(wgIface)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$adapter = Get-NetAdapter -Name '%s' -ErrorAction Stop
Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Forwarding Enabled
Get-NetNat -Name '%s' -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false
try {
  New-NetNat -Name '%s' -InternalIPInterfaceAddressPrefix '%s' | Out-Null
} catch {
  Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Forwarding Disabled -ErrorAction SilentlyContinue
  throw
}
`, iface, windowsNATName, windowsNATName, cidr)
}

func windowsNATDisableScript(wgIface string) string {
	iface := psSingleQuote(wgIface)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
Get-NetNat -Name '%s' -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false
$adapter = Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue
if ($null -ne $adapter) {
  Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Forwarding Disabled -ErrorAction SilentlyContinue
}
`, windowsNATName, iface)
}

func psSingleQuote(value string) string { return strings.ReplaceAll(value, "'", "''") }

type linuxNAT struct{ log *slog.Logger }

const natTable = "ratelmesh_nat"

func (n *linuxNAT) Enable(meshCIDR, wgIface string) error {
	// Enable forwarding. If the write fails (e.g. /proc/sys is read-only in a
	// container) but it is already on — set out-of-band via `--sysctl` — proceed.
	if err := sh("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		if !ipForwardEnabled() {
			return fmt.Errorf("exitstack: enable ip_forward: %w", err)
		}
		n.log.Warn("exitstack: ip_forward already enabled out-of-band; continuing")
	}
	// Fresh nftables table with masquerade on egress and forward-accept for the
	// tunnel, so traffic from the mesh is SNAT'd out the uplink. Loaded as one
	// ruleset via `nft -f -` (robust vs. argv token parsing).
	_ = sh("nft", "delete", "table", "ip", natTable) // ignore if absent
	// Note: chain names must avoid nft reserved words (e.g. "fwd"); each rule
	// statement ends on its own line before the closing brace.
	ruleset := fmt.Sprintf(`table ip %s {
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr %s oifname != "%s" counter masquerade
  }
  chain forward {
    type filter hook forward priority 0;
    iifname "%s" accept
    oifname "%s" accept
  }
}
`, natTable, meshCIDR, wgIface, wgIface, wgIface)
	if err := shStdin(ruleset, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("exitstack: nft load: %w", err)
	}
	n.log.Info("exit NAT enabled", "meshCIDR", meshCIDR, "uplink", "masquerade")
	return nil
}

func (n *linuxNAT) Disable() error {
	_ = sh("nft", "delete", "table", "ip", natTable)
	return nil
}

func ipForwardEnabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// darwinNAT makes a macOS host a VPN exit using pf. macOS has no nftables, so it
// enables IPv4 forwarding and installs a pf NAT rule that source-NATs mesh
// traffic onto the default-route uplink. It rebuilds the ruleset PRESERVING the
// system's com.apple anchors (so it does not wipe existing pf rules — the same
// lesson as the kill-switch anchor). Requires root.
type darwinNAT struct {
	log    *slog.Logger
	uplink string
}

func (n *darwinNAT) Enable(meshCIDR, _ string) error {
	if err := sh("sysctl", "-w", "net.inet.ip.forwarding=1"); err != nil {
		return fmt.Errorf("exitstack: enable ip forwarding: %w", err)
	}
	up, err := defaultUplink()
	if err != nil {
		return fmt.Errorf("exitstack: detect uplink: %w", err)
	}
	n.uplink = up
	_ = sh("pfctl", "-e") // enable pf if not already (ignore "already enabled")
	if err := shStdin(darwinPFRuleset(up, meshCIDR), "pfctl", "-f", "-"); err != nil {
		return fmt.Errorf("exitstack: pfctl load: %w", err)
	}
	n.log.Info("exit NAT enabled (macOS/pf)", "meshCIDR", meshCIDR, "uplink", up)
	return nil
}

func (n *darwinNAT) Disable() error {
	// Intentionally a no-op. On macOS the NAT lives in the single global pf
	// ruleset, so restoring /etc/pf.conf here would race with a concurrently
	// (re)starting instance's Enable and wipe its freshly-loaded rule — under
	// launchd KeepAlive, a restart's old-instance Disable kept clobbering the new
	// instance's NAT. Enable is idempotent (it reloads the rule on every start),
	// so leaving the rule in place is correct and race-free. The rule (and
	// forwarding) persist until reboot; a dedicated exit host wants exactly that.
	// A precise teardown (uninstall) is a future refinement.
	n.log.Debug("exit NAT: Disable is a no-op on macOS (rule persists to avoid a pf reload race)")
	return nil
}

// darwinPFRuleset builds a pf ruleset that SNATs meshCIDR out the uplink while
// keeping the system's com.apple anchors, in pf's required section order
// (normalization → translation → filtering).
func darwinPFRuleset(uplink, meshCIDR string) string {
	return fmt.Sprintf(`scrub-anchor "com.apple/*"
nat on %s inet from %s to any -> (%s)
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`, uplink, meshCIDR, uplink)
}

// defaultUplink returns the interface of the default IPv4 route (the machine's
// internet uplink), e.g. "en0".
func defaultUplink() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route get default: %v: %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "interface:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "interface:")), nil
		}
	}
	return "", fmt.Errorf("no default-route interface found")
}

func sh(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, out)
	}
	return nil
}

func shStdin(stdin, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, out)
	}
	return nil
}
