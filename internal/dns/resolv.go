package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/ratelmesh/ratelmesh/internal/wgengine"
)

// SystemResolver takes over the host's DNS configuration so mesh names resolve
// through the local MagicDNS server, restoring it on shutdown. Linux edits
// /etc/resolv.conf; macOS uses networksetup on the primary service. It also
// reports the pre-existing upstream resolvers so out-of-zone names keep working.
type SystemResolver interface {
	CurrentUpstreams() []string
	Install(serverIP string) error
	Restore() error
	FlushCache() error
}

// NewSystemResolver returns the resolver manager for the host OS.
func NewSystemResolver() SystemResolver {
	switch runtime.GOOS {
	case "linux":
		return &resolvFile{path: "/etc/resolv.conf", backupPath: "/etc/resolv.conf.ratelmesh-backup"}
	case "darwin":
		return &resolvDarwin{}
	case "windows":
		return resolvWindows{}
	default:
		return noopResolver{}
	}
}

type noopResolver struct{}

func (noopResolver) CurrentUpstreams() []string { return nil }
func (noopResolver) Install(string) error       { return nil }
func (noopResolver) Restore() error             { return nil }
func (noopResolver) FlushCache() error          { return nil }

// --- Windows: WireGuard tunnel-service DNS + upstream discovery ---

// resolvWindows discovers the effective DNS servers before the RatelMesh
// tunnel exists. Installation/restoration are intentionally no-ops here: the
// DNS line in the WireGuard for Windows service configuration owns that
// lifecycle atomically with the tunnel adapter.
type resolvWindows struct{}

func (resolvWindows) CurrentUpstreams() []string {
	// Exclude the tunnel adapter by its shared wgengine name so a stale
	// adapter from an unclean previous run cannot feed the MagicDNS server
	// its own address as an "upstream" (a forwarding loop).
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 |
  Where-Object { $_.InterfaceAlias -ne '%s' } |
  ForEach-Object { $_.ServerAddresses }`, wgengine.WindowsTunnelName)
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil
	}
	return parseWindowsDNSUpstreams(string(out))
}

func (resolvWindows) Install(string) error { return nil }
func (resolvWindows) Restore() error       { return nil }
func (resolvWindows) FlushCache() error    { return nil }

func parseWindowsDNSUpstreams(output string) []string {
	seen := make(map[netip.Addr]bool)
	var upstreams []string
	for _, field := range strings.Fields(output) {
		addr, err := netip.ParseAddr(strings.TrimSpace(field))
		if err != nil || addr.IsUnspecified() || addr.IsLoopback() || seen[addr] {
			continue
		}
		seen[addr] = true
		upstreams = append(upstreams, net.JoinHostPort(addr.String(), "53"))
	}
	return upstreams
}

// --- Linux: /etc/resolv.conf ---

type resolvFile struct {
	path       string
	backupPath string
	backup     []byte
	taken      bool
}

func managedResolverContent(data []byte) bool {
	legacyMarker := strings.Join([]string{"managed by h", "bmd"}, "")
	return bytes.Contains(data, []byte("managed by ratelmeshd")) || bytes.Contains(data, []byte(legacyMarker))
}

func (m *resolvFile) CurrentUpstreams() []string {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return nil
	}
	managed := managedResolverContent(data)
	recoveredOriginal := false
	if managed && m.backupPath != "" {
		if original, backupErr := os.ReadFile(m.backupPath); backupErr == nil {
			data = original
			recoveredOriginal = true
		}
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[0] == "nameserver" {
			addr, parseErr := netip.ParseAddr(f[1])
			// A managed file without its durable original contains the MagicDNS
			// listener itself, whether loopback or a mesh address. None of those
			// nameservers are safe forwarding upstreams.
			if parseErr == nil && !addr.IsUnspecified() && !(managed && !recoveredOriginal) {
				out = append(out, net.JoinHostPort(addr.String(), "53"))
			}
		}
	}
	return out
}

func (m *resolvFile) Install(serverIP string) error {
	if data, err := os.ReadFile(m.path); err == nil {
		if managedResolverContent(data) && m.backupPath != "" {
			m.backup, _ = os.ReadFile(m.backupPath)
		} else {
			m.backup = data
			if m.backupPath != "" {
				if info, statErr := os.Lstat(m.backupPath); statErr == nil && !info.Mode().IsRegular() {
					return fmt.Errorf("resolver backup is not a regular file")
				}
				if err := os.WriteFile(m.backupPath, data, 0o600); err != nil {
					return fmt.Errorf("persist resolver backup: %w", err)
				}
			}
		}
	}
	content := fmt.Sprintf("# managed by ratelmeshd (MagicDNS); original backed up\nnameserver %s\n", serverIP)
	if err := os.WriteFile(m.path, []byte(content), 0o644); err != nil {
		return err
	}
	m.taken = true
	return nil
}

func (m *resolvFile) Restore() error {
	if !m.taken {
		return nil
	}
	m.taken = false
	if m.backup == nil {
		return os.Remove(m.path)
	}
	if err := os.WriteFile(m.path, m.backup, 0o644); err != nil {
		return err
	}
	if m.backupPath != "" {
		if err := os.Remove(m.backupPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (m *resolvFile) FlushCache() error { return nil }

// --- macOS: networksetup on the primary service ---

type resolvDarwin struct {
	service         string
	backup          []string // original DNS servers ("Empty" => DHCP)
	recoveredBackup bool     // previous daemon died after installing loopback DNS
	taken           bool
}

func (m *resolvDarwin) CurrentUpstreams() []string {
	// scutil reports the effective resolvers even when networksetup shows DHCP.
	out, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	upstreams := parseDarwinDNSUpstreams(string(out))
	if len(upstreams) > 0 {
		return upstreams
	}
	// launchctl kickstart may SIGKILL the predecessor before Restore runs. In
	// that case macOS still has 127.0.0.1 configured, so scutil exposes no usable
	// forwarding resolver. Recover the DHCP resolver directly from the primary
	// interface and remember that shutdown should restore DHCP (Empty), not the
	// stale loopback address.
	service, serviceErr := primaryService()
	if serviceErr != nil || !onlyLoopbackDNS(currentDNS(service)) {
		return nil
	}
	dev := defaultInterfaceDarwin()
	dhcp, dhcpErr := exec.Command("ipconfig", "getpacket", dev).Output()
	if dhcpErr != nil {
		return nil
	}
	upstreams = parseDarwinDHCPDNS(string(dhcp))
	if len(upstreams) > 0 {
		m.recoveredBackup = true
		m.backup = nil
	}
	return upstreams
}

func onlyLoopbackDNS(servers []string) bool {
	if len(servers) == 0 {
		return false
	}
	for _, raw := range servers {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !addr.IsLoopback() {
			return false
		}
	}
	return true
}

func parseDarwinDHCPDNS(output string) []string {
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "domain_name_server") {
			continue
		}
		start, end := strings.Index(line, "{"), strings.LastIndex(line, "}")
		if start < 0 || end <= start {
			continue
		}
		var upstreams []string
		for _, raw := range strings.Split(line[start+1:end], ",") {
			addr, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err == nil && !addr.IsUnspecified() && !addr.IsLoopback() {
				upstreams = append(upstreams, net.JoinHostPort(addr.String(), "53"))
			}
		}
		return upstreams
	}
	return nil
}

func parseDarwinDNSUpstreams(output string) []string {
	seen := map[string]bool{}
	var res []string
	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// lines like: "nameserver[0] : 192.168.1.1"
		if len(f) == 3 && strings.HasPrefix(f[0], "nameserver[") && f[1] == ":" {
			ip := f[2]
			addr, err := netip.ParseAddr(ip)
			if err == nil && !addr.IsLoopback() && !addr.IsUnspecified() && !seen[ip] {
				seen[ip] = true
				res = append(res, net.JoinHostPort(ip, "53"))
			}
		}
	}
	return res
}

func (m *resolvDarwin) Install(serverIP string) error {
	svc, err := primaryService()
	if err != nil {
		return err
	}
	m.service = svc
	if !m.recoveredBackup {
		m.backup = currentDNS(svc)
	}
	if err := exec.Command("networksetup", "-setdnsservers", svc, serverIP).Run(); err != nil {
		return fmt.Errorf("networksetup set dns: %w", err)
	}
	m.taken = true
	return m.FlushCache()
}

func (m *resolvDarwin) Restore() error {
	if !m.taken {
		return nil
	}
	m.taken = false
	args := []string{"-setdnsservers", m.service}
	if len(m.backup) == 0 {
		args = append(args, "Empty") // restore DHCP-provided DNS
	} else {
		args = append(args, m.backup...)
	}
	if err := exec.Command("networksetup", args...).Run(); err != nil {
		return err
	}
	return m.FlushCache()
}

// FlushCache removes answers learned through the previous upstream. This is
// essential when an exit activates: macOS otherwise keeps poisoned ISP answers
// even after MagicDNS has switched to a clean resolver inside the tunnel.
func (m *resolvDarwin) FlushCache() error {
	if err := exec.Command("dscacheutil", "-flushcache").Run(); err != nil {
		return fmt.Errorf("dscacheutil flush: %w", err)
	}
	if err := exec.Command("killall", "-HUP", "mDNSResponder").Run(); err != nil {
		return fmt.Errorf("mDNSResponder flush: %w", err)
	}
	return nil
}

// primaryService maps the default-route interface to its network service name.
func primaryService() (string, error) {
	dev := defaultInterfaceDarwin()
	if dev == "" {
		return "", fmt.Errorf("no default interface")
	}
	out, err := exec.Command("networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return "", err
	}
	// Blocks look like:
	//   (3) Wi-Fi
	//   (Hardware Port: Wi-Fi, Device: en0)
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Device: "+dev+")") && i > 0 {
			prev := strings.TrimSpace(lines[i-1])
			if idx := strings.Index(prev, ") "); idx >= 0 {
				return prev[idx+2:], nil
			}
		}
	}
	return "", fmt.Errorf("no service for interface %s", dev)
}

func defaultInterfaceDarwin() string {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "interface:" {
			return f[1]
		}
	}
	return ""
}

func currentDNS(service string) []string {
	out, err := exec.Command("networksetup", "-getdnsservers", service).Output()
	if err != nil {
		return nil
	}
	var res []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// "There aren't any DNS Servers set on <svc>." => empty/DHCP.
		if line == "" || strings.HasPrefix(line, "There aren't") {
			continue
		}
		res = append(res, line)
	}
	return res
}
