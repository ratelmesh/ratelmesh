# RatelMesh client CLI reference

This repository builds `ratelmeshd` (client/exit daemon) and `ratelmesh` (local
CLI). The real WireGuard data plane requires the `-tags wgreal` build; the
default build uses a rootless stub.

## ratelmeshd — client / exit daemon

| Flag | Purpose |
|------|---------|
| `-coord` | Coord base URL (env `RATELMESH_COORD`) |
| `-authkey` | Auth key or OIDC ID token presented to the coord (env `RATELMESH_AUTHKEY`) |
| `-hostname` / `-tags` | Device name; ACL tags |
| `-role plain\|exit\|subnet-router` | Node role |
| `-advertise-routes` | Subnet-router CIDRs to advertise |
| `-accept-routes` | Accept subnet routes advertised by subnet routers |
| `-enable-nat` | Exit node: forward + masquerade mesh traffic (Linux root) |
| `-verify-key <b64>` | Key-authority public key; drop peers whose credential fails to verify (§5) |
| `-kill-switch` | Fail closed while an exit is selected (default on macOS; protects both IPv4 and IPv6) |
| `-tunnel-dns` | Resolver used while an exit is active (DNS-leak protection) |
| `-split-tunnel <file>` | Split-tunnel ruleset (direct/tunnel/block by domain/CIDR/GeoIP) |
| `-magic-dns` | Run MagicDNS on loopback + take over the system resolver (default on macOS; disable with `-magic-dns=false`) |
| `-dns-addr` | Bind MagicDNS on a specific address |
| `-stun` | STUN server for public-endpoint discovery |
| `-gui <addr>` | Serve the local web control panel |
| `-port` / `-state` / `-socket` | WireGuard port (`0`, the default, derives a stable per-device port); state dir; local API socket (Windows: named pipe) |

The state directory also contains `netmap-lkg.json`, an atomic, mode-`0600`,
device-authenticated last-known-good snapshot. On restart `ratelmeshd` restores
that map before contacting the Coordinator. Lower versions and different maps
claiming the same version are rejected.
The automatic WireGuard port is derived from the persisted node identity, so it
survives upgrades but differs between devices sharing one Wi-Fi/NAT. Set
`-port` only when an operator needs a fixed manual port.

## ratelmesh — local CLI

Reads the daemon socket from `$RATELMESH_SOCKET` (default `<state>/ratelmeshd.sock`).
On Windows the default local transport is the ACL-protected
`\\.\pipe\RatelMesh` named pipe.

```
ratelmesh status [--json]     mesh state, peers, active exit, kill switch, DNS
ratelmesh exit list           available exit nodes
ratelmesh exit use <name>     route all traffic through an exit
ratelmesh exit clear          resume direct egress
ratelmesh dns <name>          resolve a MagicDNS name
```

Output is localized (`ratelmesh --lang <locale>`, `RATELMESH_LANG` or `LANG`):
en, zh-Hans, ja. `--lang` overrides the environment for that command; set
`RATELMESH_LANG` in the user or service environment to keep the choice.

## macOS availability and uninstall

The menu app includes **Keep internet available if RatelMesh fails**. When enabled,
RatelMesh does not arm its fail-closed kill switch. A stale exit handshake or repeated
WireGuard health-check failure withdraws the full-tunnel routes so the Mac can
use its physical connection. This favors availability but can expose the Mac's
real public IP while the exit is unavailable. The choice persists across daemon
and system restarts.

Use **Uninstall…** in the menu app for a confirmed, administrator-authorized
removal. It stops the menu agent and daemon, removes RatelMesh's IPv4/IPv6 full-tunnel
routes, restores pf and any loopback DNS takeover, then removes applications,
device identity, logs, launchd definitions and package receipts. The same helper
can be run directly:

```sh
sudo /usr/local/ratelmesh/bin/ratelmesh-uninstall
```
