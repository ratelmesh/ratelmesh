# RatelMesh — CLI reference

Four binaries: `ratelmesh-coord` (control plane), `ratelmeshd` (client/exit daemon), `ratelmesh`
(local CLI), `ratelmesh-relay` (relay). The real WireGuard data plane requires the
`-tags wgreal` build; the default build uses a rootless stub.

## ratelmesh-coord — control plane

| Flag | Purpose |
|------|---------|
| `-addr` | Listen address (default `127.0.0.1:8080`; put TLS in front with Caddy) |
| `-authkey` | Static shared key devices must present (empty = dev mode) |
| `-authkeys` | Authkey mode; issues a reusable bootstrap key at startup |
| `-bootstrap-authkey` | Issue that reusable bootstrap key when no usable key exists (default `true`; set `false` in production) |
| `-oidc-issuer` / `-oidc-audience` / `-oidc-jwks-file` | OIDC login: devices present an ID token as their authkey; user becomes a `user:<email>` ACL tag |
| `-node-authority-key <file>` | Ed25519 key authority; signs node credentials (§5). Logs the public key for `-verify-key` |
| `-policy <file>` | JSON ACL policy (default: same-user-only) |
| `-admin-token` | Gates the `/admin` console |
| `-admin-token-file <file>` | Reads the `/admin` token from a regular file inaccessible to group/other users (recommended for production; env `RATELMESH_ADMIN_TOKEN_FILE`) |
| `-state <path\|postgres://…>` | Durable persistence: a JSON file, or a PostgreSQL DSN |
| `-insecure-dev` | Explicitly allow unauthenticated registration on a non-loopback listener (development/E2E only) |

Auth precedence: OIDC → authkeys → static `-authkey`.
OIDC enrollment binds the ID token to the device key: the token's `nonce` claim
must equal the base64 RatelMesh `NodeKey` submitted in the registration request.
Integrators must pass that value through their authorization request; a generic
ID token minted without this nonce is rejected.
An unauthenticated coord now refuses non-loopback binds unless `-insecure-dev`
is explicitly set; production deployments should use authkeys or OIDC.
Use `-admin-token-file` instead of placing the administrator token in process
arguments or a world-readable service definition. Configure only one of
`-admin-token` and `-admin-token-file`.

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
claiming the same version are rejected; see `docs/control-plane-resilience.md`.
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

## ratelmesh-relay — relay

| Flag | Purpose |
|------|---------|
| `-addr` | Relay TCP listen address (default `:3478`) |
| `-stun` | Co-located STUN UDP address (default `:3479`) |
| `-obfs-secret` | Obfuscation transport (ChaCha20 look-like-nothing) |
| `-tls-camo-sni <name>` | Camouflage the link as HTTPS (real TLS session) |
| `-siblings` | Peer relay addresses to mesh with (cross-relay delivery) |
