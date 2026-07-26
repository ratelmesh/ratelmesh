# RatelMesh

> The AI teammate that helps you secure and manage your digital life.

A WireGuard-based product that is **both** a Tailscale-style mesh network (zero-config
device overlay, NAT traversal, ACLs) **and** a NordVPN-style VPN with global exit nodes.
The unifying idea: an exit node is just a mesh peer whose `AllowedIPs` is `0.0.0.0/0`.
See [`DESIGN.md`](DESIGN.md) for the full architecture.

Long-lived company, infrastructure, domain, and release decisions are recorded in
[`docs/project-context.md`](docs/project-context.md). Keep that document free of
credentials and customer-identifying data.

## Status

All major sections of `DESIGN.md` are implemented and tested (`go test -race` green).
The WireGuard data plane is behind an interface: the
default build uses a rootless **stub** (so all control logic runs anywhere, including CI);
the real userspace/kernel data plane is behind `-tags wgreal`.

What runs today, end to end:

- **Mesh (Tailscale-style):** device registration, `100.64.0.0/10` allocation, long-poll
  netmap, STUN endpoint discovery + hole-punching with direct/relay path selection,
  DERP-style relay, MagicDNS (`device.user.ratelmesh.net`), subnet routers (`--accept-routes`).
- **Exit (NordVPN-style):** `ratelmesh exit use <region>`, default-route capture through the
  chosen exit, kill switch (fail-closed pf/nftables), DNS-leak protection.
- **Anti-censorship (§8):** pluggable obfuscation transport (look-like-nothing ChaCha20)
  wired into the relay, split-tunnel routing engine (domain/CIDR/GeoIP → direct/tunnel/block).
- **Control & security:** ACL policy engine with server-side netmap trimming, authkeys
  (reusable/ephemeral/tagged), web admin console (`/admin`).
- **Clients:** Linux/macOS daemon + CLI/web GUI; Windows WireGuard service + named-pipe
  CLI/web GUI; native SwiftUI iOS Packet Tunnel and Android Compose/VpnService apps.

Remaining work is release productionization: Authenticode/App Store/Play signing,
physical-device roaming E2E, publisher privacy-policy hosting and store-account submission,
and multi-writer PostgreSQL state. See the status note at the top of `DESIGN.md`.

## Components

| Binary | Role |
|--------|------|
| `ratelmesh-coord` | Control plane: registration, IP allocation, netmap long-poll, ACLs, authkeys, `/admin` console |
| `ratelmeshd` | Client daemon: identity, control connection, data plane, magicsock, MagicDNS, kill switch, local API + web GUI |
| `ratelmesh` | CLI front-end: `status`, `exit use/list/clear`, `dns` (localized) |
| `ratelmesh-relay` | DERP-style ciphertext relay + co-located STUN, optional obfuscation |
| `mobile/` | gomobile control/data-plane contract shared by iOS and Android |
| `clients/windows/` | Windows packaging, DPAPI config and scheduled-task installer |
| `clients/ios/` | SwiftUI app + `NEPacketTunnelProvider` + WireGuardKit |
| `clients/android/` | Compose app + foreground service + WireGuard GoBackend |

## Build

```sh
make build          # builds bin/{ratelmesh-coord,ratelmeshd,ratelmesh}
make test           # unit + end-to-end tests (rootless)
make build-wgreal   # real WireGuard data plane (needs wireguard-go + wg at runtime)
make build-windows  # Windows amd64 ratelmeshd+ratelmesh (requires WireGuard for Windows at runtime)
make mobile-ios     # generate RatelMeshMobile.xcframework
make mobile-android # generate ratelmesh-mobile.aar
```

## Try it locally

```sh
# terminal 1 — control plane
./bin/ratelmesh-coord -addr 127.0.0.1:8080

# terminal 2 — first device
./bin/ratelmeshd -coord http://127.0.0.1:8080 -state /tmp/ratelmeshA -socket /tmp/ratelmesha.sock -hostname alice

# terminal 3 — an exit node
./bin/ratelmeshd -coord http://127.0.0.1:8080 -state /tmp/ratelmeshB -socket /tmp/ratelmeshb.sock -hostname tokyo -role exit

# terminal 4 — inspect the mesh
RATELMESH_SOCKET=/tmp/ratelmesha.sock ./bin/ratelmesh status
RATELMESH_SOCKET=/tmp/ratelmesha.sock ./bin/ratelmesh exit list
```

## Layout

```
cmd/            ratelmesh-coord, ratelmeshd, ratelmesh entry points
internal/
  types/        shared data model (keys, Node, Netmap, API contract)
  coord/        control plane: registry, IP allocator, long-poll server
  control/      coord protocol client (used by ratelmeshd)
  daemon/       ratelmeshd core: state, run loop, netmap→data-plane, local API
  wgengine/     data-plane interface + rootless stub + wgreal real engine
clients/
  windows/      Windows installer/runtime packaging
  ios/          SwiftUI + Packet Tunnel Provider
  android/      Compose + Android VPN service
```

Security note: device private keys are generated locally and never sent to the coord
(only public keys are). See `DESIGN.md` §5.
