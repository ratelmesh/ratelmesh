# Client platform status

Tenant-controlled SSH/RDP/VNC launch behavior is documented in
[`remote-access.md`](remote-access.md).

| Platform | Data plane | Control/UI | Verification |
|---|---|---|---|
| Linux | Kernel WireGuard or wireguard-go | `ratelmeshd`, `ratelmesh`, local web GUI | race tests + privileged container E2E |
| macOS | wireguard-go on dynamic `utun` | `ratelmeshd`, `ratelmesh`, local web GUI | cross-build + macOS routing tests |
| Windows | Official WireGuard tunnel service/Wintun, adapter MagicDNS, WinNAT exit | named-pipe `ratelmesh`, local web GUI, PowerShell installer | amd64/arm64 PE cross-build; physical Windows E2E required |
| iOS | WireGuardKit in `NEPacketTunnelProvider` | SwiftUI app | unsigned device-SDK build; signed iPhone E2E required |
| Android | Official WireGuard `GoBackend`/`VpnService` | Compose app + foreground lifecycle | Gradle unit/build verification; signed-device E2E required |

The mobile apps run the shared Go coordinator/netmap core from `mobile/`. The
core publishes a versioned WireGuard snapshot to the native tunnel provider and
accepts handshake/RX counters back, so direct-versus-relay decisions remain in
one implementation across platforms.

Desktop and mobile clients persist the authenticated last-known-good netmap in
their state directory. After a process or device restart they publish the restored
WireGuard snapshot before Coordinator synchronization succeeds, so a control-plane
outage does not by itself prevent the native VPN provider from coming back up.

Platform build and signing instructions live in each `clients/<platform>/README.md`.
Generated `.exe` bundles, `.xcframework`, `.aar`, APK and IPA files are build
outputs and are intentionally not committed.
