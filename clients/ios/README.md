# RatelMesh for iOS

This directory contains a SwiftUI container app and an iOS Packet Tunnel
Provider. The provider starts the shared Go control core, waits for its
versioned mobile tunnel configuration, and applies it with WireGuardKit. It
also reports WireGuard handshake/RX counters back to Go and hot-applies later
netmap or exit-node changes.

## Prerequisites

- macOS with Xcode 16 or newer, XcodeGen, Go and rsync.
- A paid Apple Developer team. The App ID and extension App ID must have the
  Network Extensions capability, and both targets must share the registered
  `group.com.ratelmesh.shared` App Group and Keychain group.
- Apple approval/provisioning for Packet Tunnel Provider distribution. This
  repository cannot supply a signing team or provisioning profiles.

## Generate and build

```sh
cd clients/ios
Scripts/build-ratelmesh-mobile.sh
Scripts/prepare-wireguard.sh
xcodegen generate
open RatelMesh.xcodeproj
```

Set `RATELMESH_DEVELOPMENT_TEAM` to your ten-character Apple team ID in Xcode build
settings or on the command line. The two bundle IDs, App Group, and Keychain
group in `project.yml` must match identifiers registered to that team.

`RatelMeshMobile.xcframework` is generated from `mobile/` and intentionally ignored by
Git. Re-run `Scripts/build-ratelmesh-mobile.sh` after changing the Go mobile API. The
script uses a temporary module so the build-only gomobile dependency does not
rewrite the repository's `go.mod`; x/mobile is pinned to
`v0.0.0-20260709172247-6129f5bee9d5` for reproducibility.

WireGuardKit is cloned at the pinned official revision by
`Scripts/prepare-wireguard.sh`. That upstream revision declares Swift tools 5.3
while using platform constants added in 5.5, so the script fixes that manifest
metadata line. It also adds the direct `sys/types.h` import required by Xcode
26 explicit Clang modules. The script also applies the tracked
`Patches/wireguard-apple-selective-network-settings.patch`, which lets endpoint-only
updates avoid resetting stable iOS routes and DNS. Generated dependency files
remain in the ignored local checkout, while every source change needed to reproduce
them is tracked. Its Swift package cannot
build `wireguard-go-bridge` automatically; the PacketTunnel
target therefore runs `Scripts/build-wireguard-go.sh` as a pre-build phase, as
required by WireGuardKit's integration guide.

`RatelMeshMobile.xcframework` and WireGuardKit's Go backend must not be linked
as two static Go archives in the Packet Tunnel executable. Their cgo runtime
symbols collide on physical devices even though simulator builds pass.
`RatelMeshControl.framework` is therefore a dynamic boundary: it owns the
gomobile control core, while the extension executable owns WireGuardKit's Go
backend. Keep the Packet Tunnel dependent on that framework rather than linking
`RatelMeshMobile.xcframework` directly.

For an unsigned device-SDK compile check:

```sh
Scripts/verify.sh
```

Unit tests cover the JSON contract, route exclusion algebra and fail-closed
block-route rendering. Run the portable tests without Xcode signing via
`swift test`. Full VPN tests require a signed physical iPhone because
the simulator does not grant a production Packet Tunnel entitlement.

`Shared/PrivacyInfo.xcprivacy` is embedded in both the app and Packet Tunnel
targets. It declares App Group `UserDefaults` access, device identity and the
user-supplied device name, plus the coarse location region derived on-device
for app functionality, with tracking disabled. Keep it aligned with App Store
Connect privacy answers when data handling changes.

## Runtime and security notes

- The auth key and coordinator configuration use a shared Keychain item marked
  `AfterFirstUnlockThisDeviceOnly`; they are neither synced nor placed in
  `UserDefaults`.
- The App Group identity state directory is excluded from device backup and
  transfer. A restored device must create and enroll a fresh identity.
- Production coordinators must use HTTPS. Plain HTTP is accepted only for
  localhost development.
- `directRoutes` are subtracted from WireGuard allowed IPs. `blockRoutes` are
  assigned to an endpoint-less WireGuard peer so blocked packets are dropped
  inside the tunnel rather than escaping through the physical interface.
- An active full-tunnel configuration remains fail-closed while the Packet
  Tunnel session exists: WireGuard owns the default route and drops packets
  when the exit peer is unhealthy. iOS does not permit this app to enforce a
  firewall after the user or system has stopped the VPN session.
- The extension waits up to 30 seconds for the first active Go configuration.
  Later versions are applied through `WireGuardAdapter.update` without tearing
  down the system VPN session.

Before shipping, use your own bundle identifiers, privacy policy, App Store
metadata, export-compliance answers, signing assets, and on-device tests across
Wi-Fi/cellular transitions, lock/unlock, sleep, roaming, and coordinator loss.

Once the Apple team and provisioning profiles exist, create a signed archive:

```sh
export RATELMESH_DEVELOPMENT_TEAM=ABCDE12345
# Allow Xcode to create or refresh App Store distribution profiles when the
# signed-in Apple account has permission.
export RATELMESH_ALLOW_PROVISIONING_UPDATES=1
# Optional: also export an App Store-signed IPA.
export RATELMESH_EXPORT_OPTIONS_PLIST="$PWD/ExportOptions-AppStore.plist"
Scripts/archive.sh 0.2.39 240
# After creating the matching App Store Connect app record:
Scripts/upload-app-store.sh build-release/RatelMesh.xcarchive
# Equivalent repository-root shortcut:
# make release-ios VERSION=0.2.39 BUILD=240
```

The shipped app declares `ITSAppUsesNonExemptEncryption=true` because its VPN
data path includes WireGuard and hybrid post-quantum cryptography. Do not mark
the build exempt merely to bypass App Store Connect's compliance workflow.
Complete the applicable export declaration and regional documentation before
review submission.

The same iOS/iPadOS binary compiles and runs on Apple silicon Macs as an
iPad-designed app. That is the initial Mac App Store delivery path: opt the iOS
app into Mac availability in App Store Connect. The separately distributed
menu-bar package is not submitted to the Mac App Store because its privileged
daemon, PF integration, and installer are incompatible with App Sandbox.
