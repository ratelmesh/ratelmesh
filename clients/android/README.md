# RatelMesh for Android

This directory contains the native Android client. The app uses Jetpack Compose
for its UI, the official WireGuard Android tunnel library for the userspace VPN,
and the repository's Go `mobile` package for coordinator and netmap behavior.

## What is implemented

- Android 8.0+ (`minSdk 26`), targeting Android 15 / API 35.
- Android VPN consent flow and the official WireGuard `GoBackend`.
- Process isolation between RatelMeshMobile and WireGuard's Go backend. Each native Go
  runtime has its own Android process, preventing the post-connect native crash
  caused by loading both runtimes into one process.
- A versioned in-app VpnService disclosure with explicit accept/decline before
  Android's system VPN permission prompt.
- A foreground service with a persistent connection notification and a
  disconnect action.
- Versioned config polling through `TunnelConfigJSON()` and
  `TunnelConfigVersion()`, including live WireGuard reconfiguration.
- WireGuard handshake/RX statistics fed back through
  `UpdatePeerStatsJSON()` for direct/relay path health decisions.
- Direct-route CIDR subtraction for split tunneling.
- Restoration through Android's Always-on VPN callback.
- Normal setup asks only for a one-use enrollment code and an automatically
  generated device name. The official Coordinator is built in; self-hosted
  Coordinator URLs remain available under Advanced settings.
- Coordinator URL, enrollment code and device name are stored with Android
  Keystore-backed encrypted preferences. Go key/state files live under
  `noBackupFilesDir`.
- Status, peers, exit-node selection and direct-egress controls.

The official WireGuard `GoBackend` does not expose a customizable
`VpnService.Builder`, so Android cannot install a true blackhole route alongside
that backend. A config containing `blockRoutes` is therefore rejected instead
of silently leaking traffic. Supporting that policy requires a dedicated
WireGuard VpnService backend; it is not falsely reported as implemented here.

For a production kill switch, open Android Settings → Network & internet → VPN,
select RatelMesh, enable **Always-on VPN**, then enable **Block connections
without VPN**. The app registers WireGuard's always-on callback so Android can
restore its control/foreground service after process death. The OS setting is
the enforcement boundary; the `killSwitch` value in mobile config is status
metadata and is not treated as proof that Android has enabled blocking.

## Generate the Go AAR

`ratelmesh-mobile.aar` is generated build output and is intentionally not committed.
Install the Android SDK/NDK, Go 1.26, and `gomobile`, then run from the repository
root:

```sh
export PATH="/opt/homebrew/bin:$PATH"
export ANDROID_HOME="$HOME/Library/Android/sdk"
clients/android/scripts/build-ratelmesh-mobile.sh
```

The helper pins `golang.org/x/mobile` to
`v0.0.0-20260709172247-6129f5bee9d5` and works from a temporary module copy, so
the repository's `go.mod` and `go.sum` are not changed by build-only tools. On
Linux/ARM64 builders such as NVIDIA DGX Spark, gomobile stays native while the
helper substitutes Ubuntu's native ARM64 LLVM driver for Google's x86_64-only
NDK host driver while retaining the NDK sysroot and Android runtime libraries.
This avoids emulation for the AAR step; install `clang lld llvm` on the builder
once. Google's current Gradle AAPT2 binary is also x86_64-only, so final APK/AAB
resource packaging still needs macOS or an x86_64 Linux builder unless a
compatible native ARM64 AAPT2 is available.

The generated Java package is expected to be `mobile`, exposing `Mobile.newApp`
and `mobile.App`. Regenerate the AAR whenever the Go mobile contract changes.
Do not use an AAR from an untrusted build: it contains the client control and
key-management code loaded into the app process.

## Build and test

Use Android Studio (JDK 17, Android SDK 35) or the pinned Gradle wrapper:

```sh
cd clients/android
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
```

Unit tests cover mobile JSON conversion, inactive snapshots, fail-closed block
policies and IPv4/IPv6 CIDR route subtraction. A real APK additionally requires
the generated AAR. VPN behavior must be checked on a physical device: emulators
do not faithfully reproduce roaming, Doze, carrier NAT or VPN handoff.

## Release signing

Create a release keystore outside the repository and add an ignored
`clients/android/keystore.properties`:

```properties
storeFile=/absolute/path/to/ratelmesh-release.jks
storePassword=...
keyAlias=ratelmesh
keyPassword=...
```

Then run `./gradlew :app:bundleRelease`. Without that file the release target is
left unsigned. Back up the keystore securely; Android updates must be signed by
the same key. Production distribution also requires Play Console VPN policy and
foreground-service declarations, a privacy policy, and testing of the signed
bundle on supported ABIs.

`assembleDebug` uses Android's standard local debug certificate. Its APK is for
development only: never publish it or present it as a production-signed build.
`assembleRelease` without `keystore.properties` produces an unsigned APK and is
also not distributable.

`scripts/bundle-release.sh` runs release tests and lint, builds the AAB and
rejects it unless `jarsigner` verifies the final bundle.

The Play declaration answers and required recording flow are kept in
[`store/vpnservice-declaration.md`](store/vpnservice-declaration.md). Increment
`VpnDisclosureConsent.CURRENT_VERSION` whenever the text or VPN data use
changes so existing users affirm the new disclosure.
