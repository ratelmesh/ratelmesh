# RatelMesh clients

This repository contains the source for the official RatelMesh clients:

- macOS menu-bar app, daemon, CLI, installer and signed-update verifier
- Windows daemon, CLI and PowerShell installer
- Linux daemon, CLI and systemd unit
- Android Compose/VpnService app
- iOS SwiftUI/Packet Tunnel app

It also contains the shared Go control, cryptographic, routing, WireGuard and
relay-client code required to build those applications. The hosted control
plane, website, tenant backend, relay service and production infrastructure are
maintained separately and are not part of this repository.

## Security model

Device private keys are generated and stored locally. The client verifies
server-authorized network maps, keeps an authenticated last-known-good snapshot
for control-plane outages, and applies platform-specific routing and kill-switch
controls. Relay links carry WireGuard ciphertext; relay operators cannot decrypt
mesh traffic.

Security-sensitive behavior is covered by race-tested Go packages and native
platform tests. Please report vulnerabilities privately to
`admin@ratelmesh.com` before opening a public issue.

## Build

Go 1.26 is required. Put Homebrew Go first on `PATH` on macOS:

```sh
export PATH="/opt/homebrew/bin:$PATH"
make build
make build-wgreal
make test
make vet
```

The default build uses the dependency-light rootless data-plane stub.
`build-wgreal` compiles the real WireGuard client data plane.

Platform-specific instructions:

- [Android](clients/android/README.md)
- [iOS](clients/ios/README.md)
- [Linux](clients/linux/README.md)
- [Windows](clients/windows/README.md)

The macOS release scripts live under `scripts/` and package the Swift menu app,
Go daemon/CLI and checksum-pinned WireGuard runtime dependencies.

## Repository boundary

The public tree is exported from an internal integration repository through an
explicit allowlist. It starts with a clean public history so files that belong
to the private service implementation cannot remain recoverable in Git history.

Official downloads and documentation are available at
[ratelmesh.com](https://ratelmesh.com/).

## License

The current `main` branch and future RatelMesh client releases are licensed
under the [GNU Affero General Public License v3.0 only](LICENSE)
(`AGPL-3.0-only`). The published `v0.2.33` release and its earlier public
history remain available under the Apache License 2.0 terms attached to those
versions. Third-party components remain under their respective licenses;
macOS runtime notices are listed in
[`packaging/macos/THIRD-PARTY-NOTICES.txt`](packaging/macos/THIRD-PARTY-NOTICES.txt).
