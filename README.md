# RatelMesh

RatelMesh is a WireGuard-based private network for individuals and small
businesses. It connects a user's devices, supports a user-owned EXIT device,
and provides privacy-aware diagnostics, temporary remote access, and encrypted
file-transfer primitives.

## Repository boundary

The public `ratelmesh/ratelmesh` repository contains the client source:

- the `ratelmeshd` client daemon and `ratelmesh` CLI;
- Linux, macOS, Windows, Android, and iPhone/iPad clients;
- the rootless and real WireGuard data-plane implementations;
- the client side of control, relay, remote-access, Network Doctor, and
  end-to-end encrypted file transfer;
- reproducible client build, packaging, and verification tools.

The hosted Coordinator, Relay admission service, Tenant Console, website, and
production deployment configuration are maintained separately. Their private
implementation and credentials are not required to inspect, build, test, or
modify the clients in this repository.

Security boundaries and current limitations are documented in
[`SECURITY.md`](SECURITY.md). Client behavior and command usage are documented
in [`docs/clients.md`](docs/clients.md) and [`docs/cli.md`](docs/cli.md).

## Status

RatelMesh is beta software. Release artifacts state their signing and
installation status individually:

- macOS packages require Developer ID signing and Apple notarization before
  normal end-user installation;
- Windows archives are not yet Authenticode signed;
- Android artifacts are debug-signed test builds;
- iPhone/iPad artifacts are unsigned developer previews and are not directly
  installable.

Use the [official website](https://ratelmesh.com) and the
[GitHub Releases page](https://github.com/ratelmesh/ratelmesh/releases) for
published builds. Verify downloaded artifacts against `SHA256SUMS.txt`.

## Components

| Path | Role |
| --- | --- |
| `cmd/ratelmeshd` | Client daemon: identity, control connection, data plane, MagicDNS, EXIT routing, local API |
| `cmd/ratelmesh` | Localized CLI for status, EXIT, DNS, diagnostics, and client operations |
| `mobile/` | Shared mobile control/data-plane contract |
| `clients/android/` | Android Compose app and VPN service |
| `clients/ios/` | SwiftUI app and Network Extension |
| `clients/macos-menubar/` | macOS menu-bar app |
| `clients/windows/` | Windows packaging and service integration |
| `clients/linux/` | Linux service, installer, and uninstaller |
| `internal/wgengine/` | Rootless stub and `wgreal` WireGuard data planes |

The default Go build is dependency-light and uses the rootless stub data plane.
The real macOS/Linux WireGuard implementation is selected with `-tags wgreal`.

## Build and test

Go 1.26 is required.

```sh
make build
make build-wgreal
go test -race ./...
go test -race -tags wgreal ./...
make vet
```

`make build` creates `bin/ratelmeshd` and `bin/ratelmesh` in the public
checkout. In the private server monorepo it also builds the Coordinator; the
explicit `make build-server` target fails with a clear message when server
source is not present.

Platform helpers:

```sh
make build-windows
make mobile-ios
make mobile-android
```

These commands require their respective platform SDKs and toolchains. Client
installation and release-specific instructions are in
[`docs/clients.md`](docs/clients.md) and [`docs/releases/`](docs/releases/).

## Security model

Device private keys are generated locally and are never sent to the
Coordinator. Remote-access authorization is temporary and authority-signed;
RatelMesh does not store login passwords on the server. File-transfer content
is end-to-end encrypted and authenticated by the participating devices.

Please report vulnerabilities privately using the process in
[`SECURITY.md`](SECURITY.md).

## License

The public client source is licensed under the GNU Affero General Public
License v3.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
