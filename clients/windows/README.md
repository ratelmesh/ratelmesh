# RatelMesh for Windows

The installer shows a one-time geographic privacy reminder. It can open Windows
Location settings, but never changes location, browser, advertising, Wi-Fi or
Bluetooth permissions without user consent. Run
`Show-RatelMeshPrivacy.ps1 -Force` from the installation directory to review
the guidance again.

This client runs `ratelmeshd` as the signed-in Windows user through a highest-privilege scheduled task. It starts at logon, can create the WireGuard tunnel with administrator rights, and keeps the local named pipe owned by the same user that runs `ratelmesh`.

## Requirements

- Windows 10/11 or Windows Server with PowerShell 5.1+
- Official [WireGuard for Windows](https://www.wireguard.com/install/)
- An Administrator PowerShell for install/uninstall
- `ratelmeshd.exe` built with `-tags wgreal`; the stub build does not create a VPN

## Build a bundle

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\clients\windows\Package.ps1 -Arch amd64
```

The bundle is written below `clients\windows\dist`. `Package.ps1` also emits SHA-256 hashes.

For a release bundle, pass a code-signing certificate thumbprint. The packager
finds it in the current-user or local-machine certificate store, signs both
executables and all PowerShell entry points, verifies every signature, and only
then writes hashes:

```powershell
.\clients\windows\Package.ps1 -Arch amd64 `
  -CodeSigningCertificateThumbprint '0123456789ABCDEF...' `
  -TimestampServer 'http://your-authenticode-timestamp-service'
```

## Install

Open an Administrator PowerShell in the bundle directory. Read the enrollment key without placing it in shell history:

```powershell
$key = Read-Host 'Auth key' -AsSecureString
.\Install-RatelMesh.ps1 `
  -Coord 'https://coord.example.com' `
  -AuthKey $key `
  -Language 'zh-Hans' `
  -TunnelDNS '1.1.1.1' `
  -EnableGui
```

If WireGuard is not installed, install it first or pass its official signed installer with `-WireGuardInstaller`. The installer signature is checked before execution.

MagicDNS is enabled by default. The installer starts the local resolver on
`127.0.0.1:53`; WireGuard for Windows installs that address on the tunnel
adapter and restores the prior resolver state when the service stops. Existing
physical-adapter DNS servers are retained as upstreams when no exit is active.
Use `-TunnelDNS host[:port]` to force out-of-zone queries through an exit-side
resolver, or `-DisableMagicDNS` to opt out.

Useful optional switches include `-Relay host:port`, `-VerifyKey BASE64`, `-AcceptRoutes`, `-ForceRelay`, `-SplitTunnelPath rules.json`, and `-KillSwitch`. The GUI, when enabled, binds only to `127.0.0.1:8088` by default.

Every installation includes the local permission needed to become an exit;
EXIT remains disabled until the Tenant administrator grants it in the cloud.
`-RunAsExitNode` remains as a legacy initial-role option. When EXIT is granted,
the daemon enables IPv4 forwarding on `ratelmesh0` and creates only the named
`RatelMesh` WinNAT instance for `100.64.0.0/10`; shutdown and uninstall
remove that instance without touching Hyper-V or other application NATs. This
requires the scheduled task's administrator rights.

`-KillSwitch` preserves `/0` routes so the official WireGuard tunnel service activates its Windows firewall kill switch. Without it, defaults are split into `/1` routes, allowing configured direct-route exceptions. Windows direct-route exceptions and `-KillSwitch` are mutually exclusive because the official firewall intentionally blocks bypass traffic.

The auth key is protected with current-user DPAPI. Config, binaries, logs, and device state are placed below the current user's LocalAppData with ACLs limited to that user, Administrators, and LocalSystem. The scheduled task uses `Interactive` logon at `Highest` privilege; it does not run before that user logs on.

Open a new terminal after installation:

```powershell
ratelmesh status
ratelmesh --lang en status
ratelmesh exit list
ratelmesh exit use <name>
```

Logs are in `%LOCALAPPDATA%\RatelMesh\state\logs\ratelmeshd.log`. The optional GUI is at <http://127.0.0.1:8088>.
`-Language` accepts `system`, `en`, `zh-Hans` or `ja` and persists the CLI
choice for the signed-in Windows user. A one-command override is also available
through `ratelmesh --lang <locale> ...`.

## Upgrade or remove

Run the install command again to replace binaries and update the task while retaining the encrypted auth key when `-AuthKey` is omitted.

```powershell
.\Uninstall-RatelMesh.ps1
# Also delete the device identity and enrollment state:
.\Uninstall-RatelMesh.ps1 -PurgeState
```

Uninstall keeps WireGuard for Windows because other tunnels may depend on it.

## Current limits

- WinNAT requires a Windows edition with the `NetNat` PowerShell cmdlets; the installer reports setup failure instead of silently advertising a broken exit.
- The scheduled task is intentionally per-user and starts at logon, not at boot.
- The publisher must supply its own trusted Authenticode certificate and timestamp service; unsigned development bundles remain supported.
