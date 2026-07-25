# Remote access launchers

RatelMesh can expose SSH, RDP and VNC/screen-sharing launchers for devices that
are already reachable inside a Tenant mesh. The feature is off by default.

The Tenant administrator chooses one of three modes in the private console:

- `off`: no official client shows remote-access launchers;
- `all`: every visible Tenant device is an eligible target;
- `selected`: only the selected target device IDs are eligible.

The Coordinator persists this policy and computes `remoteAccessAllowed` for each
node in the authenticated Netmap. A client cannot grant the flag to itself.
Revoking a device also removes it from the selected-target list.

Official clients map the target platform to fixed URI schemes:

| Target platform | Launchers |
| --- | --- |
| macOS | Screen Sharing (`vnc://`), SSH (`ssh://`) |
| Windows | RDP (`rdp://`), SSH (`ssh://`) |
| Linux | SSH (`ssh://`), VNC (`vnc://`) |

The URI host is always the Coordinator-validated Mesh IP. Administrators cannot
inject a command, hostname or arbitrary URL. Android and iOS hand the URI to an
installed protocol app; macOS uses the registered system/application handler.

## Security boundary

This policy controls both the official RatelMesh launch experience and the
temporary target-side network grant. On supported Linux and macOS targets, the
daemon accepts only authority-signed target state and grants, then atomically
allows the exact Mesh source, target and service port in the host firewall.
Expiry and revocation remove that allow without waiting for another Netmap
update. The deny boundary remains active while the target feature is enabled.
Targets without a capable enforcement backend do not advertise secure target
capability; Windows target enforcement is not yet supported.

RatelMesh does not silently enable SSH, RDP or VNC, install a server, create an
account or bypass the Tenant ACL. The target service must already be running.
Opening a launcher cannot start it. Safe bounded service startup remains a
separate, locally confirmed feature and is intentionally detect-only in this
release.

RatelMesh does not collect or persist protocol passwords. SSH keys and remote
desktop credentials remain in the selected client, OS Keychain, Android
Keystore or the platform credential manager. Removing the target from the
policy removes the launcher on the next Netmap update; revoking the target also
removes its mesh reachability.
