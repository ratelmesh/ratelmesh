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

This policy controls the official RatelMesh launch experience. It does not
silently enable SSH, RDP or VNC on a target, install a server, create an account,
or replace the mesh ACL. The target service must already be enabled and allowed
by its operating-system firewall. Packet reachability remains governed by the
Tenant ACL.

RatelMesh does not collect or persist protocol passwords. SSH keys and remote
desktop credentials remain in the selected client, OS Keychain, Android
Keystore or the platform credential manager. Removing the target from the
policy removes the launcher on the next Netmap update; revoking the target also
removes its mesh reachability.
