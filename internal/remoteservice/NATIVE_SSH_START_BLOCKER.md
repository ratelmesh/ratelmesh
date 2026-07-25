# Native SSH start safety decision

Status: **blocked; production remains detect-only**

Reviewed against `main` commit `790a14b3`.

This decision covers Linux OpenSSH managed by systemd and macOS Remote Login.
It assumes the authority-signed target activation and temporary-grant firewall
are present in the daemon. Those controls are necessary, but they do not make a
global SSH service start safe.

## Why the current boundary is insufficient

The target firewall protects managed ports only on the RatelMesh tunnel
interface. It does not deny the same listener on Ethernet, Wi-Fi, a public
interface, or another local address. Both supported native start mechanisms can
create a wildcard listener:

- `systemctl start ssh.service` or `sshd.service` starts the host's global SSH
  service according to administrator-owned configuration.
- macOS `systemsetup -setremotelogin on` enables the host-wide Remote Login
  service and launchd socket.

Consequently, a correctly signed, correctly applied Mesh firewall can coexist
with `0.0.0.0:22` or `[::]:22` on a physical interface. Starting either service
would violate the requirement that this feature never creates public exposure.
Listener health and service-manager identity prove which process owns port 22;
they do not prove which interfaces can reach it.

The remote-service transaction also receives no authenticated attestation of
the currently applied firewall generation, target Mesh address, tunnel
interface, managed port set, or signed activation digest. A local confirmation
is bound to a `Target`, not to those values. Enabling mutation inside this
package would therefore leave a check/use race with firewall withdrawal,
netmap replacement, interface replacement, and activation revocation.

Finally, the native mechanisms do not provide the compare-and-swap ownership
required by `ChangeReceipt`:

- systemd does not atomically compare the captured unit state, start the unit,
  and issue a private ownership token which a later conditional stop can
  validate against every external administrator action;
- Remote Login exposes no atomic generation/ownership primitive at all, and a
  rollback could disable a service an administrator enabled concurrently.

Before/after CLI polling, a command exit status, PID comparison, launchd socket
observation, or a systemd job identifier is not sufficient. A timeout or
concurrent start can leave the service running without proving which actor owns
the transition.

## Required design before enabling production mutation

All of the following are prerequisites:

1. The daemon must mint a short-lived, single-use start permit only while an
   exact firewall policy is successfully applied. The permit must bind the
   signed target-activation digest and version, target Mesh IP, tunnel
   interface, TCP port 22, firewall generation, and local confirmation.
2. The firewall transition and service-start admission must share a serialized
   generation boundary. Revocation or firewall replacement must invalidate an
   unused permit and prevent a concurrent start.
3. The started service must be unreachable on every non-Mesh interface. The
   preferred Linux design is a dedicated, fixed RatelMesh sshd instance with a
   root-owned configuration and an exact Mesh-IP bind. It must not mutate the
   administrator's global `ssh.service`. A host-firewall alternative would need
   deny rules for every non-Mesh ingress path and coexistence guarantees for an
   already-running administrator SSH service.
4. A privileged native helper must own a durable transaction journal and an
   OS-level serialization mechanism. It must atomically validate pre-state,
   start the fixed instance, record a nonzero process/service generation and
   ownership nonce, and conditionally roll back only that exact generation.
   Crash recovery must preserve the same ownership decision.
5. macOS must remain detect-only unless a dedicated Mesh-bound SSH instance can
   be implemented without toggling Remote Login, or Apple exposes equivalent
   atomic ownership and interface-binding primitives.
6. An already-running wildcard SSH listener is observable, not made safe by
   this feature. The UI may report it, but RatelMesh must not claim ownership,
   broaden access, or automatically stop it.

Until these prerequisites are integrated and tested across the daemon,
firewall, and privileged platform helper, `NewSystemBackend` must reject SSH
mutation with `CodeUnsupportedTarget`. Detection remains read-only.
