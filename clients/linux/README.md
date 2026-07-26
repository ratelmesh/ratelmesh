# RatelMesh for Linux

This bundle contains `ratelmeshd` and `ratelmesh` for amd64 or arm64.

Install `ratelmeshd` and `ratelmesh` in `/usr/local/bin`, install the supplied
`ratelmeshd.service` in `/etc/systemd/system`, and create
`/etc/ratelmesh/client.env` with the HTTPS Coordinator URL and one-use
enrollment credential:

```sh
sudo install -d -o root -g root -m 0700 /etc/ratelmesh
sudo install -o root -g root -m 0600 /dev/null /etc/ratelmesh/client.env
sudoedit /etc/ratelmesh/client.env
```

The file uses systemd environment syntax:

```text
RATELMESH_COORD=https://control.ratelmesh.com
RATELMESH_AUTHKEY=ratelmesh-xxxx-xxxx-xxxx
```

The credential remains in the daemon environment rather than its command line,
and the service's state, runtime files and default umask are root-only. After
enrollment has created a renewable session, remove `RATELMESH_AUTHKEY` from
`client.env` and restart the service.

The ordinary service includes `-enable-nat`: this is
local permission only. NAT stays off until the signed cloud Netmap grants EXIT,
and is removed again when the Tenant administrator revokes EXIT.

The local control socket is root-only at
`/run/ratelmeshd/ratelmeshd.sock`. Run administrative CLI commands with:

```sh
sudo env RATELMESH_SOCKET=/run/ratelmeshd/ratelmeshd.sock ratelmesh status
```

The binaries are currently unsigned Beta artifacts. Verify them against the
published `SHA256SUMS.txt` before installation.

## Upgrade and removal

Stop the service before replacing binaries. A clean stop removes owned routes,
DNS and firewall state; the durable route-owner ledger lets the next start
reconcile a previous crash without deleting another VPN's routes.

Before removing the service permanently, require that cleanup completed:

```sh
sudo systemctl stop ratelmeshd
if sudo test -e /var/lib/ratelmeshd/route-owners-v1.json; then
  echo "Route cleanup is incomplete; restart RatelMesh and retry the stop." >&2
  exit 1
fi
sudo systemctl disable ratelmeshd
```

The repository-supplied uninstaller performs those checks, refuses linked
managed paths, and preserves `/var/lib/ratelmeshd` by default:

```sh
sudo ./uninstall.sh
```

Use `sudo ./uninstall.sh --purge-state` only when you intentionally want to
delete the device identity and enrollment state. It retains the shared daemon
binary if the EXIT service is still enabled or running.
