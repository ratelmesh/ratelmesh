# RatelMesh for Linux

The Linux bundle contains the `ratelmeshd` client daemon and `ratelmesh` local
CLI for amd64 or arm64.

Install `ratelmeshd` and `ratelmesh` in `/usr/local/bin`, install the supplied
`ratelmeshd.service` in `/etc/systemd/system`, and create
`/etc/ratelmesh/client.env` with the HTTPS Coordinator URL and one-use
enrollment credential. The ordinary service includes `-enable-nat`: this is
local permission only. NAT stays off until the signed cloud Netmap grants EXIT,
and is removed again when the Tenant administrator revokes EXIT.

The binaries are currently unsigned Beta artifacts. Verify them against the
published `SHA256SUMS.txt` before installation.
