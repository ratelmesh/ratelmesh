# RatelMesh for Linux

This v0.2.7 bundle contains `ratelmeshd`, `ratelmesh`, and the optional
`ratelmesh-relay` service binary for amd64 or arm64.

Install `ratelmeshd` and `ratelmesh` in `/usr/local/bin`, install the supplied
`ratelmeshd.service` in `/etc/systemd/system`, and create
`/etc/ratelmesh/client.env` with the HTTPS Coordinator URL and one-use
enrollment credential. The ordinary service includes `-enable-nat`: this is
local permission only. NAT stays off until the signed cloud Netmap grants EXIT,
and is removed again when the Tenant administrator revokes EXIT.

RELAY is a separate cloud authorization. Running a useful Tenant Relay also
requires a reachable TCP/WSS listener and the Tenant relay service configuration;
the cloud grant alone never opens a firewall or router port.

The binaries are currently unsigned Beta artifacts. Verify them against the
published `SHA256SUMS.txt` before installation.
