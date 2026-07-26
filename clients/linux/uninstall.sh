#!/bin/sh
# Safely remove the Linux client while preserving device identity by default.
set -eu

usage() {
    echo "usage: $0 [--purge-state]" >&2
    exit 2
}

PURGE_STATE=false
case "${1:-}" in
    '') ;;
    --purge-state) PURGE_STATE=true ;;
    *) usage ;;
esac
[ "$#" -le 1 ] || usage
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

UNIT=/etc/systemd/system/ratelmeshd.service
ENV_FILE=/etc/ratelmesh/client.env
STATE=/var/lib/ratelmeshd
LEDGER=$STATE/route-owners-v1.json

for path in "$UNIT" "$ENV_FILE" "$STATE"; do
    if [ -L "$path" ]; then
        echo "refusing symbolic-link managed path: $path" >&2
        exit 1
    fi
done

systemctl stop ratelmeshd.service
if [ -e "$LEDGER" ] || [ -L "$LEDGER" ]; then
    echo "route cleanup is incomplete; installation and state were retained" >&2
    exit 1
fi
if command -v ip >/dev/null 2>&1 && ip link show ratelmesh0 >/dev/null 2>&1; then
    echo "ratelmesh0 still exists; installation and state were retained" >&2
    exit 1
fi
systemctl disable ratelmeshd.service >/dev/null 2>&1 || true

# The exit service uses the same daemon binary. Never break it while it exists.
if systemctl is-enabled ratelmeshd-exit.service >/dev/null 2>&1 ||
   systemctl is-active ratelmeshd-exit.service >/dev/null 2>&1; then
    echo "ratelmeshd-exit still uses /usr/local/bin/ratelmeshd; daemon binary retained" >&2
else
    rm -f /usr/local/bin/ratelmeshd
fi
rm -f /usr/local/bin/ratelmesh "$UNIT" "$ENV_FILE"
systemctl daemon-reload

if [ "$PURGE_STATE" = true ]; then
    rm -rf "$STATE"
    echo "RatelMesh client, identity, and state removed."
else
    echo "RatelMesh client removed; identity and state retained at $STATE."
fi
