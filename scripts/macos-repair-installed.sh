#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ ! -x "$1" ]; then
    echo "usage: $0 /path/to/new/ratelmeshd [preferred-exit]" >&2
    exit 2
fi

NEW_BINARY=$1
PREFERRED_EXIT=${2:-}
LABEL=com.ratelmesh.daemon
PLIST=/Library/LaunchDaemons/$LABEL.plist
INSTALL_DIR=/usr/local/ratelmesh/bin
INSTALLED_BINARY=$INSTALL_DIR/ratelmeshd
LOG=/var/log/ratelmesh.log
BACKUP_DIR=/usr/local/ratelmesh/backup-$(date +%Y%m%d-%H%M%S)
STATUS_FILE=$(mktemp "${TMPDIR:-/tmp}/ratelmesh-repair-status.XXXXXX")
chmod 600 "$STATUS_FILE"

test -f "$PLIST"
mkdir -p "$BACKUP_DIR"
cp -p "$PLIST" "$BACKUP_DIR/ratelmesh.plist"
cp -p "$INSTALLED_BINARY" "$BACKUP_DIR/ratelmeshd"
chmod 700 "$BACKUP_DIR"

stop_service() {
    launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
    i=0
    while launchctl print "system/$LABEL" >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -ge 40 ]; then
            echo "timed out waiting for launchd to unload $LABEL" >&2
            return 1
        fi
        sleep 0.25
    done
}

start_service() {
    attempts=0
    while ! launchctl bootstrap system "$PLIST"; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 3 ]; then
            return 1
        fi
        sleep 1
    done
    launchctl kickstart -k "system/$LABEL"
}

wait_running() {
    i=0
    while [ "$i" -lt 45 ]; do
        status=$(curl -fsS --max-time 2 http://127.0.0.1:8088/localapi/status 2>/dev/null || true)
        if echo "$status" | grep -q '"state":"Running"'; then
            echo "$status"
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

rollback() {
    finished=true
    echo "repair failed; restoring previous daemon" >&2
    stop_service || true
    cp -p "$BACKUP_DIR/ratelmeshd" "$INSTALLED_BINARY"
    cp -p "$BACKUP_DIR/ratelmesh.plist" "$PLIST"
    chmod 600 "$PLIST"
    chown root:wheel "$PLIST" "$INSTALLED_BINARY"
    start_service || true
}

finished=false
trap 'if [ "$finished" != true ]; then rollback; fi; rm -f "$STATUS_FILE"' EXIT
trap 'exit 1' HUP INT TERM
stop_service
install -o root -g wheel -m 755 "$NEW_BINARY" "$INSTALLED_BINARY"
chmod 600 "$PLIST"
chown root:wheel "$PLIST"
touch "$LOG"
chmod 600 "$LOG"
chown root:wheel "$LOG"
start_service

if ! wait_running >"$STATUS_FILE"; then
    exit 1
fi

# Enrollment is complete and the root-only state directory contains the
# renewable session token, so the reusable auth key no longer belongs in the
# launchd environment. Validate a second clean start without it; roll back if
# this deployment still depends on the enrollment key.
if plutil -p "$PLIST" | grep -q 'RATELMESH_AUTHKEY'; then
    stop_service
    plutil -remove EnvironmentVariables.RATELMESH_AUTHKEY "$PLIST"
    chmod 600 "$PLIST"
    start_service
    if ! wait_running >"$STATUS_FILE"; then
        exit 1
    fi
fi

if [ -n "$PREFERRED_EXIT" ]; then
    curl -fsS --max-time 5 --unix-socket /var/run/ratelmesh.sock \
        -X POST --get --data-urlencode "name=$PREFERRED_EXIT" \
        http://localapi/localapi/exit/use >/dev/null
fi

finished=true
echo "RatelMesh repair completed. Backup: $BACKUP_DIR"
cat "$STATUS_FILE"
