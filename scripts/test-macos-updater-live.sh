#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 RELEASE_PUBLIC_KEY" >&2
    exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-updater-live.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

xcrun swiftc -O -parse-as-library -target "$(uname -m)-apple-macos13.0" \
    -o "$WORK/updater-live-tests" \
    "$ROOT/clients/macos-menubar/UpdateSupport.swift" \
    "$ROOT/clients/macos-menubar/UpdateStoreIntegrationTests.swift"
"$WORK/updater-live-tests" "$1" "$WORK/cache"
