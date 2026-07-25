#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 RELEASE_ED25519_PUBLIC_KEY RELEASE_MLDSA65_PUBLIC_KEY" >&2
    exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-updater-live.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
MANIFEST_URL=https://download.ratelmesh.com/download/macos/latest.json
MANIFEST="$WORK/latest.json"

curl --fail --silent --show-error \
    --proto '=https' \
    --tlsv1.2 \
    --max-time 30 \
    --max-filesize 65536 \
    --output "$MANIFEST" \
    "$MANIFEST_URL"

go build -o "$WORK/ratelmesh-pqverify" "$ROOT/cmd/ratelmesh-pqverify"

xcrun swiftc -O -parse-as-library -target "$(uname -m)-apple-macos13.0" \
    -o "$WORK/updater-live-tests" \
    "$ROOT/clients/macos-menubar/UpdateSupport.swift" \
    "$ROOT/clients/macos-menubar/UpdateStoreIntegrationTests.swift"

# Extract the expected version only after both release signatures and all
# manifest invariants have been verified by the same code used by the updater.
EXPECTED_VERSION=$(
    "$WORK/updater-live-tests" verify-manifest \
        "$MANIFEST" "$1" "$2" "$WORK/ratelmesh-pqverify"
)
if [ -z "$EXPECTED_VERSION" ] || [ "$(printf '%s\n' "$EXPECTED_VERSION" | wc -l | tr -d ' ')" -ne 1 ]; then
    echo "verified manifest did not produce exactly one version" >&2
    exit 1
fi

"$WORK/updater-live-tests" run \
    "$MANIFEST" "$1" "$2" "$WORK/ratelmesh-pqverify" \
    "$EXPECTED_VERSION" "$WORK/cache"
