#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REPO=$(CDPATH= cd -- "$ROOT/../.." && pwd)

if [ "$#" -ne 2 ]; then
    echo "usage: $0 VERSION BUILD" >&2
    exit 2
fi
VERSION=$1
BUILD=$2
EXPECTED_VERSION=$(awk '/MARKETING_VERSION:/ { print $2; exit }' "$ROOT/project.yml")
EXPECTED_BUILD=$(awk '/CURRENT_PROJECT_VERSION:/ { print $2; exit }' "$ROOT/project.yml")
if [ "$VERSION:$BUILD" != "$EXPECTED_VERSION:$EXPECTED_BUILD" ]; then
    echo "release version mismatch: requested $VERSION/$BUILD, project.yml has $EXPECTED_VERSION/$EXPECTED_BUILD" >&2
    exit 2
fi

: "${RATELMESH_DEVELOPMENT_TEAM:?set RATELMESH_DEVELOPMENT_TEAM to the Apple team ID}"
ARCHIVE_PATH=${RATELMESH_MAC_ARCHIVE_PATH:-"$ROOT/build-release/RatelMeshMac.xcarchive"}
PROVISIONING_FLAG=
if [ "${RATELMESH_ALLOW_PROVISIONING_UPDATES:-0}" = "1" ]; then
    PROVISIONING_FLAG=-allowProvisioningUpdates
fi

cd "$ROOT"
"$REPO/scripts/test-client-locales.py"
Scripts/build-ratelmesh-mobile.sh
Scripts/prepare-wireguard.sh
xcodegen generate
xcodebuild $PROVISIONING_FLAG -project RatelMesh.xcodeproj \
    -scheme RatelMeshMac \
    -configuration Release \
    -destination 'generic/platform=macOS' \
    -archivePath "$ARCHIVE_PATH" \
    DEVELOPMENT_TEAM="$RATELMESH_DEVELOPMENT_TEAM" \
    CODE_SIGN_STYLE=Automatic \
    clean archive

Scripts/verify-macos-archive.sh "$ARCHIVE_PATH"
printf '%s\n' "Signed macOS App Store archive: $ARCHIVE_PATH"
