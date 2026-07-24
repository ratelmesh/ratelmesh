#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${RATELMESH_DEVELOPMENT_TEAM:?set RATELMESH_DEVELOPMENT_TEAM to the Apple team ID}"

ARCHIVE_PATH=${RATELMESH_ARCHIVE_PATH:-"$ROOT/build-release/RatelMesh.xcarchive"}
EXPORT_PATH=${RATELMESH_EXPORT_PATH:-"$ROOT/build-release/export"}

cd "$ROOT"
if [ ! -d Frameworks/RatelMeshMobile.xcframework ]; then
    Scripts/build-ratelmesh-mobile.sh
fi
Scripts/prepare-wireguard.sh
xcodegen generate

xcodebuild -project RatelMesh.xcodeproj \
    -scheme RatelMesh \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -archivePath "$ARCHIVE_PATH" \
    DEVELOPMENT_TEAM="$RATELMESH_DEVELOPMENT_TEAM" \
    CODE_SIGN_STYLE=Automatic \
    clean archive

if [ -n "${RATELMESH_EXPORT_OPTIONS_PLIST:-}" ]; then
    test -f "$RATELMESH_EXPORT_OPTIONS_PLIST"
    xcodebuild -exportArchive \
        -archivePath "$ARCHIVE_PATH" \
        -exportPath "$EXPORT_PATH" \
        -exportOptionsPlist "$RATELMESH_EXPORT_OPTIONS_PLIST"
fi

printf '%s\n' "Signed archive: $ARCHIVE_PATH"
