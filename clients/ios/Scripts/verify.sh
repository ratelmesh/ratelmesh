#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-ios-verify.XXXXXX")
trap 'rm -rf "$BUILD_ROOT"' EXIT INT TERM
cd "$ROOT"

swift test

find RatelMesh PacketTunnel Shared \( -name '*.plist' -o -name '*.entitlements' -o -name '*.xcprivacy' \) | while read -r file; do
    plutil -lint "$file"
done

if [ ! -d Frameworks/RatelMeshMobile.xcframework ]; then
    echo "RatelMeshMobile.xcframework is absent; run Scripts/build-ratelmesh-mobile.sh before compile verification." >&2
    exit 2
fi

Scripts/prepare-wireguard.sh
xcodegen generate

xcodebuild -project RatelMesh.xcodeproj \
    -target RatelMesh \
    -configuration Release \
    -sdk iphoneos \
    CODE_SIGNING_ALLOWED=NO \
    ENABLE_TESTABILITY=YES \
    SYMROOT="$BUILD_ROOT" \
    OBJROOT="$BUILD_ROOT/obj" \
    build

ASSET_CATALOG="$BUILD_ROOT/Release-iphoneos/RatelMesh.app/Assets.car"
test -s "$ASSET_CATALOG"
xcrun assetutil --info "$ASSET_CATALOG" | grep -q '"Name" : "BrandMarkDark"'

for manifest in \
    "$BUILD_ROOT/Release-iphoneos/RatelMesh.app/PrivacyInfo.xcprivacy" \
    "$BUILD_ROOT/Release-iphoneos/RatelMesh.app/PlugIns/PacketTunnel.appex/PrivacyInfo.xcprivacy"; do
    test -f "$manifest"
    plutil -lint "$manifest"
done

xcodebuild -project RatelMesh.xcodeproj \
    -target RatelMeshTests \
    -configuration Release \
    -sdk iphoneos \
    CODE_SIGNING_ALLOWED=NO \
    ENABLE_TESTABILITY=YES \
    SYMROOT="$BUILD_ROOT" \
    OBJROOT="$BUILD_ROOT/obj" \
    build
