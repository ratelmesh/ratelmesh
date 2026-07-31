#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-macos-store-verify.XXXXXX")
trap 'rm -rf "$BUILD_ROOT"' EXIT INT TERM

cd "$ROOT"
for file in \
    ../macos-appstore/RatelMeshMac-Info.plist \
    ../macos-appstore/PacketTunnelMac-Info.plist \
    ../macos-appstore/RatelMeshMac.entitlements \
    ../macos-appstore/PacketTunnelMac.entitlements; do
    plutil -lint "$file"
done

if [ ! -d Frameworks/RatelMeshMobile.xcframework ]; then
    echo "RatelMeshMobile.xcframework is absent; run Scripts/build-ratelmesh-mobile.sh." >&2
    exit 2
fi
if ! find Frameworks/RatelMeshMobile.xcframework -type f -path '*macos*' | grep -q .; then
    echo "RatelMeshMobile.xcframework has no macOS slice; rebuild it." >&2
    exit 2
fi

Scripts/prepare-wireguard.sh
xcodegen generate
xcodebuild -project RatelMesh.xcodeproj \
    -target RatelMeshMac \
    -configuration Release \
    -sdk macosx \
    CODE_SIGNING_ALLOWED=NO \
    ENABLE_TESTABILITY=YES \
    SYMROOT="$BUILD_ROOT" \
    OBJROOT="$BUILD_ROOT/obj" \
    build

APP="$BUILD_ROOT/Release/RatelMesh.app"
EXTENSION="$APP/Contents/PlugIns/PacketTunnel.appex"
test -d "$APP"
test -d "$EXTENSION"
test -d "$APP/Contents/Frameworks/RatelMeshControlMac.framework"
if [ -e "$EXTENSION/Contents/Resources/Info.plist" ]; then
    echo "macOS Packet Tunnel contains a second Info.plist resource" >&2
    exit 1
fi
test -s "$APP/Contents/Resources/BrandMarkDark.png"
test -s "$APP/Contents/Resources/RatelMesh.icns"

EXPECTED_LOCALES="de es fr it ja ko nl pl pt-BR sv zh-Hans zh-Hant"
ACTUAL_LOCALES=$(find "$APP/Contents/Resources" -maxdepth 1 -type d -name '*.lproj' -exec basename {} .lproj \; | sort | tr '\n' ' ' | sed 's/ $//')
if [ "$ACTUAL_LOCALES" != "$EXPECTED_LOCALES" ]; then
    echo "macOS app localization mismatch: got '$ACTUAL_LOCALES', want '$EXPECTED_LOCALES'" >&2
    exit 1
fi

if [ "$(plutil -extract ITSAppUsesNonExemptEncryption raw -o - "$APP/Contents/Info.plist")" != "false" ]; then
    echo "macOS App Store build must declare its current export-document exemption" >&2
    exit 1
fi
if find "$APP" -type f \( -name ratelmeshd -o -name ratelmesh-enroll -o -name '*.pkg' \) | grep -q .; then
    echo "macOS App Store build contains a privileged/direct-distribution component" >&2
    exit 1
fi

xcodebuild -project RatelMesh.xcodeproj \
    -target RatelMeshMacTests \
    -configuration Release \
    -sdk macosx \
    CODE_SIGNING_ALLOWED=NO \
    ENABLE_TESTABILITY=YES \
    SYMROOT="$BUILD_ROOT" \
    OBJROOT="$BUILD_ROOT/obj" \
    build

printf '%s\n' "Verified unsigned macOS App Store build"
