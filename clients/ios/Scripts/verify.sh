#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-ios-verify.XXXXXX")
trap 'rm -rf "$BUILD_ROOT"' EXIT INT TERM
cd "$ROOT"
EXPECTED_VERSION=$(awk '/MARKETING_VERSION:/ { print $2; exit }' project.yml)
EXPECTED_BUILD=$(awk '/CURRENT_PROJECT_VERSION:/ { print $2; exit }' project.yml)

if ! printf '%s\n' "$EXPECTED_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
   ! printf '%s\n' "$EXPECTED_BUILD" | grep -Eq '^[1-9][0-9]*$'; then
    echo "invalid iOS version metadata in project.yml" >&2
    exit 2
fi

swift test

find RatelMesh PacketTunnel Shared \( -name '*.plist' -o -name '*.entitlements' -o -name '*.xcprivacy' \) | while read -r file; do
    plutil -lint "$file"
done

if [ ! -d Frameworks/RatelMeshMobile.xcframework ]; then
    echo "RatelMeshMobile.xcframework is absent; run Scripts/build-ratelmesh-mobile.sh before compile verification." >&2
    exit 2
fi

if ! xcrun simctl list runtimes available 2>/dev/null | grep -Eq '^iOS[[:space:]]'; then
    echo "No available iOS Simulator runtime. Xcode's asset compiler requires one even for this unsigned device build." >&2
    echo "Install the iOS runtime matching Xcode in Xcode Settings > Components, then rerun Scripts/verify.sh." >&2
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

EXPECTED_LOCALES="de es fr it ja ko nl pl pt-BR sv zh-Hans zh-Hant"
ACTUAL_LOCALES=$(find "$BUILD_ROOT/Release-iphoneos/RatelMesh.app" -maxdepth 1 -type d -name '*.lproj' -exec basename {} .lproj \; | sort | tr '\n' ' ' | sed 's/ $//')
if [ "$ACTUAL_LOCALES" != "$EXPECTED_LOCALES" ]; then
    echo "iOS app localization bundle mismatch: got '$ACTUAL_LOCALES', want '$EXPECTED_LOCALES'" >&2
    exit 1
fi
for locale in $EXPECTED_LOCALES; do
    INFO_STRINGS="$BUILD_ROOT/Release-iphoneos/RatelMesh.app/$locale.lproj/InfoPlist.strings"
    test -s "$INFO_STRINGS"
    plutil -extract NSLocationWhenInUseUsageDescription raw -o - "$INFO_STRINGS" | grep -q .
done

for bundle in \
    "$BUILD_ROOT/Release-iphoneos/RatelMesh.app" \
    "$BUILD_ROOT/Release-iphoneos/RatelMesh.app/PlugIns/PacketTunnel.appex"; do
    ACTUAL_VERSION=$(plutil -extract CFBundleShortVersionString raw -o - "$bundle/Info.plist")
    ACTUAL_BUILD=$(plutil -extract CFBundleVersion raw -o - "$bundle/Info.plist")
    if [ "$ACTUAL_VERSION:$ACTUAL_BUILD" != "$EXPECTED_VERSION:$EXPECTED_BUILD" ]; then
        echo "iOS bundle version mismatch in $bundle: got $ACTUAL_VERSION/$ACTUAL_BUILD, want $EXPECTED_VERSION/$EXPECTED_BUILD" >&2
        exit 1
    fi
done

APP_GROUP=$(plutil -extract RatelMeshAppGroup raw -o - "$BUILD_ROOT/Release-iphoneos/RatelMesh.app/Info.plist")
EXTENSION_APP_GROUP=$(plutil -extract RatelMeshAppGroup raw -o - "$BUILD_ROOT/Release-iphoneos/RatelMesh.app/PlugIns/PacketTunnel.appex/Info.plist")
KEYCHAIN_GROUP=$(plutil -extract RatelMeshKeychainAccessGroup raw -o - "$BUILD_ROOT/Release-iphoneos/RatelMesh.app/Info.plist")
EXTENSION_KEYCHAIN_GROUP=$(plutil -extract RatelMeshKeychainAccessGroup raw -o - "$BUILD_ROOT/Release-iphoneos/RatelMesh.app/PlugIns/PacketTunnel.appex/Info.plist")
if [ -z "$APP_GROUP" ] || [ -z "$KEYCHAIN_GROUP" ] ||
   [ "$APP_GROUP:$KEYCHAIN_GROUP" != "$EXTENSION_APP_GROUP:$EXTENSION_KEYCHAIN_GROUP" ]; then
    echo "iOS app and extension resolved sharing groups are empty or differ" >&2
    exit 1
fi

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
