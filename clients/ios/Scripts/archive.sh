#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REPO=$(CDPATH= cd -- "$ROOT/../.." && pwd)

if [ "$#" -ne 2 ]; then
    echo "usage: $0 VERSION BUILD" >&2
    exit 2
fi
RELEASE_VERSION=$1
RELEASE_BUILD=$2

if ! printf '%s\n' "$RELEASE_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "invalid release version '$RELEASE_VERSION'; expected X.Y.Z" >&2
    exit 2
fi
if ! printf '%s\n' "$RELEASE_BUILD" | grep -Eq '^[1-9][0-9]*$'; then
    echo "invalid release build '$RELEASE_BUILD'; expected a positive integer" >&2
    exit 2
fi

ARCHIVE_PATH=${RATELMESH_ARCHIVE_PATH:-"$ROOT/build-release/RatelMesh.xcarchive"}
EXPORT_PATH=${RATELMESH_EXPORT_PATH:-"$ROOT/build-release/export"}
EXPECTED_VERSION=$(awk '/MARKETING_VERSION:/ { print $2; exit }' "$ROOT/project.yml")
EXPECTED_BUILD=$(awk '/CURRENT_PROJECT_VERSION:/ { print $2; exit }' "$ROOT/project.yml")

if ! printf '%s\n' "$EXPECTED_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
   ! printf '%s\n' "$EXPECTED_BUILD" | grep -Eq '^[1-9][0-9]*$'; then
    echo "invalid iOS version metadata in project.yml" >&2
    exit 2
fi
if [ "$RELEASE_VERSION:$RELEASE_BUILD" != "$EXPECTED_VERSION:$EXPECTED_BUILD" ]; then
    echo "release version mismatch: requested $RELEASE_VERSION/$RELEASE_BUILD, project.yml has $EXPECTED_VERSION/$EXPECTED_BUILD" >&2
    exit 2
fi

if [ "${RATELMESH_ARCHIVE_VALIDATE_ONLY:-0}" = "1" ]; then
    printf '%s\n' "Validated iOS release metadata: $EXPECTED_VERSION ($EXPECTED_BUILD)"
    exit 0
fi

: "${RATELMESH_DEVELOPMENT_TEAM:?set RATELMESH_DEVELOPMENT_TEAM to the Apple team ID}"
PROVISIONING_FLAG=
if [ "${RATELMESH_ALLOW_PROVISIONING_UPDATES:-0}" = "1" ]; then
    PROVISIONING_FLAG=-allowProvisioningUpdates
fi

cd "$ROOT"
"$REPO/scripts/test-client-locales.py"
if [ ! -d Frameworks/RatelMeshMobile.xcframework ]; then
    Scripts/build-ratelmesh-mobile.sh
fi
Scripts/prepare-wireguard.sh
xcodegen generate

xcodebuild $PROVISIONING_FLAG -project RatelMesh.xcodeproj \
    -scheme RatelMesh \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -archivePath "$ARCHIVE_PATH" \
    DEVELOPMENT_TEAM="$RATELMESH_DEVELOPMENT_TEAM" \
    CODE_SIGN_STYLE=Automatic \
    clean archive

EXPECTED_LOCALES="de es fr it ja ko nl pl pt-BR sv zh-Hans zh-Hant"
ACTUAL_LOCALES=$(find "$ARCHIVE_PATH/Products/Applications/RatelMesh.app" -maxdepth 1 -type d -name '*.lproj' -exec basename {} .lproj \; | sort | tr '\n' ' ' | sed 's/ $//')
if [ "$ACTUAL_LOCALES" != "$EXPECTED_LOCALES" ]; then
    echo "iOS archive localization bundle mismatch: got '$ACTUAL_LOCALES', want '$EXPECTED_LOCALES'" >&2
    exit 1
fi

for bundle in \
    "$ARCHIVE_PATH/Products/Applications/RatelMesh.app" \
    "$ARCHIVE_PATH/Products/Applications/RatelMesh.app/PlugIns/PacketTunnel.appex"; do
    ACTUAL_VERSION=$(plutil -extract CFBundleShortVersionString raw -o - "$bundle/Info.plist")
    ACTUAL_BUILD=$(plutil -extract CFBundleVersion raw -o - "$bundle/Info.plist")
    if [ "$ACTUAL_VERSION:$ACTUAL_BUILD" != "$EXPECTED_VERSION:$EXPECTED_BUILD" ]; then
        echo "iOS bundle version mismatch in $bundle: got $ACTUAL_VERSION/$ACTUAL_BUILD, want $EXPECTED_VERSION/$EXPECTED_BUILD" >&2
        exit 1
    fi
done

APP_BUNDLE="$ARCHIVE_PATH/Products/Applications/RatelMesh.app"
EXTENSION_BUNDLE="$APP_BUNDLE/PlugIns/PacketTunnel.appex"
APP_GROUP=$(plutil -extract RatelMeshAppGroup raw -o - "$APP_BUNDLE/Info.plist")
EXTENSION_APP_GROUP=$(plutil -extract RatelMeshAppGroup raw -o - "$EXTENSION_BUNDLE/Info.plist")
KEYCHAIN_GROUP=$(plutil -extract RatelMeshKeychainAccessGroup raw -o - "$APP_BUNDLE/Info.plist")
EXTENSION_KEYCHAIN_GROUP=$(plutil -extract RatelMeshKeychainAccessGroup raw -o - "$EXTENSION_BUNDLE/Info.plist")

for value in "$APP_GROUP" "$EXTENSION_APP_GROUP" "$KEYCHAIN_GROUP" "$EXTENSION_KEYCHAIN_GROUP"; do
    if [ -z "$value" ] || printf '%s\n' "$value" | grep -Eq '[[:space:]]|\$\('; then
        echo "iOS archive contains an empty or unresolved sharing group" >&2
        exit 1
    fi
done
if [ "$APP_GROUP:$KEYCHAIN_GROUP" != "$EXTENSION_APP_GROUP:$EXTENSION_KEYCHAIN_GROUP" ]; then
    echo "iOS app and extension Info.plist sharing groups differ" >&2
    exit 1
fi

Scripts/verify-archive.sh "$ARCHIVE_PATH"
SIGNED_ENTITLEMENTS=$(mktemp "${TMPDIR:-/tmp}/ratelmesh-ios-entitlements.XXXXXX")
trap 'rm -f "$SIGNED_ENTITLEMENTS"' EXIT INT TERM
codesign -d --entitlements :- "$APP_BUNDLE" >"$SIGNED_ENTITLEMENTS" 2>/dev/null
SIGNED_APP_GROUP=$(/usr/libexec/PlistBuddy -c "Print :com.apple.security.application-groups:0" "$SIGNED_ENTITLEMENTS")
SIGNED_KEYCHAIN_GROUP=$(/usr/libexec/PlistBuddy -c "Print :keychain-access-groups:0" "$SIGNED_ENTITLEMENTS")
if [ "$SIGNED_APP_GROUP:$SIGNED_KEYCHAIN_GROUP" != "$APP_GROUP:$KEYCHAIN_GROUP" ]; then
    echo "iOS signed entitlements do not match resolved Info.plist sharing groups" >&2
    exit 1
fi

if [ -n "${RATELMESH_EXPORT_OPTIONS_PLIST:-}" ]; then
    test -f "$RATELMESH_EXPORT_OPTIONS_PLIST"
    xcodebuild $PROVISIONING_FLAG -exportArchive \
        -archivePath "$ARCHIVE_PATH" \
        -exportPath "$EXPORT_PATH" \
        -exportOptionsPlist "$RATELMESH_EXPORT_OPTIONS_PLIST"
fi

printf '%s\n' "Signed archive: $ARCHIVE_PATH"
