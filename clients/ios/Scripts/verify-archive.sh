#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 ARCHIVE_PATH" >&2
    exit 2
fi

ARCHIVE_PATH=$1
APP_BUNDLE="$ARCHIVE_PATH/Products/Applications/RatelMesh.app"
EXTENSION_BUNDLE="$APP_BUNDLE/PlugIns/PacketTunnel.appex"

test -d "$APP_BUNDLE"
test -d "$EXTENSION_BUNDLE"
codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
if [ "$(plutil -extract ITSAppUsesNonExemptEncryption raw -o - "$APP_BUNDLE/Info.plist")" != "true" ]; then
    echo "iOS archive must declare non-exempt encryption use" >&2
    exit 1
fi

ENTITLEMENTS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-ios-entitlements.XXXXXX")
trap 'rm -rf "$ENTITLEMENTS_DIR"' EXIT INT TERM
codesign -d --entitlements :- "$APP_BUNDLE" >"$ENTITLEMENTS_DIR/app.plist" 2>/dev/null
codesign -d --entitlements :- "$EXTENSION_BUNDLE" >"$ENTITLEMENTS_DIR/extension.plist" 2>/dev/null

for key in com.apple.security.application-groups keychain-access-groups; do
    /usr/libexec/PlistBuddy -c "Print :$key" "$ENTITLEMENTS_DIR/app.plist" >"$ENTITLEMENTS_DIR/app-$key.txt"
    /usr/libexec/PlistBuddy -c "Print :$key" "$ENTITLEMENTS_DIR/extension.plist" >"$ENTITLEMENTS_DIR/extension-$key.txt"
    if ! cmp -s "$ENTITLEMENTS_DIR/app-$key.txt" "$ENTITLEMENTS_DIR/extension-$key.txt"; then
        echo "iOS app and extension signed entitlement '$key' differ" >&2
        exit 1
    fi
done

APP_ID=$(/usr/libexec/PlistBuddy -c "Print :application-identifier" "$ENTITLEMENTS_DIR/app.plist")
EXTENSION_APP_ID=$(/usr/libexec/PlistBuddy -c "Print :application-identifier" "$ENTITLEMENTS_DIR/extension.plist")
case "$APP_ID:$EXTENSION_APP_ID" in
    *.com.ratelmesh.ios:*.com.ratelmesh.ios.PacketTunnel) ;;
    *)
        echo "unexpected signed application identifiers" >&2
        exit 1
        ;;
esac

printf '%s\n' "Verified iOS archive: $ARCHIVE_PATH"
