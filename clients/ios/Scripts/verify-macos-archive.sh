#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 ARCHIVE_PATH" >&2
    exit 2
fi

ARCHIVE_PATH=$1
APP="$ARCHIVE_PATH/Products/Applications/RatelMesh.app"
EXTENSION="$APP/Contents/PlugIns/PacketTunnel.appex"
CONTROL="$APP/Contents/Frameworks/RatelMeshControlMac.framework"

test -d "$APP"
test -d "$EXTENSION"
test -d "$CONTROL"
if [ -e "$EXTENSION/Contents/Resources/Info.plist" ]; then
    echo "macOS Packet Tunnel contains a second Info.plist resource" >&2
    exit 1
fi
if [ -e "$EXTENSION/Contents/Frameworks" ]; then
    echo "macOS Packet Tunnel must load the host-owned control framework" >&2
    exit 1
fi

codesign --verify --deep --strict --verbose=2 "$APP"
codesign --verify --strict --verbose=2 "$CONTROL"

if [ "$(plutil -extract ITSAppUsesNonExemptEncryption raw -o - "$APP/Contents/Info.plist")" != "false" ]; then
    echo "macOS archive must declare its current export-document exemption" >&2
    exit 1
fi
if plutil -extract ITSEncryptionExportComplianceCode raw -o - "$APP/Contents/Info.plist" >/dev/null 2>&1; then
    echo "macOS archive must not contain an unapproved export compliance code" >&2
    exit 1
fi

ENTITLEMENTS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-macos-store-entitlements.XXXXXX")
trap 'rm -rf "$ENTITLEMENTS_DIR"' EXIT INT TERM
codesign -d --entitlements :- "$APP" >"$ENTITLEMENTS_DIR/app.plist" 2>/dev/null
codesign -d --entitlements :- "$EXTENSION" >"$ENTITLEMENTS_DIR/extension.plist" 2>/dev/null

for bundle in app extension; do
    if [ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' "$ENTITLEMENTS_DIR/$bundle.plist")" != "true" ]; then
        echo "$bundle is not App Sandbox enabled" >&2
        exit 1
    fi
    /usr/libexec/PlistBuddy -c 'Print :com.apple.developer.networking.networkextension:0' \
        "$ENTITLEMENTS_DIR/$bundle.plist" | grep -qx packet-tunnel-provider
done

for key in com.apple.security.application-groups keychain-access-groups; do
    /usr/libexec/PlistBuddy -c "Print :$key" "$ENTITLEMENTS_DIR/app.plist" >"$ENTITLEMENTS_DIR/app-$key.txt"
    /usr/libexec/PlistBuddy -c "Print :$key" "$ENTITLEMENTS_DIR/extension.plist" >"$ENTITLEMENTS_DIR/extension-$key.txt"
    if ! cmp -s "$ENTITLEMENTS_DIR/app-$key.txt" "$ENTITLEMENTS_DIR/extension-$key.txt"; then
        echo "macOS app and extension signed entitlement '$key' differ" >&2
        exit 1
    fi
done

APP_ID=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.application-identifier' "$ENTITLEMENTS_DIR/app.plist" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c 'Print :application-identifier' "$ENTITLEMENTS_DIR/app.plist")
EXTENSION_APP_ID=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.application-identifier' "$ENTITLEMENTS_DIR/extension.plist" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c 'Print :application-identifier' "$ENTITLEMENTS_DIR/extension.plist")
case "$APP_ID:$EXTENSION_APP_ID" in
    *.com.ratelmesh.ios:*.com.ratelmesh.ios.PacketTunnel) ;;
    *)
        echo "unexpected macOS signed application identifiers" >&2
        exit 1
        ;;
esac

if find "$APP" -type f \( -name ratelmeshd -o -name ratelmesh-enroll -o -name '*.pkg' \) | grep -q .; then
    echo "macOS archive contains a privileged/direct-distribution component" >&2
    exit 1
fi

printf '%s\n' "Verified macOS App Store archive: $ARCHIVE_PATH"
