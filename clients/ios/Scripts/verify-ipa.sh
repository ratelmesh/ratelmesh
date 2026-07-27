#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 IPA_PATH" >&2
    exit 2
fi

IPA_PATH=$1
test -f "$IPA_PATH"

VERIFY_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-ios-ipa.XXXXXX")
trap 'rm -rf "$VERIFY_DIR"' EXIT INT TERM
unzip -q "$IPA_PATH" -d "$VERIFY_DIR"

APP_BUNDLE=$(find "$VERIFY_DIR/Payload" -maxdepth 1 -type d -name '*.app' -print -quit)
EXTENSION_BUNDLE="$APP_BUNDLE/PlugIns/PacketTunnel.appex"
test -n "$APP_BUNDLE"
test -d "$EXTENSION_BUNDLE"
codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"

if [ "$(plutil -extract ITSAppUsesNonExemptEncryption raw -o - "$APP_BUNDLE/Info.plist")" != "true" ]; then
    echo "iOS IPA must declare non-exempt encryption use" >&2
    exit 1
fi

for bundle in "$APP_BUNDLE" "$EXTENSION_BUNDLE"; do
    PROFILE="$VERIFY_DIR/profile.plist"
    security cms -D -i "$bundle/embedded.mobileprovision" >"$PROFILE"
    if [ "$(plutil -extract Entitlements.get-task-allow raw -o - "$PROFILE")" != "false" ] ||
       [ "$(plutil -extract Entitlements.beta-reports-active raw -o - "$PROFILE")" != "true" ]; then
        echo "bundle does not contain an App Store distribution profile: $bundle" >&2
        exit 1
    fi
done

AUTHORITY=$(codesign -dv --verbose=4 "$APP_BUNDLE" 2>&1 | sed -n 's/^Authority=//p' | head -1)
case "$AUTHORITY" in
    "Apple Distribution: "*) ;;
    *)
        echo "unexpected IPA signing authority: $AUTHORITY" >&2
        exit 1
        ;;
esac

printf '%s\n' "Verified App Store IPA: $IPA_PATH"
