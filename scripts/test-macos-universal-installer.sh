#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 PACKAGE.pkg VERSION" >&2
    exit 2
fi

PACKAGE=$1
VERSION=$2
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck disable=SC1091
. "$ROOT/packaging/macos/dependencies.env"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-universal-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

pkgutil --expand-full "$PACKAGE" "$WORK/package"
xmllint --noout "$WORK/package/PackageInfo"
test "$(xmllint --xpath 'count(/pkg-info/relocate/bundle)' "$WORK/package/PackageInfo")" = 0
test -x "$WORK/package/Scripts/preinstall"
test -x "$WORK/package/Scripts/postinstall"
test -x "$WORK/package/Payload/usr/local/ratelmesh/bin/ratelmesh-enroll"
test -x "$WORK/package/Payload/usr/local/ratelmesh/bin/ratelmesh-uninstall"
test -x "$WORK/package/Payload/usr/local/ratelmesh/bin/wg"
test -x "$WORK/package/Payload/usr/local/ratelmesh/bin/wireguard-go"
test -d "$WORK/package/Payload/usr/local/ratelmesh/share/RatelMesh.app"
test ! -e "$WORK/package/Payload/Applications/RatelMesh.app"
test -f "$WORK/package/Payload/usr/local/ratelmesh/share/licenses/wireguard-go/LICENSE"
test -f "$WORK/package/Payload/usr/local/ratelmesh/share/licenses/wireguard-tools/COPYING"
TOOLS_SOURCE="$WORK/package/Payload/usr/local/ratelmesh/share/sources/wireguard-tools-$RATELMESH_WIREGUARD_TOOLS_VERSION.tar.xz"
test "$(shasum -a 256 "$TOOLS_SOURCE" | awk '{print $1}')" = "$RATELMESH_WIREGUARD_TOOLS_SHA256"
APP_INFO="$WORK/package/Payload/usr/local/ratelmesh/share/RatelMesh.app/Contents/Info.plist"
test "$(plutil -extract CFBundleShortVersionString raw -o - "$APP_INFO")" = "$VERSION"
test "$(plutil -extract CFBundleIconFile raw -o - "$APP_INFO")" = "RatelMesh"
test -s "$WORK/package/Payload/usr/local/ratelmesh/share/RatelMesh.app/Contents/Resources/RatelMesh.icns"
rg -q '\[ -t 0 \]' "$WORK/package/Payload/usr/local/ratelmesh/bin/ratelmesh-enroll"
rg -q 'private authorization pipe' "$WORK/package/Payload/usr/local/ratelmesh/bin/ratelmesh-enroll"
test "$(plutil -extract RatelMeshUpdateFeedURL raw -o - "$APP_INFO")" = "https://download.ratelmesh.com/download/macos/latest.json"
UPDATE_PUBLIC_KEY=$(plutil -extract RatelMeshUpdatePublicKey raw -o - "$APP_INFO")
test "$(printf '%s' "$UPDATE_PUBLIC_KEY" | base64 -D | wc -c | tr -d ' ')" = 32

BIN="$WORK/package/Payload/usr/local/ratelmesh/bin"
for binary in ratelmesh ratelmeshd wg wireguard-go; do
    test "$(lipo -archs "$BIN/$binary")" = "x86_64 arm64"
    codesign --verify --strict "$BIN/$binary"
done
test "$("$BIN/wg" --version)" = \
    "wireguard-tools v$RATELMESH_WIREGUARD_TOOLS_VERSION - https://git.zx2c4.com/wireguard-tools/"
for binary in ratelmesh ratelmeshd wireguard-go; do
    for arch in x86_64 arm64; do
        THIN="$WORK/$binary-$arch"
        lipo "$BIN/$binary" -thin "$arch" -output "$THIN"
        test "$(go version -m "$THIN" | head -n 1 | awk '{print $2}')" = "$RATELMESH_GO_VERSION"
    done
done
go version -m "$WORK/wireguard-go-arm64" | awk \
    -v version="$RATELMESH_WIREGUARD_GO_VERSION" \
    '$1 == "mod" && $2 == "golang.zx2c4.com/wireguard" && $3 == version { found = 1 } END { exit !found }'
codesign --verify --deep --strict \
    "$WORK/package/Payload/usr/local/ratelmesh/share/RatelMesh.app"

PLIST="$WORK/package/Payload/Library/LaunchDaemons/com.ratelmesh.daemon.plist"
AGENT="$WORK/package/Payload/Library/LaunchAgents/com.ratelmesh.menubar.plist"
plutil -lint "$PLIST" "$AGENT" >/dev/null
test "$(plutil -extract EnvironmentVariables.RATELMESH_COORD raw -o - "$PLIST")" = https://control.ratelmesh.com
test "$(plutil -extract ProgramArguments.0 raw -o - "$AGENT")" = \
    /Applications/RatelMesh.app/Contents/MacOS/ratelmesh-menu
rg -q 'RatelMesh menu app exited before its icon became available' "$WORK/package/Scripts/postinstall"
rg -q '^MENU_LABEL=com\.ratelmesh\.menubar$' "$WORK/package/Scripts/postinstall"
rg -q 'AGENT=.*MENU_LABEL.*\.plist' "$WORK/package/Scripts/postinstall"
rg -q 'MENU_SERVICE="gui/\$USER_ID/\$MENU_LABEL"' "$WORK/package/Scripts/postinstall"
if rg -q 'LABEL\.menubar' "$WORK/package/Scripts/postinstall"; then
    echo "menu LaunchAgent must not be derived from the daemon label" >&2
    exit 1
fi
if rg -q 'launchctl bootstrap .*menubar.*\|\| true' "$WORK/package/Scripts/postinstall"; then
    echo "installer silently ignores menu LaunchAgent bootstrap failure" >&2
    exit 1
fi
if rg -q 'RATELMESH_AUTHKEY|ratelmeshauth-' "$PLIST" || rg -q 'ratelmeshauth-' "$WORK/package/Payload"; then
    echo "installer payload contains an enrollment credential" >&2
    exit 1
fi

make_existing_plist() {
    root=$1
    plist="$root/Library/LaunchDaemons/com.ratelmesh.daemon.plist"
    mkdir -p "$(dirname "$plist")" "$root/var/lib/ratelmesh"
    printf '%s\n' preserved-session >"$root/var/lib/ratelmesh/session.token"
    plutil -create xml1 "$plist"
    plutil -insert Label -string com.ratelmesh.daemon "$plist"
    plutil -insert EnvironmentVariables -dictionary "$plist"
    plutil -insert EnvironmentVariables.RATELMESH_COORD -string https://control.ratelmesh.com "$plist"
    plutil -insert EnvironmentVariables.RATELMESH_AUTHKEY -string preserved-test-value "$plist"
    chmod 600 "$plist"
}

run_scripts() {
    root=$1
    RATELMESH_INSTALL_ROOT="$root" RATELMESH_INSTALL_TEST_MODE=1 "$WORK/package/Scripts/preinstall"
    ditto "$WORK/package/Payload" "$root"
    RATELMESH_INSTALL_ROOT="$root" RATELMESH_INSTALL_TEST_MODE=1 "$WORK/package/Scripts/postinstall"
}

# Existing devices are updated in place while their coordinator and credential
# configuration survives. The upgrade adds only the idempotent cloud EXIT
# permission to the preserved daemon arguments.
EXISTING="$WORK/existing"
make_existing_plist "$EXISTING"
run_scripts "$EXISTING"
test "$(plutil -extract EnvironmentVariables.RATELMESH_COORD raw -o - "$EXISTING/Library/LaunchDaemons/com.ratelmesh.daemon.plist")" = https://control.ratelmesh.com
test "$(plutil -extract EnvironmentVariables.RATELMESH_AUTHKEY raw -o - "$EXISTING/Library/LaunchDaemons/com.ratelmesh.daemon.plist")" = preserved-test-value
test "$(plutil -extract EnvironmentVariables.RATELMESH_VERIFY_KEY raw -o - "$EXISTING/Library/LaunchDaemons/com.ratelmesh.daemon.plist")" = e1qzn0SwLDllwhSZ2k6zYdMLXXvj3y6quBo5KYwKjlI=
test "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments' "$EXISTING/Library/LaunchDaemons/com.ratelmesh.daemon.plist" | grep -Fxc '    -enable-nat')" = 1
# Repeating the upgrade must not duplicate the permission.
run_scripts "$EXISTING"
test "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments' "$EXISTING/Library/LaunchDaemons/com.ratelmesh.daemon.plist" | grep -Fxc '    -enable-nat')" = 1
test -x "$EXISTING/usr/local/ratelmesh/bin/ratelmeshd"
test -x "$EXISTING/Applications/RatelMesh.app/Contents/MacOS/ratelmesh-menu"
test -f "$EXISTING/var/db/ratelmesh/enrolled"

# New devices receive the RatelMesh coordinator with no embedded enrollment
# credential and remain stopped until ratelmesh-enroll consumes a one-use code.
NEW="$WORK/new"
mkdir -p "$NEW"
run_scripts "$NEW"
NEW_PLIST="$NEW/Library/LaunchDaemons/com.ratelmesh.daemon.plist"
test "$(plutil -extract EnvironmentVariables.RATELMESH_COORD raw -o - "$NEW_PLIST")" = https://control.ratelmesh.com
test "$(plutil -extract EnvironmentVariables.RATELMESH_VERIFY_KEY raw -o - "$NEW_PLIST")" = e1qzn0SwLDllwhSZ2k6zYdMLXXvj3y6quBo5KYwKjlI=
test "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments' "$NEW_PLIST" | grep -Fxc '    -enable-nat')" = 1
if plutil -extract EnvironmentVariables.RATELMESH_AUTHKEY raw -o - "$NEW_PLIST" >/dev/null 2>&1; then
    echo "new install contains an enrollment credential" >&2
    exit 1
fi
test -x "$NEW/usr/local/ratelmesh/bin/ratelmesh-enroll"
test -x "$NEW/Applications/RatelMesh.app/Contents/MacOS/ratelmesh-menu"
test ! -e "$NEW/var/db/ratelmesh/enrolled"

# A pre-RatelMesh installation is stopped and migrated by the full installer:
# its device state moves to the new location and the old launchd label is gone.
LEGACY="$WORK/legacy"
LEGACY_LABEL=ai.futurealpha.h"bmesh"
LEGACY_STATE="$LEGACY/var/lib/h""bmesh"
mkdir -p "$LEGACY/Library/LaunchDaemons" "$LEGACY_STATE"
printf '%s\n' preserved-device-state >"$LEGACY_STATE/device.json"
plutil -create xml1 "$LEGACY/Library/LaunchDaemons/$LEGACY_LABEL.plist"
plutil -insert Label -string "$LEGACY_LABEL" "$LEGACY/Library/LaunchDaemons/$LEGACY_LABEL.plist"
run_scripts "$LEGACY"
test "$(cat "$LEGACY/var/lib/ratelmesh/device.json")" = preserved-device-state
test ! -e "$LEGACY_STATE"
test ! -e "$LEGACY/Library/LaunchDaemons/$LEGACY_LABEL.plist"
test -f "$LEGACY/Library/LaunchDaemons/com.ratelmesh.daemon.plist"

# The uninstaller is root-prefix aware in test mode: it removes RatelMesh state and
# both app locations without touching the real host running this test.
UNINSTALL_ROOT="$WORK/uninstall"
ditto "$NEW" "$UNINSTALL_ROOT"
mkdir -p "$UNINSTALL_ROOT/Users/test/Library/LaunchAgents" \
    "$UNINSTALL_ROOT/Users/test/Applications/RatelMesh.app" \
    "$UNINSTALL_ROOT/Users/test/Library/Application Support/ratelmesh"
cp "$AGENT" "$UNINSTALL_ROOT/Users/test/Library/LaunchAgents/com.ratelmesh.menubar.plist"
RATELMESH_INSTALL_ROOT="$UNINSTALL_ROOT" RATELMESH_UNINSTALL_TEST_MODE=1 \
    RATELMESH_UNINSTALL_USER=test RATELMESH_UNINSTALL_USER_HOME=/Users/test \
    "$WORK/package/Payload/usr/local/ratelmesh/bin/ratelmesh-uninstall"
test ! -e "$UNINSTALL_ROOT/usr/local/ratelmesh"
test ! -e "$UNINSTALL_ROOT/Library/LaunchDaemons/com.ratelmesh.daemon.plist"
test ! -e "$UNINSTALL_ROOT/Applications/RatelMesh.app"
test ! -e "$UNINSTALL_ROOT/Users/test/Applications/RatelMesh.app"
test ! -e "$UNINSTALL_ROOT/Users/test/Library/Application Support/ratelmesh"

echo "universal installer tests passed"
