#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 VERSION UPDATE.pkg OUTPUT.pkg" >&2
    exit 2
fi

VERSION=$1
UPDATE_PKG=$2
OUTPUT=$3
if ! printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "version must use MAJOR.MINOR.PATCH" >&2
    exit 2
fi
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APPLICATION_IDENTITY=${RATELMESH_APPLICATION_IDENTITY:--}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-installer.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

pkgutil --expand-full "$UPDATE_PKG" "$WORK/update"
PAYLOAD="$WORK/root"
BIN="$PAYLOAD/usr/local/ratelmesh/bin"
SHARE="$PAYLOAD/usr/local/ratelmesh/share"
mkdir -p "$BIN" "$SHARE" \
    "$PAYLOAD/Library/LaunchDaemons" \
    "$PAYLOAD/Library/LaunchAgents" \
    "$WORK/scripts"

install -m 755 "$WORK/update/Payload/usr/local/ratelmesh/bin/ratelmesh" "$BIN/ratelmesh"
install -m 755 "$WORK/update/Payload/usr/local/ratelmesh/bin/ratelmeshd" "$BIN/ratelmeshd"
install -m 755 "$ROOT/packaging/macos/installer/ratelmesh-enroll" "$BIN/ratelmesh-enroll"
install -m 755 "$ROOT/packaging/macos/installer/ratelmesh-uninstall" "$BIN/ratelmesh-uninstall"
install -m 755 "$ROOT/packaging/macos/installer/scripts/preinstall" "$WORK/scripts/preinstall"
install -m 755 "$ROOT/packaging/macos/installer/scripts/postinstall" "$WORK/scripts/postinstall"
install -m 600 "$ROOT/packaging/macos/installer/com.ratelmesh.daemon.plist" \
    "$PAYLOAD/Library/LaunchDaemons/com.ratelmesh.daemon.plist"
install -m 644 "$ROOT/packaging/macos/installer/com.ratelmesh.menubar.plist" \
    "$PAYLOAD/Library/LaunchAgents/com.ratelmesh.menubar.plist"

# Build both WireGuard runtime executables from checksum-pinned source. This is
# deliberately independent of Homebrew and every prior RatelMesh installer.
"$ROOT/scripts/build-macos-dependencies.sh" "$WORK/dependencies"
install -m 755 "$WORK/dependencies/bin/wg" "$BIN/wg"
install -m 755 "$WORK/dependencies/bin/wireguard-go" "$BIN/wireguard-go"
ditto "$WORK/dependencies/licenses" "$SHARE/licenses"
ditto "$WORK/dependencies/sources" "$SHARE/sources"
install -m 644 "$WORK/dependencies/THIRD-PARTY-NOTICES.txt" \
    "$SHARE/THIRD-PARTY-NOTICES.txt"
install -m 644 "$WORK/dependencies/BUILD-DEPENDENCIES.env" \
    "$SHARE/BUILD-DEPENDENCIES.env"

# Keep the menu app as installer source data rather than a relocatable bundle.
# postinstall copies it to /Applications for new users and also refreshes any
# legacy per-user app location during an upgrade.
APP="$SHARE/RatelMesh.app"
ditto "$WORK/update/Payload/usr/local/ratelmesh/share/RatelMesh.app" "$APP"
plutil -replace CFBundleShortVersionString -string "$VERSION" "$APP/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$(printf '%s' "$VERSION" | tr -d '.')" "$APP/Contents/Info.plist"
sign_item() {
    if [ "$APPLICATION_IDENTITY" = "-" ]; then
        codesign --force --sign - "$1"
    else
        codesign --force --options runtime --timestamp --sign "$APPLICATION_IDENTITY" "$1"
    fi
}
for EXECUTABLE in "$BIN/"*; do
    if file "$EXECUTABLE" | grep -q 'Mach-O'; then
        sign_item "$EXECUTABLE"
    fi
done
sign_item "$APP/Contents/MacOS/ratelmesh-menu"
sign_item "$APP"
codesign --verify --deep --strict "$APP"

PLIST="$PAYLOAD/Library/LaunchDaemons/com.ratelmesh.daemon.plist"
plutil -remove EnvironmentVariables.RATELMESH_AUTHKEY "$PLIST" 2>/dev/null || true
plutil -replace EnvironmentVariables.RATELMESH_COORD -string https://control.ratelmesh.com "$PLIST" 2>/dev/null || \
    plutil -insert EnvironmentVariables.RATELMESH_COORD -string https://control.ratelmesh.com "$PLIST"
chmod 600 "$PLIST"

if rg -q 'RATELMESH_AUTHKEY|ratelmeshauth-' "$PLIST"; then
    echo "refusing to package an embedded enrollment credential" >&2
    exit 1
fi
test "$(plutil -extract EnvironmentVariables.RATELMESH_COORD raw -o - "$PLIST")" = "https://control.ratelmesh.com"
plutil -lint "$PLIST" "$PAYLOAD/Library/LaunchAgents/com.ratelmesh.menubar.plist"
xattr -cr "$PAYLOAD"
find "$PAYLOAD" -name '._*' -delete

mkdir -p "$(dirname "$OUTPUT")"
UNSIGNED="$WORK/RatelMesh.pkg"
COMPONENTS="$WORK/components.plist"
# PackageKit otherwise treats the menu app as relocatable and can silently
# install the source copy over a legacy app with the same bundle identifier.
# Keep the source at its deterministic payload path; postinstall owns copying
# it to the system and any legacy per-user locations.
pkgbuild --analyze --root "$PAYLOAD" "$COMPONENTS"
plutil -replace 0.BundleIsRelocatable -bool false "$COMPONENTS"
# Rebuild the component package instead of flattening the modified base. This
# regenerates PackageInfo and Bom for the actual payload, and includes both the
# preinstall and postinstall scripts. Reusing the base metadata can produce an
# invalid XML declaration and a stale file manifest.
COPYFILE_DISABLE=1 COPY_EXTENDED_ATTRIBUTES_DISABLE=1 pkgbuild \
    --root "$PAYLOAD" \
    --scripts "$WORK/scripts" \
    --component-plist "$COMPONENTS" \
    --identifier com.ratelmesh.daemon.universal \
    --version "$VERSION" \
    --install-location / \
    "$UNSIGNED"
if [ -n "${RATELMESH_INSTALLER_IDENTITY:-}" ]; then
    productsign --sign "$RATELMESH_INSTALLER_IDENTITY" "$UNSIGNED" "$OUTPUT"
else
    cp "$UNSIGNED" "$OUTPUT"
fi
pkgutil --check-signature "$OUTPUT" || true
# Ask the same system Installer framework used by Finder to parse the finished
# package. This catches malformed PackageInfo metadata before publication.
OUTPUT_DIR=$(CDPATH= cd -- "$(dirname -- "$OUTPUT")" && pwd)
OUTPUT_ABS="$OUTPUT_DIR/$(basename -- "$OUTPUT")"
installer -pkg "$OUTPUT_ABS" -target / -showChoicesXML >/dev/null
"$ROOT/scripts/test-macos-universal-installer.sh" "$OUTPUT_ABS" "$VERSION"
echo "$OUTPUT"
