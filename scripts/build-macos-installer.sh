#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 VERSION UPDATE.pkg OUTPUT.pkg" >&2
    exit 2
fi

VERSION=$1
UPDATE_PKG=$2
OUTPUT=$3
if ! printf '%s\n' "$VERSION" |
    grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    echo "version must use canonical MAJOR.MINOR.PATCH without leading zeros" >&2
    exit 2
fi
if [ ! -f "$UPDATE_PKG" ] || [ -L "$UPDATE_PKG" ]; then
    echo "update package must be a regular non-symbolic-link file: $UPDATE_PKG" >&2
    exit 2
fi
if [ -e "$OUTPUT" ] || [ -L "$OUTPUT" ]; then
    echo "installer output must not already exist: $OUTPUT" >&2
    exit 2
fi
OUTPUT_DIR=$(dirname -- "$OUTPUT")
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(CDPATH= cd -- "$OUTPUT_DIR" && pwd)
OUTPUT_ABS="$OUTPUT_DIR/$(basename -- "$OUTPUT")"
if [ -e "$OUTPUT_ABS" ] || [ -L "$OUTPUT_ABS" ]; then
    echo "installer output must not already exist: $OUTPUT_ABS" >&2
    exit 2
fi
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CANONICAL_INFO="$ROOT/clients/macos-menubar/Info.plist"
CANONICAL_VERSION=$(plutil -extract CFBundleShortVersionString raw -o - "$CANONICAL_INFO")
BUNDLE_BUILD=$(plutil -extract CFBundleVersion raw -o - "$CANONICAL_INFO")
if [ "$CANONICAL_VERSION" != "$VERSION" ]; then
    echo "requested version $VERSION does not match canonical macOS metadata $CANONICAL_VERSION" >&2
    exit 2
fi
case "$BUNDLE_BUILD" in
    ''|0|0*|*[!0-9]*)
        echo "canonical CFBundleVersion must be a positive integer without leading zeros" >&2
        exit 2
        ;;
esac
APPLICATION_IDENTITY=${RATELMESH_APPLICATION_IDENTITY:--}
WORK=$(mktemp -d "$OUTPUT_DIR/.ratelmesh-installer.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
STAGED_OUTPUT="$WORK/RatelMesh-final.pkg"

install -m 600 "$UPDATE_PKG" "$WORK/update-input.pkg"
pkgutil --expand-full "$WORK/update-input.pkg" "$WORK/update"
UPDATE_INFO="$WORK/update/Payload/usr/local/ratelmesh/share/RatelMesh.app/Contents/Info.plist"
UPDATE_PROVENANCE="$WORK/update/Payload/usr/local/ratelmesh/share/BUILD-PROVENANCE.json"
UPDATE_VERSION=$(plutil -extract CFBundleShortVersionString raw -o - "$UPDATE_INFO" 2>/dev/null || true)
UPDATE_BUILD=$(plutil -extract CFBundleVersion raw -o - "$UPDATE_INFO" 2>/dev/null || true)
PROVENANCE_VERSION=$(plutil -extract version raw -o - "$UPDATE_PROVENANCE" 2>/dev/null || true)
PROVENANCE_BUILD=$(plutil -extract build raw -o - "$UPDATE_PROVENANCE" 2>/dev/null || true)
PROVENANCE_COMMIT=$(plutil -extract sourceCommit raw -o - "$UPDATE_PROVENANCE" 2>/dev/null || true)
PROVENANCE_EPOCH=$(plutil -extract sourceDateEpoch raw -o - "$UPDATE_PROVENANCE" 2>/dev/null || true)
if [ "$UPDATE_VERSION" != "$VERSION" ] || [ "$PROVENANCE_VERSION" != "$VERSION" ]; then
    echo "update package version does not match requested installer version" >&2
    exit 1
fi
if [ "$UPDATE_BUILD" != "$BUNDLE_BUILD" ] || [ "$PROVENANCE_BUILD" != "$BUNDLE_BUILD" ]; then
    echo "update package build does not match canonical bundle build" >&2
    exit 1
fi
if ! printf '%s\n' "$PROVENANCE_COMMIT" | grep -Eq '^[0-9a-f]{40}$' ||
    ! printf '%s\n' "$PROVENANCE_EPOCH" | grep -Eq '^[0-9]+$'; then
    echo "update package has invalid source provenance" >&2
    exit 1
fi
PAYLOAD="$WORK/root"
BIN="$PAYLOAD/usr/local/ratelmesh/bin"
SHARE="$PAYLOAD/usr/local/ratelmesh/share"
mkdir -p "$BIN" "$SHARE" \
    "$PAYLOAD/Library/LaunchDaemons" \
    "$PAYLOAD/Library/LaunchAgents" \
    "$WORK/scripts"
install -m 644 "$UPDATE_PROVENANCE" "$SHARE/BUILD-PROVENANCE.json"

install -m 755 "$WORK/update/Payload/usr/local/ratelmesh/bin/ratelmesh" "$BIN/ratelmesh"
install -m 755 "$WORK/update/Payload/usr/local/ratelmesh/bin/ratelmeshd" "$BIN/ratelmeshd"
for EXECUTABLE in "$BIN/ratelmesh" "$BIN/ratelmeshd"; do
    test "$(lipo -archs "$EXECUTABLE")" = "x86_64 arm64"
done
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
plutil -replace CFBundleVersion -string "$BUNDLE_BUILD" "$APP/Contents/Info.plist"
test "$(plutil -extract CFBundleShortVersionString raw -o - "$APP/Contents/Info.plist")" = "$VERSION"
test "$(plutil -extract CFBundleVersion raw -o - "$APP/Contents/Info.plist")" = "$BUNDLE_BUILD"
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
    productsign --sign "$RATELMESH_INSTALLER_IDENTITY" "$UNSIGNED" "$STAGED_OUTPUT"
else
    cp "$UNSIGNED" "$STAGED_OUTPUT"
fi
pkgutil --check-signature "$STAGED_OUTPUT" || true
# Ask the same system Installer framework used by Finder to parse the finished
# package. This catches malformed PackageInfo metadata before publication.
installer -pkg "$STAGED_OUTPUT" -target / -showChoicesXML >/dev/null
"$ROOT/scripts/test-macos-universal-installer.sh" "$STAGED_OUTPUT" "$VERSION"
ln "$STAGED_OUTPUT" "$OUTPUT_ABS"
rm -f "$STAGED_OUTPUT"
echo "$OUTPUT_ABS"
