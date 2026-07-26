#!/usr/bin/env bash
# Build, Developer ID sign, notarize, staple, and sign the update feed for a
# production macOS release. This script intentionally has no unsigned mode.
set -euo pipefail

if [[ $# -ne 2 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 VERSION OUTPUT_DIRECTORY" >&2
  exit 2
fi

VERSION=$1
OUTDIR=$2
REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$REPO/packaging/macos/dependencies.env"
RELEASE_KEY="${RATELMESH_RELEASE_KEY:-$HOME/.config/ratelmesh/release-ed25519.key}"
APPLICATION_IDENTITY="${RATELMESH_APPLICATION_IDENTITY:-}"
INSTALLER_IDENTITY="${RATELMESH_INSTALLER_IDENTITY:-}"
NOTARY_PROFILE="${RATELMESH_NOTARY_PROFILE:-}"
NOTARY_KEYCHAIN="${RATELMESH_NOTARY_KEYCHAIN:-}"
PACKAGE_NAME="RatelMesh-macOS-$VERSION-universal.pkg"
PACKAGE_URL="https://download.ratelmesh.com/download/$PACKAGE_NAME"

for required in "$RELEASE_KEY" "$RELEASE_KEY.mldsa65"; do
  if [[ ! -f "$required" ]]; then
    echo "required file is missing: $required" >&2
    exit 2
  fi
done
if [[ "$(GOTOOLCHAIN=local go version | awk '{print $3}')" != "$RATELMESH_GO_VERSION" ]]; then
  echo "Go $RATELMESH_GO_VERSION is required for this release" >&2
  exit 2
fi
if [[ -z "$APPLICATION_IDENTITY" || -z "$INSTALLER_IDENTITY" || -z "$NOTARY_PROFILE" ]]; then
  echo "RATELMESH_APPLICATION_IDENTITY, RATELMESH_INSTALLER_IDENTITY, and RATELMESH_NOTARY_PROFILE are required" >&2
  exit 2
fi
if ! security find-identity -v -p codesigning | grep -Fq "\"$APPLICATION_IDENTITY\""; then
  echo "Developer ID Application identity is unavailable: $APPLICATION_IDENTITY" >&2
  exit 2
fi
if ! security find-certificate -a -c "$INSTALLER_IDENTITY" >/dev/null 2>&1; then
  echo "Developer ID Installer certificate is unavailable: $INSTALLER_IDENTITY" >&2
  exit 2
fi

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"
PUBLIC_KEY=$(go run "$REPO/scripts/update-manifest.go" public -key "$RELEASE_KEY")
PQ_PUBLIC_KEY=$(go run "$REPO/scripts/update-manifest.go" public-pq -key "$RELEASE_KEY")

RATELMESH_UPDATE_PUBLIC_KEY="$PUBLIC_KEY" \
RATELMESH_UPDATE_PQ_PUBLIC_KEY="$PQ_PUBLIC_KEY" \
RATELMESH_APPLICATION_IDENTITY="$APPLICATION_IDENTITY" \
  "$REPO/scripts/build-macos-update.sh" "$VERSION" "$OUTDIR/update"

RATELMESH_APPLICATION_IDENTITY="$APPLICATION_IDENTITY" \
RATELMESH_INSTALLER_IDENTITY="$INSTALLER_IDENTITY" \
  "$REPO/scripts/build-macos-installer.sh" \
    "$VERSION" "$OUTDIR/update/RatelMesh-macOS-$VERSION-update.pkg" "$OUTDIR/$PACKAGE_NAME"

pkgutil --check-signature "$OUTDIR/$PACKAGE_NAME" | grep -Fq "Developer ID Installer"
NOTARY_ARGS=(--keychain-profile "$NOTARY_PROFILE")
if [[ -n "$NOTARY_KEYCHAIN" ]]; then
  NOTARY_ARGS+=(--keychain "$NOTARY_KEYCHAIN")
fi
xcrun notarytool submit "$OUTDIR/$PACKAGE_NAME" "${NOTARY_ARGS[@]}" --wait
xcrun stapler staple "$OUTDIR/$PACKAGE_NAME"
xcrun stapler validate "$OUTDIR/$PACKAGE_NAME"
spctl --assess --type install -vv "$OUTDIR/$PACKAGE_NAME"

# Publish the exact GPL source archive that accompanies the bundled `wg`
# binary. It is also inside the package, but a sidecar makes source access
# possible without installing the product.
EXPANDED=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-release-pkg.XXXXXX")
trap 'rm -rf "$EXPANDED"' EXIT HUP INT TERM
pkgutil --expand-full "$OUTDIR/$PACKAGE_NAME" "$EXPANDED/package"
mkdir -p "$OUTDIR/sources"
SOURCE_NAME="wireguard-tools-$RATELMESH_WIREGUARD_TOOLS_VERSION.tar.xz"
install -m 644 \
  "$EXPANDED/package/Payload/usr/local/ratelmesh/share/sources/$SOURCE_NAME" \
  "$OUTDIR/sources/$SOURCE_NAME"
SOURCE_SHA=$(shasum -a 256 "$OUTDIR/sources/$SOURCE_NAME" | awk '{print $1}')
if [[ "$SOURCE_SHA" != "$RATELMESH_WIREGUARD_TOOLS_SHA256" ]]; then
  echo "packaged wireguard-tools source checksum changed unexpectedly" >&2
  exit 1
fi

go run "$REPO/scripts/update-manifest.go" sign \
  -key "$RELEASE_KEY" \
  -package "$OUTDIR/$PACKAGE_NAME" \
  -version "$VERSION" \
  -url "$PACKAGE_URL" \
  -minimum-system 13.0 \
  -output "$OUTDIR/macos/latest.json"

echo "$OUTDIR/$PACKAGE_NAME"
echo "$OUTDIR/macos/latest.json"
echo "$OUTDIR/sources/$SOURCE_NAME"
