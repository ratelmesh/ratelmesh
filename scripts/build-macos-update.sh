#!/usr/bin/env bash
# Build an update-only macOS package for already-enrolled RatelMesh Macs.
# It replaces ratelmeshd/ratelmesh and restarts the existing launchd service without
# embedding or changing coordinator/auth credentials.
set -euo pipefail

VERSION="${1:-}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 <version> [output-directory]" >&2
  exit 2
fi

UPDATE_PUBLIC_KEY="${RATELMESH_UPDATE_PUBLIC_KEY:-}"
UPDATE_PQ_PUBLIC_KEY="${RATELMESH_UPDATE_PQ_PUBLIC_KEY:-}"
UPDATE_FEED_URL="${RATELMESH_UPDATE_FEED_URL:-https://download.ratelmesh.com/download/macos/latest.json}"
APPLICATION_IDENTITY="${RATELMESH_APPLICATION_IDENTITY:--}"
if [[ -z "$UPDATE_PUBLIC_KEY" || -z "$UPDATE_PQ_PUBLIC_KEY" ]]; then
  echo "RATELMESH_UPDATE_PUBLIC_KEY and RATELMESH_UPDATE_PQ_PUBLIC_KEY are required for a secure macOS release" >&2
  exit 2
fi
if [[ "$UPDATE_FEED_URL" != https://download.ratelmesh.com/download/* ]]; then
  echo "RATELMESH_UPDATE_FEED_URL must use the official HTTPS download host" >&2
  exit 2
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$REPO/packaging/macos/dependencies.env"
if [[ "$(GOTOOLCHAIN=local go version | awk '{print $3}')" != "$RATELMESH_GO_VERSION" ]]; then
  echo "Go $RATELMESH_GO_VERSION is required; found $(go version | awk '{print $3}')" >&2
  exit 2
fi
OUTDIR="${2:-/tmp/ratelmesh-macos-update-$VERSION}"
WORK="$OUTDIR/work"
ROOT="$WORK/root"
SCRIPTS="$REPO/packaging/macos/update/scripts"
PKG="$OUTDIR/RatelMesh-macOS-$VERSION-update.pkg"
APP="$ROOT/usr/local/ratelmesh/share/RatelMesh.app"

rm -rf "$WORK"
mkdir -p "$ROOT/usr/local/ratelmesh/bin" "$APP/Contents/MacOS" "$APP/Contents/Helpers" \
  "$APP/Contents/Resources" "$OUTDIR"

export PATH="/opt/homebrew/bin:$PATH"
for arch in amd64 arm64; do
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath -tags wgreal \
    -ldflags="-s -w" -o "$WORK/ratelmeshd-$arch" "$REPO/cmd/ratelmeshd"
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath \
    -ldflags="-s -w" -o "$WORK/ratelmesh-$arch" "$REPO/cmd/ratelmesh"
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath \
    -ldflags="-s -w" -o "$WORK/ratelmesh-pqverify-$arch" "$REPO/cmd/ratelmesh-pqverify"
done

for arch in x86_64 arm64; do
  xcrun swiftc -O -parse-as-library -target "$arch-apple-macos13.0" \
    -o "$WORK/ratelmesh-menu-$arch" \
    "$REPO/clients/macos-menubar/MenuModels.swift" \
    "$REPO/clients/macos-menubar/EnrollmentSupport.swift" \
    "$REPO/clients/macos-menubar/RatelMeshMenuApp.swift" \
    "$REPO/clients/macos-menubar/UpdateSupport.swift"
done

lipo -create "$WORK/ratelmeshd-amd64" "$WORK/ratelmeshd-arm64" \
  -output "$ROOT/usr/local/ratelmesh/bin/ratelmeshd"
lipo -create "$WORK/ratelmesh-amd64" "$WORK/ratelmesh-arm64" \
  -output "$ROOT/usr/local/ratelmesh/bin/ratelmesh"
lipo -create "$WORK/ratelmesh-pqverify-amd64" "$WORK/ratelmesh-pqverify-arm64" \
  -output "$APP/Contents/Helpers/ratelmesh-pqverify"
install -m 755 "$REPO/packaging/macos/installer/ratelmesh-uninstall" \
  "$ROOT/usr/local/ratelmesh/bin/ratelmesh-uninstall"
lipo -create "$WORK/ratelmesh-menu-x86_64" "$WORK/ratelmesh-menu-arm64" \
  -output "$APP/Contents/MacOS/ratelmesh-menu"
cp "$REPO/clients/macos-menubar/Info.plist" "$APP/Contents/Info.plist"
install -m 644 "$REPO/clients/macos-menubar/RatelMesh.icns" \
  "$APP/Contents/Resources/RatelMesh.icns"
plutil -replace CFBundleShortVersionString -string "$VERSION" "$APP/Contents/Info.plist"
plutil -replace CFBundleVersion -string "${VERSION//./}" "$APP/Contents/Info.plist"
plutil -replace RatelMeshUpdateFeedURL -string "$UPDATE_FEED_URL" "$APP/Contents/Info.plist" 2>/dev/null || \
  plutil -insert RatelMeshUpdateFeedURL -string "$UPDATE_FEED_URL" "$APP/Contents/Info.plist"
plutil -replace RatelMeshUpdatePublicKey -string "$UPDATE_PUBLIC_KEY" "$APP/Contents/Info.plist" 2>/dev/null || \
  plutil -insert RatelMeshUpdatePublicKey -string "$UPDATE_PUBLIC_KEY" "$APP/Contents/Info.plist"
plutil -replace RatelMeshUpdatePQPublicKey -string "$UPDATE_PQ_PUBLIC_KEY" "$APP/Contents/Info.plist" 2>/dev/null || \
  plutil -insert RatelMeshUpdatePQPublicKey -string "$UPDATE_PQ_PUBLIC_KEY" "$APP/Contents/Info.plist"
sign_item() {
  if [[ "$APPLICATION_IDENTITY" == "-" ]]; then
    codesign --force --sign - "$1"
  else
    codesign --force --options runtime --timestamp --sign "$APPLICATION_IDENTITY" "$1"
  fi
}
sign_item "$ROOT/usr/local/ratelmesh/bin/ratelmeshd"
sign_item "$ROOT/usr/local/ratelmesh/bin/ratelmesh"
sign_item "$APP/Contents/Helpers/ratelmesh-pqverify"
sign_item "$APP/Contents/MacOS/ratelmesh-menu"
sign_item "$APP"
codesign --verify --strict "$ROOT/usr/local/ratelmesh/bin/ratelmeshd"
codesign --verify --strict "$ROOT/usr/local/ratelmesh/bin/ratelmesh"
codesign --verify --deep --strict "$APP"
xattr -cr "$ROOT"
find "$ROOT" -name '._*' -delete

COPYFILE_DISABLE=1 COPY_EXTENDED_ATTRIBUTES_DISABLE=1 pkgbuild \
  --root "$ROOT" \
  --scripts "$SCRIPTS" \
  --identifier com.ratelmesh.daemon.update \
  --version "$VERSION" \
  --install-location / \
  "$PKG"

pkgutil --check-signature "$PKG" || true
shasum -a 256 "$PKG"
echo "$PKG"
