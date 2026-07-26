#!/usr/bin/env bash
# Build an update-only macOS package for already-enrolled RatelMesh Macs.
# It replaces ratelmeshd/ratelmesh and restarts the existing launchd service without
# embedding or changing coordinator/auth credentials.
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "usage: $0 <version> [output-directory]" >&2
  exit 2
fi
if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "version must use canonical MAJOR.MINOR.PATCH without leading zeros" >&2
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
if [[ "$UPDATE_FEED_URL" != "https://download.ratelmesh.com/download/macos/latest.json" ]]; then
  echo "RATELMESH_UPDATE_FEED_URL must be the canonical production feed" >&2
  exit 2
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_COMMIT="$(git -C "$REPO" rev-parse --verify HEAD)"
SOURCE_DATE_EPOCH="$(git -C "$REPO" show -s --format=%ct HEAD)"
if [[ ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ||
      ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
  echo "source commit metadata is invalid" >&2
  exit 2
fi
if [[ -n "$(git -C "$REPO" status --porcelain --untracked-files=all)" ]]; then
  echo "source tree must be clean before building release artifacts" >&2
  exit 2
fi
"$REPO/scripts/test-client-locales.py"
CANONICAL_INFO="$REPO/clients/macos-menubar/Info.plist"
CANONICAL_VERSION=$(plutil -extract CFBundleShortVersionString raw -o - "$CANONICAL_INFO")
BUNDLE_BUILD=$(plutil -extract CFBundleVersion raw -o - "$CANONICAL_INFO")
if [[ "$CANONICAL_VERSION" != "$VERSION" ]]; then
  echo "requested version $VERSION does not match canonical macOS metadata $CANONICAL_VERSION" >&2
  exit 2
fi
if [[ ! "$BUNDLE_BUILD" =~ ^[1-9][0-9]*$ ]]; then
  echo "canonical CFBundleVersion must be a positive integer without leading zeros" >&2
  exit 2
fi
# shellcheck disable=SC1091
source "$REPO/packaging/macos/dependencies.env"
if [[ "$(GOTOOLCHAIN=local go version | awk '{print $3}')" != "$RATELMESH_GO_VERSION" ]]; then
  echo "Go $RATELMESH_GO_VERSION is required; found $(go version | awk '{print $3}')" >&2
  exit 2
fi
OUTDIR="${2:-/tmp/ratelmesh-macos-update-$VERSION}"
SCRIPTS="$REPO/packaging/macos/update/scripts"

if [[ -L "$OUTDIR" ]]; then
  echo "macOS update output directory must not be a symbolic link: $OUTDIR" >&2
  exit 2
fi
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"
PKG="$OUTDIR/RatelMesh-macOS-$VERSION-update.pkg"
if [[ -e "$PKG" || -L "$PKG" ]]; then
  echo "macOS update package must not already exist: $PKG" >&2
  exit 2
fi
WORK="$(mktemp -d "$OUTDIR/.ratelmesh-macos-update.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
ROOT="$WORK/root"
STAGED_PKG="$WORK/RatelMesh-macOS-$VERSION-update.pkg"
APP="$ROOT/usr/local/ratelmesh/share/RatelMesh.app"
mkdir -p "$ROOT/usr/local/ratelmesh/bin" "$APP/Contents/MacOS" "$APP/Contents/Helpers" \
  "$APP/Contents/Resources"
PROVENANCE="$ROOT/usr/local/ratelmesh/share/BUILD-PROVENANCE.json"
printf '{\n  "version": "%s",\n  "build": "%s",\n  "platform": "macos",\n  "architecture": "universal",\n  "sourceCommit": "%s",\n  "sourceDateEpoch": %s,\n  "go": "%s"\n}\n' \
  "$VERSION" "$BUNDLE_BUILD" "$SOURCE_COMMIT" "$SOURCE_DATE_EPOCH" \
  "$RATELMESH_GO_VERSION" >"$PROVENANCE"
chmod 0644 "$PROVENANCE"

export PATH="/opt/homebrew/bin:$PATH"
for arch in amd64 arm64; do
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath -tags wgreal \
    -ldflags="-s -w" -o "$WORK/ratelmeshd-$arch" "$REPO/cmd/ratelmeshd"
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath \
    -ldflags="-s -w -X main.version=$VERSION" -o "$WORK/ratelmesh-$arch" "$REPO/cmd/ratelmesh"
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath \
    -ldflags="-s -w" -o "$WORK/ratelmesh-pqverify-$arch" "$REPO/cmd/ratelmesh-pqverify"
  for executable in ratelmeshd ratelmesh ratelmesh-pqverify; do
    build_info="$(go version -m "$WORK/$executable-$arch")"
    grep -Fq $'build\tvcs.revision='"$SOURCE_COMMIT" <<<"$build_info"
    grep -Fq $'build\tvcs.modified=false' <<<"$build_info"
  done
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
for executable in \
  "$ROOT/usr/local/ratelmesh/bin/ratelmeshd" \
  "$ROOT/usr/local/ratelmesh/bin/ratelmesh" \
  "$APP/Contents/Helpers/ratelmesh-pqverify" \
  "$APP/Contents/MacOS/ratelmesh-menu"; do
  test "$(lipo -archs "$executable")" = "x86_64 arm64"
done
cp "$REPO/clients/macos-menubar/Info.plist" "$APP/Contents/Info.plist"
install -m 644 "$REPO/clients/macos-menubar/RatelMesh.icns" \
  "$APP/Contents/Resources/RatelMesh.icns"
install -m 644 "$REPO/clients/macos-menubar/BrandMarkDark.png" \
  "$APP/Contents/Resources/BrandMarkDark.png"
if [[ -d "$REPO/clients/macos-menubar/Localizations" ]]; then
  for localization in "$REPO"/clients/macos-menubar/Localizations/*.lproj; do
    [[ -d "$localization" ]] || continue
    ditto "$localization" "$APP/Contents/Resources/$(basename "$localization")"
  done
fi
plutil -replace CFBundleShortVersionString -string "$VERSION" "$APP/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$BUNDLE_BUILD" "$APP/Contents/Info.plist"
test "$(plutil -extract CFBundleShortVersionString raw -o - "$APP/Contents/Info.plist")" = "$VERSION"
test "$(plutil -extract CFBundleVersion raw -o - "$APP/Contents/Info.plist")" = "$BUNDLE_BUILD"
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
  "$STAGED_PKG"

pkgutil --check-signature "$STAGED_PKG" || true
pkgutil --expand-full "$STAGED_PKG" "$WORK/verify"
PACKAGED_INFO="$WORK/verify/Payload/usr/local/ratelmesh/share/RatelMesh.app/Contents/Info.plist"
PACKAGED_PROVENANCE="$WORK/verify/Payload/usr/local/ratelmesh/share/BUILD-PROVENANCE.json"
test "$(plutil -extract CFBundleShortVersionString raw -o - "$PACKAGED_INFO")" = "$VERSION"
test "$(plutil -extract CFBundleVersion raw -o - "$PACKAGED_INFO")" = "$BUNDLE_BUILD"
test "$(plutil -extract version raw -o - "$PACKAGED_PROVENANCE")" = "$VERSION"
test "$(plutil -extract build raw -o - "$PACKAGED_PROVENANCE")" = "$BUNDLE_BUILD"
test "$(plutil -extract sourceCommit raw -o - "$PACKAGED_PROVENANCE")" = "$SOURCE_COMMIT"
shasum -a 256 "$STAGED_PKG"
ln "$STAGED_PKG" "$PKG"
rm -f "$STAGED_PKG"
echo "$PKG"
