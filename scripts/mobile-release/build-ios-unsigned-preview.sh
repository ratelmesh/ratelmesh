#!/usr/bin/env bash
# Rebuild the explicitly non-installable iOS developer preview from one
# committed tree and emit a deterministic ZIP, checksum, and provenance.
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ||
      ! "$2" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: $0 VERSION BUILD NEW_OUTPUT_DIRECTORY [SOURCE_REF]" >&2
  exit 2
fi

VERSION=$1
BUILD=$2
OUTDIR=$3
SOURCE_REF=${4:-HEAD}
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

fail() {
  echo "iOS preview build failed: $*" >&2
  exit 1
}

export PATH="/opt/homebrew/bin:$PATH"
command -v go >/dev/null || fail "Go is required"
command -v rsync >/dev/null || fail "rsync is required"

if [[ -e "$OUTDIR" || -L "$OUTDIR" ]]; then
  fail "output path must not already exist: $OUTDIR"
fi
SOURCE_COMMIT=$(git -C "$REPO" rev-parse --verify "$SOURCE_REF^{commit}" 2>/dev/null) ||
  fail "source ref is not a commit"
SOURCE_EPOCH=$(git -C "$REPO" show -s --format=%ct "$SOURCE_COMMIT")
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] ||
  fail "source commit is not a full object ID"

PARENT=$(dirname -- "$OUTDIR")
mkdir -p "$PARENT"
PARENT=$(cd "$PARENT" && pwd)
OUTDIR="$PARENT/$(basename -- "$OUTDIR")"
WORK="/tmp/ratelmesh-ios-preview-$SOURCE_COMMIT"
mkdir -m 0700 "$WORK" ||
  fail "deterministic iOS build workspace is already in use: $WORK"
STAGE=
MOBILE_WORK=
cleanup() {
  rm -rf "$WORK" "$STAGE"
  if [[ -n "$MOBILE_WORK" ]]; then
    rm -rf "$MOBILE_WORK"
  fi
}
trap cleanup EXIT HUP INT TERM
STAGE=$(mktemp -d "$PARENT/.ratelmesh-ios-preview.XXXXXX")
mkdir "$WORK/source"
git -C "$REPO" archive "$SOURCE_COMMIT" | tar -xf - -C "$WORK/source"
SOURCE="$WORK/source"
IOS="$SOURCE/clients/ios"

PROJECT_VERSION=$(awk '/MARKETING_VERSION:/ { print $2; exit }' "$IOS/project.yml")
PROJECT_BUILD=$(awk '/CURRENT_PROJECT_VERSION:/ { print $2; exit }' "$IOS/project.yml")
[[ "$PROJECT_VERSION:$PROJECT_BUILD" == "$VERSION:$BUILD" ]] ||
  fail "requested $VERSION/$BUILD does not match committed iOS metadata $PROJECT_VERSION/$PROJECT_BUILD"

if [[ "${RATELMESH_MOBILE_RELEASE_VALIDATE_ONLY:-0}" == 1 ]]; then
  echo "Validated iOS preview source $SOURCE_COMMIT at $VERSION ($BUILD)"
  exit 0
fi

for command in xcodebuild xcodegen xcrun zip; do
  command -v "$command" >/dev/null || fail "required command is unavailable: $command"
done
if ! xcrun simctl list runtimes available 2>/dev/null | grep -Eq '^iOS[[:space:]]'; then
  fail "an iOS Simulator runtime is required by Xcode's asset compiler"
fi

# Build the bridge with the repository's pinned x/mobile revision, but make it
# independent of this recipe's random workspace and suppress Go build IDs.
XMOBILE_VERSION=v0.0.0-20260709172247-6129f5bee9d5
MOBILE_PATH="/tmp/ratelmesh-mobile-release-$SOURCE_COMMIT-ios"
mkdir -m 0700 "$MOBILE_PATH" ||
  fail "deterministic mobile build workspace is already in use: $MOBILE_PATH"
MOBILE_WORK="$MOBILE_PATH"
mkdir "$MOBILE_WORK/repo"
rsync -a --exclude .git --exclude clients "$SOURCE/" "$MOBILE_WORK/repo/"
(
  cd "$MOBILE_WORK/repo"
  export PATH="/opt/homebrew/bin:$MOBILE_WORK/bin:$(go env GOPATH)/bin:$PATH"
  go get -tool "golang.org/x/mobile/cmd/gobind@$XMOBILE_VERSION"
  GOBIN="$MOBILE_WORK/bin" go install "golang.org/x/mobile/cmd/gomobile@$XMOBILE_VERSION"
  GOBIN="$MOBILE_WORK/bin" go install "golang.org/x/mobile/cmd/gobind@$XMOBILE_VERSION"
  rm -rf "$IOS/Frameworks/RatelMeshMobile.xcframework"
  "$MOBILE_WORK/bin/gomobile" bind \
    -trimpath \
    -ldflags=-buildid= \
    -target=ios \
    -o "$IOS/Frameworks/RatelMeshMobile.xcframework" \
    ./mobile
)

(
  cd "$IOS"
  "$SOURCE/scripts/test-client-locales.py"
  Scripts/prepare-wireguard.sh
  # The pinned WireGuard bridge otherwise injects a fresh Go build ID, which
  # also makes ld64 derive a different UUID for PacketTunnel on every build.
  perl -i -pe 's/go build -ldflags=-w /go build -ldflags="-w -buildid=" /' \
    Dependencies/wireguard-apple/Sources/WireGuardKitGo/Makefile
  grep -Fq -- '-ldflags="-w -buildid="' \
    Dependencies/wireguard-apple/Sources/WireGuardKitGo/Makefile ||
    fail "could not make the pinned WireGuard bridge reproducible"
  xcodegen generate
  xcodebuild -project RatelMesh.xcodeproj \
    -target RatelMesh \
    -configuration Release \
    -sdk iphoneos \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    ENABLE_TESTABILITY=NO \
    SWIFT_SERIALIZE_DEBUGGING_OPTIONS=NO \
    SYMROOT="$WORK/build" \
    OBJROOT="$WORK/obj" \
    build
)

APP="$WORK/build/Release-iphoneos/RatelMesh.app"
EXTENSION="$APP/PlugIns/PacketTunnel.appex"
[[ -d "$APP" && -d "$EXTENSION" ]] || fail "Xcode did not produce the app and tunnel extension"
for bundle in "$APP" "$EXTENSION"; do
  ACTUAL_VERSION=$(plutil -extract CFBundleShortVersionString raw -o - "$bundle/Info.plist")
  ACTUAL_BUILD=$(plutil -extract CFBundleVersion raw -o - "$bundle/Info.plist")
  [[ "$ACTUAL_VERSION:$ACTUAL_BUILD" == "$VERSION:$BUILD" ]] ||
    fail "compiled bundle metadata differs in $bundle"
  [[ ! -e "$bundle/_CodeSignature" && ! -e "$bundle/embedded.mobileprovision" ]] ||
    fail "unsigned preview unexpectedly contains signing material"
  if codesign --verify "$bundle" >/dev/null 2>&1; then
    fail "unsigned preview unexpectedly passes code-signature verification"
  fi
done

ARCHIVE_TIMESTAMP="$(TZ=UTC date -r "$SOURCE_EPOCH" '+%Y%m%d%H%M.%S')"
find "$APP" -exec touch -h -t "$ARCHIVE_TIMESTAMP" {} +
ARTIFACT="RatelMesh-iOS-$VERSION-unsigned.zip"
(
  cd "$(dirname "$APP")"
  find "$(basename "$APP")" -print |
    LC_ALL=C sort |
    /usr/bin/zip -X -y -q "$STAGE/$ARTIFACT" -@
)
chmod 0644 "$STAGE/$ARTIFACT"
XCODE_VERSION=$(xcodebuild -version | tr '\n' ' ' | sed 's/[[:space:]]*$//')
SWIFT_VERSION=$(xcrun swiftc --version | sed -nE 's/^Apple Swift version ([^ ]+).*/\1/p')
TOOLCHAIN="xcode=$XCODE_VERSION;swift=$SWIFT_VERSION"
go run "$SOURCE/scripts/mobile-release/provenance.go" \
  -artifact "$STAGE/$ARTIFACT" \
  -platform ios \
  -classification unsigned-developer-preview \
  -version "$VERSION" \
  -build "$BUILD" \
  -source-commit "$SOURCE_COMMIT" \
  -source-date-epoch "$SOURCE_EPOCH" \
  -signing unsigned \
  -toolchain "$TOOLCHAIN" \
  -output "$STAGE/$ARTIFACT.provenance.json"
(
  cd "$STAGE"
  shasum -a 256 "$ARTIFACT" >"$ARTIFACT.sha256"
  chmod 0644 "$ARTIFACT.sha256"
)

mkdir -m 0755 "$OUTDIR"
for file in "$ARTIFACT" "$ARTIFACT.sha256" "$ARTIFACT.provenance.json"; do
  ln "$STAGE/$file" "$OUTDIR/$file"
done
echo "$OUTDIR/$ARTIFACT"
