#!/usr/bin/env bash
# Build the macOS WireGuard runtime from pinned upstream sources. No Homebrew
# binaries and no prior RatelMesh package are accepted as build inputs.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$REPO/packaging/macos/dependencies.env"
OUT=$1
if [[ -e "$OUT" || -L "$OUT" ]]; then
  echo "dependency output directory must not already exist: $OUT" >&2
  exit 2
fi
OUT_PARENT=$(dirname -- "$OUT")
mkdir -p "$OUT_PARENT"
OUT_PARENT=$(cd "$OUT_PARENT" && pwd)
OUT="$OUT_PARENT/$(basename -- "$OUT")"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-macos-deps.XXXXXX")
STAGE=$(mktemp -d "$OUT_PARENT/.ratelmesh-macos-deps.XXXXXX")
chmod 0700 "$STAGE"
cleanup() {
  # The Go module cache intentionally makes downloaded sources read-only.
  # Restore owner write permission so the private temporary GOPATH can be
  # removed without noisy permission failures.
  chmod -R u+w "$WORK" 2>/dev/null || true
  rm -rf "$WORK"
  if [[ -n "${STAGE:-}" ]]; then
    rm -rf "$STAGE"
  fi
  if [[ -n "${PARTIAL:-}" ]]; then
    rm -f "$PARTIAL"
  fi
}
trap cleanup EXIT HUP INT TERM

for command in curl git go lipo make shasum tar xcrun; do
  command -v "$command" >/dev/null || {
    echo "required build command is missing: $command" >&2
    exit 2
  }
done
if [[ "$(go env GOHOSTOS)" != darwin ]]; then
  echo "macOS dependencies must be built on macOS" >&2
  exit 2
fi
if [[ "$(GOTOOLCHAIN=local go version | awk '{print $3}')" != "$RATELMESH_GO_VERSION" ]]; then
  echo "Go $RATELMESH_GO_VERSION is required; found $(go version | awk '{print $3}')" >&2
  exit 2
fi

TOOLS_ARCHIVE_NAME="wireguard-tools-$RATELMESH_WIREGUARD_TOOLS_VERSION.tar.xz"
TOOLS_URL="https://git.zx2c4.com/wireguard-tools/snapshot/$TOOLS_ARCHIVE_NAME"
CACHE=${RATELMESH_BUILD_CACHE:-$HOME/Library/Caches/RatelMesh/build}
if [[ -L "$CACHE" ]]; then
  echo "build cache must not be a symbolic link: $CACHE" >&2
  exit 1
fi
if [[ -e "$CACHE" ]]; then
  if [[ ! -d "$CACHE" ]]; then
    echo "build cache must be a directory: $CACHE" >&2
    exit 1
  fi
  CACHE_MODE=$(stat -f '%Lp' "$CACHE")
  if (( (8#$CACHE_MODE & 8#077) != 0 )); then
    echo "existing build cache must not grant group or other access: $CACHE" >&2
    exit 1
  fi
else
  install -d -m 700 "$CACHE"
fi
CACHE=$(cd "$CACHE" && pwd)
CACHED_ARCHIVE="$CACHE/$TOOLS_ARCHIVE_NAME"

verify_archive() {
  local archive=$1
  local actual
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  [[ "$actual" == "$RATELMESH_WIREGUARD_TOOLS_SHA256" ]]
}

if [[ -n "${RATELMESH_WIREGUARD_TOOLS_ARCHIVE:-}" ]]; then
  TOOLS_ARCHIVE=$RATELMESH_WIREGUARD_TOOLS_ARCHIVE
  if [[ ! -f "$TOOLS_ARCHIVE" || -L "$TOOLS_ARCHIVE" ]] ||
      ! verify_archive "$TOOLS_ARCHIVE"; then
    echo "RATELMESH_WIREGUARD_TOOLS_ARCHIVE does not match the pinned SHA-256" >&2
    exit 1
  fi
else
  TOOLS_ARCHIVE=$CACHED_ARCHIVE
  if [[ -L "$TOOLS_ARCHIVE" ]]; then
    echo "cached wireguard-tools source must not be a symbolic link" >&2
    exit 1
  fi
  if [[ -f "$TOOLS_ARCHIVE" ]] && ! verify_archive "$TOOLS_ARCHIVE"; then
    rm -f "$TOOLS_ARCHIVE"
  fi
  if [[ ! -f "$TOOLS_ARCHIVE" ]]; then
    PARTIAL=$(mktemp "$CACHE/.wireguard-tools.XXXXXX")
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
      --output "$PARTIAL" "$TOOLS_URL"
    if ! verify_archive "$PARTIAL"; then
      echo "downloaded wireguard-tools source failed SHA-256 verification" >&2
      exit 1
    fi
    chmod 600 "$PARTIAL"
    if ! ln "$PARTIAL" "$TOOLS_ARCHIVE"; then
      if [[ -L "$TOOLS_ARCHIVE" || ! -f "$TOOLS_ARCHIVE" ]] ||
          ! verify_archive "$TOOLS_ARCHIVE"; then
        echo "concurrent dependency cache publication was not trustworthy" >&2
        exit 1
      fi
    fi
    rm -f "$PARTIAL"
    unset PARTIAL
  fi
fi

TOOLS_ARCHIVE_PRIVATE="$WORK/$TOOLS_ARCHIVE_NAME"
install -m 600 "$TOOLS_ARCHIVE" "$TOOLS_ARCHIVE_PRIVATE"
if ! verify_archive "$TOOLS_ARCHIVE_PRIVATE"; then
  echo "wireguard-tools source changed while entering the private build area" >&2
  exit 1
fi
tar -xJf "$TOOLS_ARCHIVE_PRIVATE" -C "$WORK"
TOOLS_SOURCE="$WORK/wireguard-tools-$RATELMESH_WIREGUARD_TOOLS_VERSION"
if [[ ! -f "$TOOLS_SOURCE/src/Makefile" || ! -f "$TOOLS_SOURCE/COPYING" ]]; then
  echo "wireguard-tools source archive has an unexpected layout" >&2
  exit 1
fi

# The release snapshot omits Git metadata, while the upstream Makefile obtains
# its version string from `git describe`. Add deterministic local metadata only;
# no source file is changed.
for arch in x86_64 arm64; do
  SOURCE="$WORK/wireguard-tools-$arch"
  ditto "$TOOLS_SOURCE" "$SOURCE"
  git -C "$SOURCE" init -q
  git -C "$SOURCE" config user.name "RatelMesh release builder"
  git -C "$SOURCE" config user.email "release-builder@ratelmesh.invalid"
  git -C "$SOURCE" add .
  GIT_AUTHOR_DATE=2026-02-23T00:00:00Z \
    GIT_COMMITTER_DATE=2026-02-23T00:00:00Z \
    git -C "$SOURCE" commit -q -m "wireguard-tools $RATELMESH_WIREGUARD_TOOLS_VERSION"
  git -C "$SOURCE" tag "v$RATELMESH_WIREGUARD_TOOLS_VERSION"
  ZERO_AR_DATE=1 SOURCE_DATE_EPOCH=1771804800 \
    make -C "$SOURCE/src" PLATFORM=darwin \
      CC="xcrun --sdk macosx clang -arch $arch -mmacosx-version-min=13.0" wg
  mv "$SOURCE/src/wg" "$WORK/wg-$arch"
done

GOPATH_DIR="$WORK/gopath"
MODULE_JSON=$(GOPATH="$GOPATH_DIR" GOWORK=off GOTOOLCHAIN=local \
  go mod download -json "golang.zx2c4.com/wireguard@$RATELMESH_WIREGUARD_GO_VERSION")
MODULE_SUM=$(sed -n 's/^[[:space:]]*"Sum": "\([^"]*\)",$/\1/p' <<<"$MODULE_JSON")
MODULE_DIR=$(sed -n 's/^[[:space:]]*"Dir": "\([^"]*\)",$/\1/p' <<<"$MODULE_JSON")
if [[ "$MODULE_SUM" != "$RATELMESH_WIREGUARD_GO_SUM" || ! -f "$MODULE_DIR/LICENSE" ]]; then
  echo "wireguard-go module checksum or layout does not match the pinned input" >&2
  exit 1
fi

HOST_ARCH=$(go env GOHOSTARCH)
for arch in amd64 arm64; do
  GOPATH="$GOPATH_DIR" GOWORK=off GOTOOLCHAIN=local GOFLAGS= \
    CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" \
    go install -trimpath -ldflags='-s -w' \
      "golang.zx2c4.com/wireguard@$RATELMESH_WIREGUARD_GO_VERSION"
  if [[ "$arch" == "$HOST_ARCH" ]]; then
    BUILT="$GOPATH_DIR/bin/wireguard"
  else
    BUILT="$GOPATH_DIR/bin/darwin_$arch/wireguard"
  fi
  mv "$BUILT" "$WORK/wireguard-go-$arch"
done

mkdir -p "$STAGE/bin" \
  "$STAGE/licenses/wireguard-go" \
  "$STAGE/licenses/wireguard-tools" \
  "$STAGE/sources"
lipo -create "$WORK/wg-x86_64" "$WORK/wg-arm64" -output "$STAGE/bin/wg"
lipo -create "$WORK/wireguard-go-amd64" "$WORK/wireguard-go-arm64" \
  -output "$STAGE/bin/wireguard-go"
chmod 755 "$STAGE/bin/wg" "$STAGE/bin/wireguard-go"
install -m 644 "$MODULE_DIR/LICENSE" "$STAGE/licenses/wireguard-go/LICENSE"
install -m 644 "$TOOLS_SOURCE/COPYING" "$STAGE/licenses/wireguard-tools/COPYING"
install -m 644 "$TOOLS_ARCHIVE_PRIVATE" "$STAGE/sources/$TOOLS_ARCHIVE_NAME"
install -m 644 "$REPO/packaging/macos/THIRD-PARTY-NOTICES.txt" \
  "$STAGE/THIRD-PARTY-NOTICES.txt"
install -m 644 "$REPO/packaging/macos/dependencies.env" \
  "$STAGE/BUILD-DEPENDENCIES.env"

for binary in wg wireguard-go; do
  [[ "$(lipo -archs "$STAGE/bin/$binary")" == "x86_64 arm64" ]]
done
[[ "$($STAGE/bin/wg --version)" == \
  "wireguard-tools v$RATELMESH_WIREGUARD_TOOLS_VERSION - https://git.zx2c4.com/wireguard-tools/" ]]
for arch in x86_64 arm64; do
  THIN="$WORK/wireguard-go-check-$arch"
  lipo "$STAGE/bin/wireguard-go" -thin "$arch" -output "$THIN"
  [[ "$(go version -m "$THIN" | head -n 1 | awk '{print $2}')" == "$RATELMESH_GO_VERSION" ]]
  go version -m "$THIN" | grep -Fq \
    $'mod\tgolang.zx2c4.com/wireguard\t'"$RATELMESH_WIREGUARD_GO_VERSION"$'\t'"$RATELMESH_WIREGUARD_GO_SUM"
done

chmod 0755 "$STAGE"
go run "$REPO/scripts/publish-directory" "$STAGE" "$OUT"
STAGE=
echo "$OUT"
