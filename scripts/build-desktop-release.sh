#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 VERSION OUTPUT_DIRECTORY" >&2
  exit 2
fi
if [[ ! "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "version must use canonical MAJOR.MINOR.PATCH without leading zeros" >&2
  exit 2
fi

VERSION=$1
OUTDIR=$2
VERSION_LDFLAGS="-s -w -X main.version=$VERSION"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_COMMIT="$(git -C "$REPO" rev-parse --verify HEAD)"
if [[ ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "source commit is not a full Git object ID" >&2
  exit 2
fi
if [[ -n "$(git -C "$REPO" status --porcelain --untracked-files=all)" ]]; then
  echo "source tree must be clean before building release artifacts" >&2
  exit 2
fi
"$REPO/scripts/test-client-locales.py"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-desktop-release.XXXXXX")"
STAGE=
cleanup() {
  rm -rf "$WORK"
  if [[ -n "$STAGE" ]]; then
    rm -rf "$STAGE"
  fi
}
trap cleanup EXIT HUP INT TERM
if [[ -e "$OUTDIR" || -L "$OUTDIR" ]]; then
  echo "output directory must not already exist: $OUTDIR" >&2
  exit 2
fi
OUT_PARENT="$(dirname -- "$OUTDIR")"
mkdir -p "$OUT_PARENT"
OUT_PARENT="$(cd "$OUT_PARENT" && pwd)"
OUTDIR="$OUT_PARENT/$(basename -- "$OUTDIR")"
STAGE="$(mktemp -d "$OUT_PARENT/.ratelmesh-desktop.XXXXXX")"
chmod 0700 "$STAGE"

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || true)}"
if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ || "$SOURCE_DATE_EPOCH" -lt 315532800 ]]; then
  echo "SOURCE_DATE_EPOCH must be an integer timestamp on or after 1980-01-01" >&2
  exit 2
fi
ARCHIVE_TIMESTAMP="$(TZ=UTC date -r "$SOURCE_DATE_EPOCH" '+%Y%m%d%H%M.%S')"
export TZ=UTC
GO_VERSION="$(GOTOOLCHAIN=local go env GOVERSION)"
if [[ ! "$GO_VERSION" =~ ^go[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "could not determine a canonical Go toolchain version" >&2
  exit 2
fi

write_provenance() {
  local output=$1 platform=$2 architecture=$3
  printf '{\n  "version": "%s",\n  "platform": "%s",\n  "architecture": "%s",\n  "sourceCommit": "%s",\n  "sourceDateEpoch": %s,\n  "go": "%s"\n}\n' \
    "$VERSION" "$platform" "$architecture" "$SOURCE_COMMIT" \
    "$SOURCE_DATE_EPOCH" "$GO_VERSION" >"$output"
  chmod 0644 "$output"
}

export PATH="/opt/homebrew/bin:$PATH"
for arch in amd64 arm64; do
  linux="$WORK/RatelMesh-Linux-$VERSION-$arch"
  mkdir -p "$linux"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -tags wgreal -ldflags="-s -w" -o "$linux/ratelmeshd" "$REPO/cmd/ratelmeshd"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags="$VERSION_LDFLAGS" -o "$linux/ratelmesh" "$REPO/cmd/ratelmesh"
  for executable in "$linux/ratelmeshd" "$linux/ratelmesh"; do
    build_info="$(go version -m "$executable")"
    grep -Eq "^[[:space:]]*build[[:space:]]+GOARCH=$arch$" <<<"$build_info"
    grep -Fq $'build\tvcs.revision='"$SOURCE_COMMIT" <<<"$build_info"
    grep -Fq $'build\tvcs.modified=false' <<<"$build_info"
  done
  install -m 644 "$REPO/clients/linux/ratelmeshd.service" "$linux/ratelmeshd.service"
  install -m 644 "$REPO/clients/linux/README.md" "$linux/README.md"
  install -m 755 "$REPO/clients/linux/uninstall.sh" "$linux/uninstall.sh"
  write_provenance "$linux/BUILD-PROVENANCE.json" linux "$arch"
  test "$(stat -f '%Lp' "$linux/ratelmeshd")" = 755
  test "$(stat -f '%Lp' "$linux/ratelmesh")" = 755
  test "$(stat -f '%Lp' "$linux/uninstall.sh")" = 755
  test "$(stat -f '%Lp' "$linux/ratelmeshd.service")" = 644
  test "$(stat -f '%Lp' "$linux/README.md")" = 644
  find "$linux" -exec touch -h -t "$ARCHIVE_TIMESTAMP" {} +
  COPYFILE_DISABLE=1 COPY_EXTENDED_ATTRIBUTES_DISABLE=1 /usr/bin/tar \
    --uid 0 --gid 0 --uname root --gname root --no-xattrs --no-mac-metadata \
    -C "$WORK" -cf - "$(basename "$linux")" |
    /usr/bin/gzip -n -9 >"$STAGE/RatelMesh-Linux-$VERSION-$arch.tar.gz"
  chmod 0644 "$STAGE/RatelMesh-Linux-$VERSION-$arch.tar.gz"

  windows="$WORK/windows-$arch"
  pwsh -NoProfile -NonInteractive -File "$REPO/clients/windows/Package.ps1" -Arch "$arch" -Version "$VERSION" -OutputDir "$windows"
  mv "$windows/RatelMesh-windows-$arch" "$windows/RatelMesh-Windows-$VERSION-$arch"
  windows_bundle="RatelMesh-Windows-$VERSION-$arch"
  for executable in ratelmeshd.exe ratelmesh.exe; do
    build_info="$(go version -m "$windows/$windows_bundle/$executable")"
    grep -Fq $'build\tvcs.revision='"$SOURCE_COMMIT" <<<"$build_info"
    grep -Fq $'build\tvcs.modified=false' <<<"$build_info"
  done
  write_provenance "$windows/$windows_bundle/BUILD-PROVENANCE.json" windows "$arch"
  (
    cd "$windows/$windows_bundle"
    rm -f SHA256SUMS.txt
    for artifact in *; do
      [[ -f "$artifact" ]] || continue
      shasum -a 256 "$artifact"
    done | LC_ALL=C sort >SHA256SUMS.txt
    chmod 0644 SHA256SUMS.txt
  )
  find "$windows/$windows_bundle" -exec touch -h -t "$ARCHIVE_TIMESTAMP" {} +
  (
    cd "$windows"
    find "$windows_bundle" -type f -print |
      LC_ALL=C sort |
      /usr/bin/zip -X -q "$STAGE/RatelMesh-Windows-$VERSION-$arch.zip" -@
  )
  chmod 0644 "$STAGE/RatelMesh-Windows-$VERSION-$arch.zip"
done

(
  cd "$STAGE"
  shasum -a 256 RatelMesh-{Linux,Windows}-"$VERSION"-* |
    LC_ALL=C sort >SHA256SUMS-desktop.txt
  chmod 0644 SHA256SUMS-desktop.txt
)
chmod 0755 "$STAGE"
go run "$REPO/scripts/publish-directory" "$STAGE" "$OUTDIR"
STAGE=
cat "$OUTDIR/SHA256SUMS-desktop.txt"
