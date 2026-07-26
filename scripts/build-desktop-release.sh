#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 VERSION OUTPUT_DIRECTORY" >&2
  exit 2
fi

VERSION=$1
OUTDIR=$2
REPO="$(cd "$(dirname "$0")/.." && pwd)"
"$REPO/scripts/test-client-locales.py"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-desktop-release.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"

export PATH="/opt/homebrew/bin:$PATH"
for arch in amd64 arm64; do
  linux="$WORK/RatelMesh-Linux-$VERSION-$arch"
  mkdir -p "$linux"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -tags wgreal -o "$linux/ratelmeshd" "$REPO/cmd/ratelmeshd"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$linux/ratelmesh" "$REPO/cmd/ratelmesh"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$linux/ratelmesh-relay" "$REPO/cmd/ratelmesh-relay"
  install -m 644 "$REPO/deploy/systemd/ratelmeshd.service" "$linux/ratelmeshd.service"
  install -m 644 "$REPO/deploy/tenant/relay/ratelmesh-relay.service" "$linux/ratelmesh-relay.service"
  install -m 644 "$REPO/clients/linux/README.md" "$linux/README.md"
  tar -C "$WORK" -czf "$OUTDIR/RatelMesh-Linux-$VERSION-$arch.tar.gz" "$(basename "$linux")"

  windows="$WORK/windows-$arch"
  pwsh -NoProfile -NonInteractive -File "$REPO/clients/windows/Package.ps1" -Arch "$arch" -OutputDir "$windows"
  mv "$windows/RatelMesh-windows-$arch" "$windows/RatelMesh-Windows-$VERSION-$arch"
  (cd "$windows" && /usr/bin/zip -qry "$OUTDIR/RatelMesh-Windows-$VERSION-$arch.zip" "RatelMesh-Windows-$VERSION-$arch")
done

shasum -a 256 "$OUTDIR"/RatelMesh-{Linux,Windows}-"$VERSION"-* | sort
