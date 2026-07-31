#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IOS_ROOT=$(dirname "$SCRIPT_DIR")
REPO_ROOT=$(CDPATH= cd -- "$IOS_ROOT/../.." && pwd)
OUTPUT="$IOS_ROOT/Frameworks/RatelMeshMobile.xcframework"
XMOBILE_VERSION=v0.0.0-20260709172247-6129f5bee9d5
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratelmeshmobile.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

# New gomobile releases require an x/mobile tool directive. Keep that build-only
# dependency out of RatelMesh's production go.mod by binding a temp copy.
rsync -a \
    --exclude .git \
    --exclude clients \
    --exclude dist \
    --exclude bin \
    --exclude website \
    --exclude deploy \
    "$REPO_ROOT/" "$WORK/repo/"
cd "$WORK/repo"
export PATH="/opt/homebrew/bin:$WORK/bin:$(go env GOPATH)/bin:$PATH"
go get -tool "golang.org/x/mobile/cmd/gobind@$XMOBILE_VERSION"
GOBIN="$WORK/bin" go install "golang.org/x/mobile/cmd/gomobile@$XMOBILE_VERSION"
GOBIN="$WORK/bin" go install "golang.org/x/mobile/cmd/gobind@$XMOBILE_VERSION"
rm -rf "$OUTPUT"
"$WORK/bin/gomobile" bind \
    -target=ios,macos \
    -iosversion=16.0 \
    -macosversion=13.0 \
    -o "$OUTPUT" \
    ./mobile

printf '%s\n' "Generated $OUTPUT"
