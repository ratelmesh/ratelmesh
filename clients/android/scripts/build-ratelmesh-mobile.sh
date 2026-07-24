#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ANDROID_ROOT=$(dirname "$SCRIPT_DIR")
REPO_ROOT=$(CDPATH= cd -- "$ANDROID_ROOT/../.." && pwd)
OUTPUT="$ANDROID_ROOT/app/libs/ratelmesh-mobile.aar"
XMOBILE_VERSION=v0.0.0-20260709172247-6129f5bee9d5
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratelmeshmobile-android.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

command -v go >/dev/null 2>&1 || {
    printf '%s\n' "Go is required" >&2
    exit 1
}
: "${ANDROID_HOME:?ANDROID_HOME must point to an Android SDK}"

HOST_PLATFORM=$(go env GOOS)/$(go env GOARCH)
if [ "$HOST_PLATFORM" = "linux/arm64" ]; then
    # x/mobile can run natively after a small host check fix. Google's NDK is
    # still x86_64-only, so point it at an SDK overlay whose ELF tools are
    # launched through qemu-user with a complete amd64 userspace.
    ANDROID_HOME=$($SCRIPT_DIR/prepare-linux-arm64-ndk.sh "$ANDROID_HOME")
    export ANDROID_HOME
fi

# New gomobile releases require an x/mobile tool directive. Build from a temp
# repository copy so RatelMesh's production go.mod/go.sum stay untouched.
mkdir -p "$WORK/repo"
if command -v rsync >/dev/null 2>&1; then
    rsync -a --exclude .git --exclude clients "$REPO_ROOT/" "$WORK/repo/"
else
    tar -C "$REPO_ROOT" --exclude=.git --exclude=clients -cf - . | tar -C "$WORK/repo" -xf -
fi
cd "$WORK/repo"
export PATH="/opt/homebrew/bin:$WORK/bin:$(go env GOPATH)/bin:$PATH"
go get -tool "golang.org/x/mobile/cmd/gobind@$XMOBILE_VERSION"
GOBIN="$WORK/bin" go install "golang.org/x/mobile/cmd/gomobile@$XMOBILE_VERSION"
GOBIN="$WORK/bin" go install "golang.org/x/mobile/cmd/gobind@$XMOBILE_VERSION"
if [ "$HOST_PLATFORM" = "linux/arm64" ]; then
    XMOBILE_SOURCE=$(go list -m -f '{{.Dir}}' golang.org/x/mobile)
    cp -R "$XMOBILE_SOURCE" "$WORK/xmobile"
    chmod -R u+w "$WORK/xmobile"
    if ! grep -Fq 'runtime.GOOS == "darwin" || runtime.GOOS == "linux"' "$WORK/xmobile/cmd/gomobile/env.go"; then
        patch -s -d "$WORK/xmobile" -p1 < "$SCRIPT_DIR/xmobile-linux-arm64.patch"
    fi
    (
        cd "$WORK/xmobile"
        GOBIN="$WORK/bin" go install ./cmd/gomobile ./cmd/gobind
    )
fi
"$WORK/bin/gomobile" init

mkdir -p "$(dirname "$OUTPUT")"
rm -f "$OUTPUT"
"$WORK/bin/gomobile" bind -target=android -androidapi 26 -o "$OUTPUT" ./mobile

printf '%s\n' "Generated $OUTPUT"
