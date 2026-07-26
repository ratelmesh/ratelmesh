#!/usr/bin/env bash
# Rebuild the explicitly non-production Android preview from one committed tree
# and emit its checksum plus deterministic provenance.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 VERSION NEW_OUTPUT_DIRECTORY [SOURCE_REF]" >&2
  exit 2
fi

VERSION=$1
OUTDIR=$2
SOURCE_REF=${3:-HEAD}
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

fail() {
  echo "Android preview build failed: $*" >&2
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
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-android-preview.XXXXXX")
STAGE=$(mktemp -d "$PARENT/.ratelmesh-android-preview.XXXXXX")
MOBILE_WORK=
cleanup() {
  rm -rf "$WORK" "$STAGE"
  if [[ -n "$MOBILE_WORK" ]]; then
    rm -rf "$MOBILE_WORK"
  fi
}
trap cleanup EXIT HUP INT TERM
mkdir "$WORK/source"
git -C "$REPO" archive "$SOURCE_COMMIT" | tar -xf - -C "$WORK/source"
SOURCE="$WORK/source"

PROJECT_VERSION=$(sed -nE 's/^[[:space:]]*versionName = "([^"]+)"$/\1/p' \
  "$SOURCE/clients/android/app/build.gradle.kts")
PROJECT_BUILD=$(sed -nE 's/^[[:space:]]*versionCode = ([0-9]+)$/\1/p' \
  "$SOURCE/clients/android/app/build.gradle.kts")
[[ "$PROJECT_VERSION" == "$VERSION" && "$PROJECT_BUILD" =~ ^[1-9][0-9]*$ ]] ||
  fail "requested $VERSION does not match committed Android metadata $PROJECT_VERSION/$PROJECT_BUILD"

if [[ "${RATELMESH_MOBILE_RELEASE_VALIDATE_ONLY:-0}" == 1 ]]; then
  echo "Validated Android preview source $SOURCE_COMMIT at $VERSION ($PROJECT_BUILD)"
  exit 0
fi

SDK_ROOT=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}
[[ -d "$SDK_ROOT" ]] || fail "Android SDK not found; set ANDROID_SDK_ROOT"
export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"
if [[ -z "${JAVA_HOME:-}" || ! -x "$JAVA_HOME/bin/java" ]]; then
  for java_home in /opt/homebrew/opt/openjdk@17 /usr/local/opt/openjdk@17; do
    if [[ -x "$java_home/bin/java" ]]; then
      export JAVA_HOME="$java_home"
      break
    fi
  done
fi
[[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]] ||
  fail "JDK 17 or newer is required; set JAVA_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
JAVA_MAJOR=$("$JAVA_HOME/bin/java" -version 2>&1 |
  sed -nE '1s/.* version "([0-9]+).*/\1/p')
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ && "$JAVA_MAJOR" -ge 17 ]] ||
  fail "JAVA_HOME must select JDK 17 or newer"
APKSIGNER=$(find "$SDK_ROOT/build-tools" -mindepth 2 -maxdepth 2 -type f -name apksigner |
  LC_ALL=C sort | tail -1)
APKANALYZER=${RATELMESH_APKANALYZER:-"$SDK_ROOT/cmdline-tools/latest/bin/apkanalyzer"}
[[ -x "$APKSIGNER" && -x "$APKANALYZER" ]] ||
  fail "apksigner and apkanalyzer are required"

# Keep the pinned x/mobile dependency out of the production module while making
# the generated native libraries independent of this recipe's temporary path.
XMOBILE_VERSION=v0.0.0-20260709172247-6129f5bee9d5
MOBILE_PATH="/tmp/ratelmesh-mobile-release-$SOURCE_COMMIT-android"
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
  "$MOBILE_WORK/bin/gomobile" init
  mkdir -p "$SOURCE/clients/android/app/libs"
  rm -f "$SOURCE/clients/android/app/libs/ratelmesh-mobile.aar"
  "$MOBILE_WORK/bin/gomobile" bind \
    -trimpath \
    -ldflags=-buildid= \
    -target=android \
    -androidapi 26 \
    -o "$SOURCE/clients/android/app/libs/ratelmesh-mobile.aar" \
    ./mobile
)

(
  cd "$SOURCE/clients/android"
  ./gradlew --no-daemon :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
)
BUILT="$SOURCE/clients/android/app/build/outputs/apk/debug/app-debug.apk"
[[ -s "$BUILT" && ! -L "$BUILT" ]] || fail "Gradle did not produce a regular debug APK"
"$APKSIGNER" verify --verbose --print-certs "$BUILT" >"$WORK/apksigner.txt"
grep -Fq "Verified" "$WORK/apksigner.txt" || fail "APK signature verification did not complete"
SIGNER_SHA=$(sed -nE 's/^Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]+)$/\1/p' \
  "$WORK/apksigner.txt" | tr '[:upper:]' '[:lower:]')
[[ "$SIGNER_SHA" =~ ^[0-9a-f]{64}$ ]] || fail "debug signer digest is unavailable"
grep -Eq '^Signer #1 certificate DN: .*CN=Android Debug([,]|$)' "$WORK/apksigner.txt" ||
  fail "APK is not signed by an Android debug certificate"
[[ "$("$APKANALYZER" manifest debuggable "$BUILT")" == true ]] ||
  fail "APK is not marked debuggable"
[[ "$("$APKANALYZER" manifest version-name "$BUILT")" == "$VERSION" ]] ||
  fail "APK versionName differs from $VERSION"
[[ "$("$APKANALYZER" manifest version-code "$BUILT")" == "$PROJECT_BUILD" ]] ||
  fail "APK versionCode differs from $PROJECT_BUILD"

ARTIFACT="RatelMesh-Android-$VERSION-debug.apk"
install -m 0644 "$BUILT" "$STAGE/$ARTIFACT"
GRADLE_VERSION=$(
  cd "$SOURCE/clients/android"
  ./gradlew --no-daemon --version | sed -nE 's/^Gradle (.+)$/\1/p' | head -1
)
BUILD_TOOLS=$(basename "$(dirname "$APKSIGNER")")
TOOLCHAIN="go=$(GOTOOLCHAIN=local go version | awk '{print $3}');gradle=$GRADLE_VERSION;android-build-tools=$BUILD_TOOLS"
go run "$SOURCE/scripts/mobile-release/provenance.go" \
  -artifact "$STAGE/$ARTIFACT" \
  -platform android \
  -classification debug-signed-test \
  -version "$VERSION" \
  -build "$PROJECT_BUILD" \
  -source-commit "$SOURCE_COMMIT" \
  -source-date-epoch "$SOURCE_EPOCH" \
  -signing debug \
  -signer-sha256 "$SIGNER_SHA" \
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
