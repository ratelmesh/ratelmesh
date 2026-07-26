#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID="$ROOT/scripts/mobile-release/build-android-debug-preview.sh"
IOS="$ROOT/scripts/mobile-release/build-ios-unsigned-preview.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-mobile-provenance-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

(cd "$ROOT" && go test ./scripts/mobile-release)

for script in "$ANDROID" "$IOS"; do
  test -x "$script"
  rg -q 'git -C "\$REPO" archive "\$SOURCE_COMMIT"' "$script"
  rg -q 'provenance\.go' "$script"
  rg -q 'shasum -a 256' "$script"
  rg -q 'ln "\$STAGE/\$file" "\$OUTDIR/\$file"' "$script"
  if rg -q 'git archive HEAD|CODE_SIGNING_ALLOWED=YES' "$script"; then
    echo "mobile preview recipe contains an unbound or signed build path: $script" >&2
    exit 1
  fi
done

rg -q 'debug-signed-test' "$ANDROID"
rg -q 'CN=Android Debug' "$ANDROID"
rg -q 'manifest debuggable' "$ANDROID"
rg -q 'signer-sha256' "$ANDROID"
rg -q 'CODE_SIGNING_ALLOWED=NO' "$IOS"
rg -q 'unsigned-developer-preview' "$IOS"
rg -q '_CodeSignature' "$IOS"
rg -q 'embedded\.mobileprovision' "$IOS"

ANDROID_VERSION=$(sed -nE 's/^[[:space:]]*versionName = "([^"]+)"$/\1/p' \
  "$ROOT/clients/android/app/build.gradle.kts")
IOS_VERSION=$(awk '/MARKETING_VERSION:/ { print $2; exit }' "$ROOT/clients/ios/project.yml")
IOS_BUILD=$(awk '/CURRENT_PROJECT_VERSION:/ { print $2; exit }' "$ROOT/clients/ios/project.yml")

RATELMESH_MOBILE_RELEASE_VALIDATE_ONLY=1 \
  "$ANDROID" "$ANDROID_VERSION" "$WORK/android" HEAD >/dev/null
RATELMESH_MOBILE_RELEASE_VALIDATE_ONLY=1 \
  "$IOS" "$IOS_VERSION" "$IOS_BUILD" "$WORK/ios" HEAD >/dev/null
test ! -e "$WORK/android"
test ! -e "$WORK/ios"

mkdir "$WORK/existing"
printf '%s\n' sentinel >"$WORK/existing/keep"
if RATELMESH_MOBILE_RELEASE_VALIDATE_ONLY=1 \
  "$ANDROID" "$ANDROID_VERSION" "$WORK/existing" HEAD >/dev/null 2>&1; then
  echo "Android recipe accepted an existing output directory" >&2
  exit 1
fi
test "$(cat "$WORK/existing/keep")" = sentinel

mkdir "$WORK/target"
ln -s "$WORK/target" "$WORK/link"
if RATELMESH_MOBILE_RELEASE_VALIDATE_ONLY=1 \
  "$IOS" "$IOS_VERSION" "$IOS_BUILD" "$WORK/link" HEAD >/dev/null 2>&1; then
  echo "iOS recipe accepted a symbolic-link output directory" >&2
  exit 1
fi
test -z "$(find "$WORK/target" -mindepth 1 -print -quit)"

if RATELMESH_MOBILE_RELEASE_VALIDATE_ONLY=1 \
  "$ANDROID" 9.9.9 "$WORK/wrong-android" HEAD >/dev/null 2>&1; then
  echo "Android recipe accepted mismatched release metadata" >&2
  exit 1
fi
if RATELMESH_MOBILE_RELEASE_VALIDATE_ONLY=1 \
  "$IOS" 9.9.9 "$IOS_BUILD" "$WORK/wrong-ios" HEAD >/dev/null 2>&1; then
  echo "iOS recipe accepted mismatched release metadata" >&2
  exit 1
fi

echo "mobile release provenance tests passed"
