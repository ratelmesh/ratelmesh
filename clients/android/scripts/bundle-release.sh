#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

test -f "$ROOT/app/libs/ratelmesh-mobile.aar" || {
    printf '%s\n' 'ratelmesh-mobile.aar is missing; run scripts/build-ratelmesh-mobile.sh first.' >&2
    exit 2
}
test -f "$ROOT/keystore.properties" || {
    printf '%s\n' 'keystore.properties is missing; see README.md.' >&2
    exit 2
}

cd "$ROOT"
./gradlew --no-daemon :app:testReleaseUnitTest :app:lintRelease :app:bundleRelease

BUNDLE="$ROOT/app/build/outputs/bundle/release/app-release.aab"
test -f "$BUNDLE"
jarsigner -verify -strict "$BUNDLE"
printf '%s\n' "Signed Android App Bundle: $BUNDLE"
