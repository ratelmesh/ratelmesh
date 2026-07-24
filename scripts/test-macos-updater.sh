#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-updater-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

for script in \
    "$ROOT/packaging/macos/installer/scripts/postinstall" \
    "$ROOT/packaging/macos/update/scripts/postinstall"; do
    if grep -Eq '/Users/\*|chown -R .*staff|APP_DIR=.*Users' "$script"; then
        echo "postinstall must not perform root mutations through user-owned paths: $script" >&2
        exit 1
    fi
done

for script in \
    "$ROOT/packaging/macos/installer/scripts/postinstall" \
    "$ROOT/packaging/macos/update/scripts/postinstall"; do
    rg -q 'previous RatelMesh daemon did not stop' "$script"
    rg -q 'daemon did not reach Running state after update' "$script"
    if rg -q 'launchctl load -w' "$script"; then
        echo "macOS updater must not hide bootstrap failure behind legacy launchctl load: $script" >&2
        exit 1
    fi
done

xcrun swiftc -O -parse-as-library -target "$(uname -m)-apple-macos13.0" \
    -o "$WORK/menu-support-tests" \
    "$ROOT/clients/macos-menubar/MenuModels.swift" \
    "$ROOT/clients/macos-menubar/EnrollmentSupport.swift" \
    "$ROOT/clients/macos-menubar/MenuSupportTests.swift"
"$WORK/menu-support-tests"

for script in \
    "$ROOT/packaging/macos/installer/scripts/postinstall" \
    "$ROOT/packaging/macos/update/scripts/postinstall"; do
    grep -qx 'MENU_LABEL=com.ratelmesh.menubar' "$script"
    if rg -q 'LABEL\.menubar' "$script"; then
        echo "menu LaunchAgent must not be derived from the daemon label: $script" >&2
        exit 1
    fi
done

printf '%s\n' 'verified package payload' >"$WORK/update.pkg"
PUBLIC_KEY=$(go run "$ROOT/scripts/update-manifest.go" keygen -key "$WORK/release.key")
PQ_PUBLIC_KEY=$(go run "$ROOT/scripts/update-manifest.go" public-pq -key "$WORK/release.key")
test "$(stat -f '%Lp' "$WORK/release.key")" = 600
test "$(stat -f '%Lp' "$WORK/release.key.mldsa65")" = 600
test "$(go run "$ROOT/scripts/update-manifest.go" public -key "$WORK/release.key")" = "$PUBLIC_KEY"
go run "$ROOT/scripts/update-manifest.go" sign \
    -key "$WORK/release.key" \
    -package "$WORK/update.pkg" \
    -version 0.1.27 \
    -url https://download.ratelmesh.com/download/RatelMesh-macOS-0.1.27-universal.pkg \
    -published-at 2026-07-13T08:00:00Z \
    -output "$WORK/latest.json"
go build -o "$WORK/ratelmesh-pqverify" "$ROOT/cmd/ratelmesh-pqverify"

xcrun swiftc -O -parse-as-library -target "$(uname -m)-apple-macos13.0" \
    -o "$WORK/updater-tests" \
    "$ROOT/clients/macos-menubar/UpdateSupport.swift" \
    "$ROOT/clients/macos-menubar/UpdateSecurityTests.swift"
"$WORK/updater-tests" "$WORK/latest.json" "$PUBLIC_KEY" "$PQ_PUBLIC_KEY" "$WORK/ratelmesh-pqverify" "$WORK/update.pkg"

xcrun swiftc -O -parse-as-library -target "$(uname -m)-apple-macos13.0" \
    -o "$WORK/updater-scheduler-tests" \
    "$ROOT/clients/macos-menubar/UpdateSupport.swift" \
    "$ROOT/clients/macos-menubar/UpdateSchedulerTests.swift"
"$WORK/updater-scheduler-tests" "$WORK/latest.json" "$PUBLIC_KEY" "$PQ_PUBLIC_KEY" "$WORK/ratelmesh-pqverify"
